"""FM1 extension: OIDC single sign-on.

What is implemented, and what is honestly not.

**Implemented**: per-tenant configuration (`TenantSsoConfig`), OIDC discovery
verification against the issuer's `/.well-known/openid-configuration`,
authorization-URL construction with PKCE and a signed state parameter,
ID-token claim-to-role mapping, and just-in-time user provisioning. The
`sso_required` tenant switch is enforced in `services/auth.py`, so a tenant that
mandates SSO genuinely cannot be reached by password.

**Not implemented**: the authorization-code exchange's signature verification
against the issuer's JWKS. Verifying an RS256 ID token needs JWKS fetching, key
caching, key rotation handling, and `aud`/`iss`/`nonce`/`azp` validation --
PyJWT can do the crypto, but getting the validation set wrong is precisely how
OIDC integrations become auth bypasses. Rather than ship a half-validated token
path that *looks* like working SSO, `complete_login` refuses unless
`settings.environment` marks a non-production environment, where it accepts a
pre-verified claim set for integration testing. The refusal names what is
missing.

**Not implemented**: SAML 2.0. The model carries `saml_metadata_url` so the
configuration shape is settled, and `validate_sso_config` rejects
`protocol="saml"` rather than storing a config nothing honours.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_password
from app.models.sso import TenantSsoConfig
from app.models.user import Role, User

logger = logging.getLogger(__name__)


class SsoError(RuntimeError):
    pass


def validate_sso_config(payload: dict[str, Any]) -> None:
    """Reject a configuration this system cannot honour."""
    protocol = payload.get("protocol", "oidc")
    if protocol == "saml":
        raise ValueError(
            "protocol 'saml' is modelled but not implemented; use 'oidc'. "
            "See app/services/sso.py for what a SAML implementation would need."
        )
    issuer = str(payload.get("issuer") or "")
    if not issuer.startswith("https://"):
        # An http issuer would carry ID tokens over cleartext.
        raise ValueError("issuer must be an https URL")

    role_mapping = payload.get("role_mapping") or {}
    valid_roles = {role.value for role in Role}
    for claim_value, role in role_mapping.items():
        if role not in valid_roles:
            raise ValueError(f"role_mapping[{claim_value!r}] = {role!r} is not a valid role")
    if payload.get("default_role") not in valid_roles:
        raise ValueError(f"default_role {payload.get('default_role')!r} is not a valid role")


def discovery_url(issuer: str) -> str:
    return issuer.rstrip("/") + "/.well-known/openid-configuration"


def verify_discovery(config: TenantSsoConfig) -> dict[str, Any]:
    """Fetch and sanity-check the issuer's OIDC discovery document."""
    url = discovery_url(config.issuer)
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "SentinelIQ/0.2"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - operator-configured issuer
            document = json.loads(response.read(1024 * 1024))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SsoError(f"could not fetch {url}: {exc}") from exc

    if not isinstance(document, dict):
        raise SsoError("discovery document is not a JSON object")

    # The issuer in the document must match the configured issuer, or the
    # configuration is pointing at a different identity provider than it claims.
    declared = str(document.get("issuer", "")).rstrip("/")
    if declared != config.issuer.rstrip("/"):
        raise SsoError(f"discovery document issuer {declared!r} does not match configured issuer {config.issuer!r}")

    for required in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not document.get(required):
            raise SsoError(f"discovery document is missing {required}")

    return document


# --------------------------------------------------------------------------
# Authorization request
# --------------------------------------------------------------------------
def _sign_state(payload: dict[str, Any]) -> str:
    """Signed, expiring state parameter.

    State must be unguessable and integrity-protected: it is the CSRF defence
    for the redirect, and it carries the tenant id the callback needs. Signing it
    means the callback can trust the tenant binding without a server-side
    session store.
    """
    settings = get_settings()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(settings.jwt_secret.encode(), body.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{body}.{signature}"


def verify_state(state: str, *, max_age_seconds: int = 600) -> dict[str, Any]:
    settings = get_settings()
    try:
        body, signature = state.split(".", 1)
    except ValueError as exc:
        raise SsoError("malformed state") from exc

    expected = hmac.new(settings.jwt_secret.encode(), body.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(expected, signature):
        raise SsoError("state signature mismatch")

    padding = "=" * (-len(body) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + padding))
    except ValueError as exc:
        raise SsoError("state payload is not decodable") from exc

    issued = int(payload.get("iat", 0))
    if time.time() - issued > max_age_seconds:
        raise SsoError("state has expired")
    return payload


def build_authorization_url(
    config: TenantSsoConfig,
    *,
    redirect_uri: str,
    scopes: tuple[str, ...] = ("openid", "email", "profile"),
) -> dict[str, str]:
    """Build the OIDC authorization-code URL with PKCE.

    Returns the URL plus the `code_verifier` and `nonce` the caller must retain
    for the callback. PKCE is included even though this is a confidential client:
    it costs nothing and removes the authorization-code interception class of
    attack entirely.
    """
    if not config.is_enabled:
        raise SsoError("SSO is not enabled for this tenant")
    if not config.authorization_endpoint:
        raise SsoError("authorization_endpoint is unknown; verify the configuration first")

    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    nonce = secrets.token_urlsafe(24)
    state = _sign_state(
        {
            "tenant_id": config.tenant_id,
            "nonce": nonce,
            "iat": int(time.time()),
        }
    )

    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return {
        "authorization_url": f"{config.authorization_endpoint}?{query}",
        "state": state,
        "code_verifier": verifier,
        "nonce": nonce,
    }


# --------------------------------------------------------------------------
# Claim mapping and JIT provisioning
# --------------------------------------------------------------------------
def map_role(config: TenantSsoConfig, claims: dict[str, Any]) -> str:
    """Map IdP claims to a SentinelIQ role.

    Checks `groups` and `roles` claims against `role_mapping`, taking the
    *least* privileged match when several apply. Picking the most privileged
    would mean adding a user to any mapped group could silently escalate them.
    """
    from app.models.user import ROLE_HIERARCHY

    candidates: list[str] = []
    for claim_name in ("groups", "roles"):
        value = claims.get(claim_name)
        values = value if isinstance(value, list) else ([value] if value else [])
        for entry in values:
            mapped = config.role_mapping.get(str(entry))
            if mapped:
                candidates.append(mapped)

    if not candidates:
        return config.default_role
    return min(candidates, key=lambda role: ROLE_HIERARCHY[Role(role)])


def provision_user(db: Session, *, config: TenantSsoConfig, claims: dict[str, Any]) -> User:
    """Find or JIT-create the user described by a verified claim set."""
    email = str(claims.get("email") or "").lower()
    if not email:
        raise SsoError("ID token has no email claim; cannot identify the user")
    if claims.get("email_verified") is False:
        # An unverified email from the IdP would let anyone who can register an
        # address at the IdP claim an existing SentinelIQ account.
        raise SsoError("ID token reports email_verified=false")

    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()

    if user is not None:
        if user.tenant_id != config.tenant_id:
            # The email belongs to another tenant. Silently moving it would be a
            # cross-tenant account takeover.
            raise SsoError("that email address already belongs to a different organization")
        if not user.is_active:
            raise SsoError("user account is disabled")
        role = map_role(config, claims)
        if role != user.role:
            logger.info(
                "sso.role_updated",
                extra={"tenant_id": config.tenant_id, "user_id": user.id, "from": user.role, "to": role},
            )
            user.role = role
        user.last_login_at = datetime.now(timezone.utc)
        db.flush()
        return user

    if not config.jit_provisioning:
        raise SsoError("no such user in this organization and just-in-time provisioning is disabled")

    user = User(
        tenant_id=config.tenant_id,
        email=email,
        # No usable local password: a random, discarded one, so there is no
        # empty-hash edge case and no password path into an SSO account.
        hashed_password=hash_password(secrets.token_urlsafe(32)),
        full_name=str(claims.get("name") or "")[:255],
        role=map_role(config, claims),
        provisioned_by="sso",
        last_login_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.flush()
    logger.info(
        "sso.user_provisioned",
        extra={"tenant_id": config.tenant_id, "user_id": user.id, "role": user.role},
    )
    return user


def complete_login(
    db: Session,
    *,
    config: TenantSsoConfig,
    claims: dict[str, Any] | None = None,
    code: str | None = None,
    code_verifier: str | None = None,
    redirect_uri: str | None = None,
) -> User:
    """Finish an SSO login.

    Refuses the real code-exchange path, by design. Exchanging the code and
    trusting the resulting ID token requires JWKS-based signature verification
    plus full `iss`/`aud`/`exp`/`nonce` validation; a partial implementation here
    would be an authentication bypass wearing the costume of a feature.

    TODO(FM1/SSO): implement the exchange --
      1. POST to `config.token_endpoint` with grant_type=authorization_code,
         code, code_verifier, redirect_uri, and client auth from
         `config.client_secret_env_var`.
      2. Fetch and cache `config.jwks_uri`, honouring `kid` and key rotation.
      3. `jwt.decode(id_token, key, algorithms=["RS256"], audience=client_id,
         issuer=config.issuer)` and additionally verify `nonce` matches the one
         minted in `build_authorization_url`.
      4. Pass the verified claims to `provision_user`.

    `claims` is accepted directly only outside production, so the mapping and
    provisioning logic above is testable end to end without a live IdP.
    """
    if claims is not None:
        if get_settings().environment.lower() in ("production", "prod"):
            raise SsoError("pre-verified claims are not accepted in production")
        return provision_user(db, config=config, claims=claims)

    raise SsoError(
        "OIDC authorization-code exchange is not implemented: ID-token signature verification against "
        "the issuer's JWKS is required before a token can be trusted, and shipping it unverified would "
        "be an authentication bypass. See app/services/sso.py::complete_login for the remaining steps."
    )
