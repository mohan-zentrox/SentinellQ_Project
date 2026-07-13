# SCAFFOLD ONLY -- OIDC/SSO / SAML

Owner (per docs/TEAM.md): [3] Backend/Cloud/AI Systems Engineer (Security
Architect), supporting FM1 Tenant & User Management.

FM1 ships with `LocalAuthProvider` (email + password, PBKDF2 + JWT) as the
working default -- see `app/core/security.py`'s `AuthProvider` abstract
base class. SSO is a documented extension point, not implemented here.

## TODO(FM1 / SSO)

- `OIDCAuthProvider(AuthProvider)` implementing `authenticate()` /
  `issue_token()` against an external Identity Provider (Okta, Azure AD,
  Google Workspace) via the standard OIDC Authorization Code flow.
- SAML 2.0 provider for enterprise IdPs that don't support OIDC.
- Per-tenant IdP configuration (`TenantSsoConfig` entity: issuer, client
  ID/secret or SAML metadata URL, attribute-to-role mapping).
- Just-in-time (JIT) user provisioning on first SSO login, respecting the
  existing `Role` enum in `app/models/user.py`.
- Enforce "SSO required" as a tenant-level setting that disables the local
  email+password path for that tenant once configured.

No code in this directory is imported by the working application.
