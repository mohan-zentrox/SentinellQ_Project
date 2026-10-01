"""FM1: session lifecycle, revocation, rate limiting, and RBAC guards.

Each test here corresponds to something the original build had no mechanism for:
there was no refresh token, no logout, no password change, no login rate limit,
no way to deactivate a user, and no way to revoke an issued access token.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.services.auth import login_rate_limiter
from tests.conftest import auth_headers, signup


def test_signup_and_login_return_a_refresh_token(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    assert owner["refreshToken"]
    assert owner["expiresIn"] == get_settings().access_token_expire_minutes * 60

    logged_in = client.post(
        "/v1/auth/login",
        json={"email": "owner@acme.test", "password": "correct-horse-1"},
    ).json()
    assert logged_in["refreshToken"]
    assert logged_in["refreshToken"] != owner["refreshToken"]


def test_refresh_rotates_the_token_and_the_old_one_stops_working(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    first = owner["refreshToken"]

    rotated = client.post("/v1/auth/refresh", json={"refreshToken": first})
    assert rotated.status_code == 200, rotated.text
    body = rotated.json()
    assert body["accessToken"]
    assert body["refreshToken"] != first

    # The new access token works.
    assert client.get("/v1/auth/me", headers=auth_headers(body["accessToken"])).status_code == 200

    # Single-use: replaying the first token fails.
    replay = client.post("/v1/auth/refresh", json={"refreshToken": first})
    assert replay.status_code == 401


def test_refresh_token_reuse_revokes_the_whole_family(client: TestClient):
    """Standard refresh-token-theft mitigation: if a token is replayed, assume
    the chain is compromised and kill all of it."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    first = owner["refreshToken"]

    second = client.post("/v1/auth/refresh", json={"refreshToken": first}).json()["refreshToken"]
    # Replay the already-used first token.
    assert client.post("/v1/auth/refresh", json={"refreshToken": first}).status_code == 401
    # The legitimate successor is now revoked too.
    assert client.post("/v1/auth/refresh", json={"refreshToken": second}).status_code == 401


def test_logout_revokes_one_session(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]

    resp = client.post(
        "/v1/auth/logout",
        json={"refreshToken": owner["refreshToken"]},
        headers=auth_headers(access),
    )
    assert resp.status_code == 204
    assert client.post("/v1/auth/refresh", json={"refreshToken": owner["refreshToken"]}).status_code == 401


def test_logout_all_devices_invalidates_existing_access_tokens(client: TestClient):
    """"Log out everywhere" must mean it.

    Revoking refresh tokens alone would leave an issued access token valid for up
    to 12 hours, which is not what the person clicking the button means. The
    token_version bump is what closes that.
    """
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    assert client.get("/v1/auth/me", headers=auth_headers(access)).status_code == 200

    resp = client.post("/v1/auth/logout", json={"allDevices": True}, headers=auth_headers(access))
    assert resp.status_code == 204

    after = client.get("/v1/auth/me", headers=auth_headers(access))
    assert after.status_code == 401
    assert "revoked" in after.json()["detail"].lower()


def test_logout_without_a_target_is_a_422(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    resp = client.post("/v1/auth/logout", json={}, headers=auth_headers(owner["accessToken"]))
    assert resp.status_code == 422


def test_password_change_requires_the_current_password_and_ends_sessions(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]

    wrong = client.post(
        "/v1/auth/change-password",
        json={"currentPassword": "nope", "newPassword": "new-correct-horse-2"},
        headers=auth_headers(access),
    )
    assert wrong.status_code == 400

    ok = client.post(
        "/v1/auth/change-password",
        json={"currentPassword": "correct-horse-1", "newPassword": "new-correct-horse-2"},
        headers=auth_headers(access),
    )
    assert ok.status_code == 204

    # Old access token is dead, old password is dead, new password works.
    assert client.get("/v1/auth/me", headers=auth_headers(access)).status_code == 401
    assert client.post(
        "/v1/auth/login", json={"email": "owner@acme.test", "password": "correct-horse-1"}
    ).status_code == 401
    assert client.post(
        "/v1/auth/login", json={"email": "owner@acme.test", "password": "new-correct-horse-2"}
    ).status_code == 200


def test_login_is_rate_limited(client: TestClient):
    signup(client, company="Acme", email="owner@acme.test")
    limit = get_settings().login_rate_limit_attempts

    for _ in range(limit):
        resp = client.post("/v1/auth/login", json={"email": "owner@acme.test", "password": "wrong"})
        assert resp.status_code == 401

    limited = client.post("/v1/auth/login", json={"email": "owner@acme.test", "password": "wrong"})
    assert limited.status_code == 429
    assert "Retry-After" in limited.headers

    # Even the correct password is refused while the window is open -- the limit
    # is on the (email, ip) pair, not on wrong guesses only.
    assert client.post(
        "/v1/auth/login", json={"email": "owner@acme.test", "password": "correct-horse-1"}
    ).status_code == 429


def test_successful_login_resets_the_failure_counter(client: TestClient):
    signup(client, company="Acme", email="owner@acme.test")
    for _ in range(3):
        client.post("/v1/auth/login", json={"email": "owner@acme.test", "password": "wrong"})

    assert client.post(
        "/v1/auth/login", json={"email": "owner@acme.test", "password": "correct-horse-1"}
    ).status_code == 200

    # Budget is fresh again.
    for _ in range(3):
        assert client.post(
            "/v1/auth/login", json={"email": "owner@acme.test", "password": "wrong"}
        ).status_code == 401


def test_unknown_email_and_wrong_password_are_indistinguishable(client: TestClient):
    signup(client, company="Acme", email="owner@acme.test")
    login_rate_limiter.clear()

    unknown = client.post("/v1/auth/login", json={"email": "nobody@acme.test", "password": "whatever1"})
    wrong = client.post("/v1/auth/login", json={"email": "owner@acme.test", "password": "whatever1"})

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]


def test_sessions_endpoint_lists_only_the_callers_own_sessions(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/tenants/me/users",
        json={"email": "other@acme.test", "password": "correct-horse-1", "role": "analyst"},
        headers=auth_headers(access),
    )
    client.post("/v1/auth/login", json={"email": "other@acme.test", "password": "correct-horse-1"})

    sessions = client.get("/v1/auth/sessions", headers=auth_headers(access)).json()
    # Only the owner's own signup session, not the analyst's login.
    assert len(sessions) == 1


def test_deactivating_a_user_immediately_cuts_their_access(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    created = client.post(
        "/v1/tenants/me/users",
        json={"email": "analyst@acme.test", "password": "correct-horse-1", "role": "analyst"},
        headers=auth_headers(access),
    ).json()
    analyst = client.post(
        "/v1/auth/login", json={"email": "analyst@acme.test", "password": "correct-horse-1"}
    ).json()
    assert client.get("/v1/auth/me", headers=auth_headers(analyst["accessToken"])).status_code == 200

    client.patch(
        f"/v1/tenants/me/users/{created['id']}",
        json={"isActive": False},
        headers=auth_headers(access),
    )

    # No waiting for token expiry.
    assert client.get("/v1/auth/me", headers=auth_headers(analyst["accessToken"])).status_code == 401
    assert client.post(
        "/v1/auth/refresh", json={"refreshToken": analyst["refreshToken"]}
    ).status_code == 401


def test_cannot_change_own_role_or_deactivate_self(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    me = client.get("/v1/auth/me", headers=auth_headers(access)).json()

    assert client.patch(
        f"/v1/tenants/me/users/{me['id']}", json={"role": "viewer"}, headers=auth_headers(access)
    ).status_code == 403
    assert client.patch(
        f"/v1/tenants/me/users/{me['id']}", json={"isActive": False}, headers=auth_headers(access)
    ).status_code == 403


def test_last_active_owner_cannot_be_demoted(client: TestClient):
    """Otherwise a tenant can strand itself with no billing-capable account."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    second_owner = client.post(
        "/v1/tenants/me/users",
        json={"email": "owner2@acme.test", "password": "correct-horse-1", "role": "owner"},
        headers=auth_headers(access),
    ).json()

    # Two owners: demoting one is fine.
    demote = client.patch(
        f"/v1/tenants/me/users/{second_owner['id']}",
        json={"role": "admin"},
        headers=auth_headers(access),
    )
    assert demote.status_code == 200

    # Now there is one owner left; the second owner (as admin) cannot demote them.
    admin_login = client.post(
        "/v1/auth/login", json={"email": "owner2@acme.test", "password": "correct-horse-1"}
    ).json()
    me = client.get("/v1/auth/me", headers=auth_headers(access)).json()
    resp = client.patch(
        f"/v1/tenants/me/users/{me['id']}",
        json={"role": "viewer"},
        headers=auth_headers(admin_login["accessToken"]),
    )
    # 403 because only an owner may remove the owner role.
    assert resp.status_code == 403


def test_admin_cannot_grant_the_owner_role(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/tenants/me/users",
        json={"email": "admin@acme.test", "password": "correct-horse-1", "role": "admin"},
        headers=auth_headers(access),
    )
    admin = client.post(
        "/v1/auth/login", json={"email": "admin@acme.test", "password": "correct-horse-1"}
    ).json()

    resp = client.post(
        "/v1/tenants/me/users",
        json={"email": "sneaky@acme.test", "password": "correct-horse-1", "role": "owner"},
        headers=auth_headers(admin["accessToken"]),
    )
    assert resp.status_code == 403


def test_admin_cannot_reset_an_owners_password(client: TestClient):
    """Otherwise "admin" is a one-step path to the billing-capable account."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    me = client.get("/v1/auth/me", headers=auth_headers(access)).json()
    client.post(
        "/v1/tenants/me/users",
        json={"email": "admin@acme.test", "password": "correct-horse-1", "role": "admin"},
        headers=auth_headers(access),
    )
    admin = client.post(
        "/v1/auth/login", json={"email": "admin@acme.test", "password": "correct-horse-1"}
    ).json()

    resp = client.post(
        f"/v1/tenants/me/users/{me['id']}/reset-password",
        json={"newPassword": "stolen-account-1"},
        headers=auth_headers(admin["accessToken"]),
    )
    assert resp.status_code == 403


def test_admin_password_reset_ends_the_targets_sessions(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    created = client.post(
        "/v1/tenants/me/users",
        json={"email": "analyst@acme.test", "password": "correct-horse-1", "role": "analyst"},
        headers=auth_headers(access),
    ).json()
    analyst = client.post(
        "/v1/auth/login", json={"email": "analyst@acme.test", "password": "correct-horse-1"}
    ).json()

    client.post(
        f"/v1/tenants/me/users/{created['id']}/reset-password",
        json={"newPassword": "reset-horse-2"},
        headers=auth_headers(access),
    )

    assert client.get("/v1/auth/me", headers=auth_headers(analyst["accessToken"])).status_code == 401
    assert client.post(
        "/v1/auth/login", json={"email": "analyst@acme.test", "password": "reset-horse-2"}
    ).status_code == 200


def test_cross_tenant_user_management_is_not_found(client: TestClient):
    owner_a = signup(client, company="Acme", email="a@acme.test")
    owner_b = signup(client, company="Globex", email="b@globex.test")
    b_user = client.get("/v1/auth/me", headers=auth_headers(owner_b["accessToken"])).json()

    resp = client.patch(
        f"/v1/tenants/me/users/{b_user['id']}",
        json={"isActive": False},
        headers=auth_headers(owner_a["accessToken"]),
    )
    assert resp.status_code == 404


def test_refresh_token_cannot_be_used_as_a_bearer_token(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    resp = client.get("/v1/auth/me", headers=auth_headers(owner["refreshToken"]))
    assert resp.status_code == 401


def test_email_is_normalized_to_lowercase(client: TestClient):
    signup(client, company="Acme", email="owner@acme.test")
    # Same address, different case: must authenticate, not 401 or create a second
    # account.
    resp = client.post("/v1/auth/login", json={"email": "OWNER@ACME.TEST", "password": "correct-horse-1"})
    assert resp.status_code == 200
