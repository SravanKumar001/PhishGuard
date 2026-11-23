import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from app.core.rate_limit import RateLimiter


def test_authentication_profile_and_logout(client: TestClient) -> None:
    credentials = {"email": "analyst@example.com", "password": "phishguard-test-password"}
    registered = client.post("/api/auth/register", json=credentials)
    assert registered.status_code == 201
    assert registered.json()["email"] == credentials["email"]
    assert "password_hash" not in registered.json()
    assert client.post("/api/auth/register", json=credentials).status_code == 409

    invalid_login = client.post(
        "/api/auth/login",
        json={"email": credentials["email"], "password": "incorrect-password"},
    )
    assert invalid_login.status_code == 401

    login = client.post("/api/auth/login", json=credentials)
    assert login.status_code == 200
    assert "httponly" in login.headers["set-cookie"].lower()
    assert client.get("/api/auth/me").json()["email"] == credentials["email"]

    updated = client.put("/api/auth/me", json={"email": "new-address@example.com"})
    assert updated.status_code == 200
    assert updated.json()["email"] == "new-address@example.com"

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_registration_and_login_input_validation(client: TestClient) -> None:
    assert (
        client.post(
            "/api/auth/register",
            json={"email": "not-an-email", "password": "short"},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/auth/register",
            json={"email": "valid@example.com", "password": "short"},
        ).status_code
        == 422
    )


def test_protected_routes_reject_anonymous_access(client: TestClient) -> None:
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/investigations").status_code == 401
    assert client.post("/api/investigations", json={"title": "No auth"}).status_code == 401


def test_users_cannot_access_another_users_investigation(
    authenticated_client: TestClient,
) -> None:
    investigation_id = authenticated_client.post(
        "/api/investigations", json={"title": "Private investigation"}
    ).json()["id"]
    authenticated_client.post("/api/auth/logout")

    second_user = {
        "email": "second-analyst@example.com",
        "password": "another-test-password",
    }
    assert authenticated_client.post("/api/auth/register", json=second_user).status_code == 201
    assert authenticated_client.post("/api/auth/login", json=second_user).status_code == 200

    assert authenticated_client.get("/api/investigations").json()["items"] == []
    assert authenticated_client.get(f"/api/investigations/{investigation_id}").status_code == 404
    assert (
        authenticated_client.patch(
            f"/api/investigations/{investigation_id}",
            json={"title": "Unauthorized edit"},
        ).status_code
        == 404
    )
    assert (
        authenticated_client.delete(f"/api/investigations/{investigation_id}").status_code
        == 404
    )


def test_rate_limiter_rejects_excess_attempts() -> None:
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    limiter.check("login:test-client")

    with pytest.raises(HTTPException) as error:
        limiter.check("login:test-client")

    assert error.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert error.value.headers["Retry-After"]


def test_password_reset_and_email_verification_require_configured_delivery(
    authenticated_client: TestClient,
) -> None:
    reset = authenticated_client.post(
        "/api/auth/password-reset/request",
        json={"email": "analyst@example.com"},
    )
    verification = authenticated_client.post("/api/auth/email-verification/request")

    assert reset.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert verification.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
