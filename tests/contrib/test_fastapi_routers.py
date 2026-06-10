import typing

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from aegistry.authentication_session import (
    AuthenticationSession,
    AuthenticationSessionService,
)
from aegistry.contrib.fastapi import (
    AuthConfig,
    build_current_identity_id,
    get_oauth2_login_router,
    get_password_router,
    get_session_router,
)
from aegistry.factors.base import FactorBase
from aegistry.factors.oauth2.base import (
    OAuth2Enrollment,
    OAuth2Factor,
    TokenResponse,
)
from aegistry.factors.oauth2.pkce import CodeChallengeMethod
from aegistry.factors.oauth2.state import OAuth2State, OAuth2StateService
from aegistry.timestamp import get_current_timestamp
from tests.factors.test_password import InMemoryPasswordFactor
from tests.test_session import InMemorySessionService


class InMemoryAuthenticationSessionService(AuthenticationSessionService):
    def __init__(self, factors: set[FactorBase[typing.Any]]) -> None:
        self.storage: dict[int, AuthenticationSession] = {}
        self._id = 0
        super().__init__(hash_secret="test-secret", factors=factors)

    async def insert(self, authentication_session: AuthenticationSession) -> int:
        self._id += 1
        self.storage[self._id] = authentication_session
        return self._id

    async def get_by_token_hash(self, token_hash: str) -> AuthenticationSession | None:
        for authentication_session in self.storage.values():
            if authentication_session.token_hash == token_hash:
                return authentication_session
        return None

    async def update(self, authentication_session: AuthenticationSession) -> None:
        assert authentication_session.id is not None
        self.storage[authentication_session.id] = authentication_session

    async def delete(self, authentication_session: AuthenticationSession) -> None:
        assert authentication_session.id is not None
        del self.storage[authentication_session.id]


class InMemoryOAuth2StateService(OAuth2StateService):
    def __init__(self) -> None:
        self.storage: dict[int, OAuth2State] = {}
        self._id = 0
        super().__init__(hash_secret="test-secret")

    async def get_by_state_hash(self, state_hash: str) -> OAuth2State | None:
        for state in self.storage.values():
            if state.state_hash == state_hash:
                return state
        return None

    async def insert(self, oauth2_state: OAuth2State) -> int:
        self._id += 1
        self.storage[self._id] = oauth2_state
        return self._id

    async def delete(self, oauth2_state: OAuth2State) -> None:
        assert oauth2_state.id is not None
        del self.storage[oauth2_state.id]


class FakeOAuth2Factor(OAuth2Factor[dict]):
    """OAuth2 factor short-circuiting the provider round-trips."""

    def __init__(self, state_service: OAuth2StateService) -> None:
        self.enrollments: dict[int, OAuth2Enrollment] = {}
        self._id = 0
        super().__init__(
            identifier="fake", client_id="client-id", state_service=state_service
        )

    async def get_client_secret(self) -> str:
        return "client-secret"

    async def get_authorization_url(
        self,
        *,
        redirect_uri: str,
        scope: list[str] | None = None,
        state: str,
        code_challenge: str | None = None,
        code_challenge_method: CodeChallengeMethod | None = None,
        nonce: str | None = None,
        extra: dict | None = None,
    ) -> str:
        return f"https://provider.example.com/authorize?state={state}"

    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
        state: OAuth2State,
    ) -> TokenResponse:
        return TokenResponse(
            account_id="fake-account-1",
            access_token="fake-access-token",
            expires_at=get_current_timestamp() + 3600,
            refresh_token=None,
            refresh_token_expires_at=None,
        )

    async def get_profile(self, access_token: str) -> dict[str, typing.Any]:
        return {"sub": "fake-account-1", "email": "user@example.com"}

    async def get_email(self, callback_result: typing.Any) -> str:
        return "user@example.com"

    async def get_enrollment(self, identity_id: typing.Any) -> OAuth2Enrollment | None:
        for enrollment in self.enrollments.values():
            if enrollment.identity_id == identity_id:
                return enrollment
        return None

    async def get_enrollment_by_provider_and_account(
        self, provider: str, account_id: str
    ) -> OAuth2Enrollment | None:
        for enrollment in self.enrollments.values():
            if enrollment.provider == provider and enrollment.account_id == account_id:
                return enrollment
        return None

    async def insert(self, enrollment: OAuth2Enrollment) -> int:
        self._id += 1
        self.enrollments[self._id] = enrollment
        return self._id

    async def update(self, enrollment: OAuth2Enrollment) -> None:
        assert enrollment.id is not None
        self.enrollments[enrollment.id] = enrollment


class InMemoryIdentityResolver:
    def __init__(self) -> None:
        self.users: dict[str, int] = {}
        self._id = 0

    async def get_id_by_email(self, email: str) -> int | None:
        return self.users.get(email)

    async def get_or_create_by_email(self, email: str) -> int:
        if email not in self.users:
            self._id += 1
            self.users[email] = self._id
        return self.users[email]


@pytest.fixture
def app_and_services() -> tuple[FastAPI, dict[str, typing.Any]]:
    password_factor = InMemoryPasswordFactor()
    state_service = InMemoryOAuth2StateService()
    oauth2_factor = FakeOAuth2Factor(state_service)
    authentication_session_service = InMemoryAuthenticationSessionService(
        factors={password_factor, oauth2_factor}
    )
    session_service = InMemorySessionService()
    identity_resolver = InMemoryIdentityResolver()
    config = AuthConfig(cookie_secure=False)

    app = FastAPI()
    app.include_router(
        get_password_router(
            factor_dependency=lambda: password_factor,
            authentication_session_service_dependency=(
                lambda: authentication_session_service
            ),
            session_service_dependency=lambda: session_service,
            identity_resolver_dependency=lambda: identity_resolver,
            config=config,
        ),
        prefix="/auth",
    )
    app.include_router(
        get_oauth2_login_router(
            identifier="fake",
            factor_dependency=lambda: oauth2_factor,
            authentication_session_service_dependency=(
                lambda: authentication_session_service
            ),
            session_service_dependency=lambda: session_service,
            identity_resolver_dependency=lambda: identity_resolver,
            config=config,
        ),
        prefix="/auth",
    )
    app.include_router(
        get_session_router(
            session_service_dependency=lambda: session_service,
            config=config,
        ),
        prefix="/auth",
    )

    current_identity_id = build_current_identity_id(lambda: session_service, config)

    @app.get("/me")
    async def me(
        identity_id: int = Depends(current_identity_id),
    ) -> dict[str, int]:
        return {"identity_id": identity_id}

    services = {
        "password_factor": password_factor,
        "oauth2_factor": oauth2_factor,
        "authentication_session_service": authentication_session_service,
        "session_service": session_service,
        "identity_resolver": identity_resolver,
        "config": config,
    }
    return app, services


@pytest.fixture
def client(app_and_services: tuple[FastAPI, dict[str, typing.Any]]) -> TestClient:
    app, _ = app_and_services
    return TestClient(app)


class TestSessionRouter:
    def test_anonymous(self, client: TestClient) -> None:
        response = client.get("/auth/session")
        assert response.status_code == 401

    def test_authenticated(self, client: TestClient) -> None:
        client.post(
            "/auth/register",
            json={"email": "user@example.com", "password": "herminetincture"},
        )

        response = client.get("/auth/session")

        assert response.status_code == 200
        json = response.json()
        assert json["identity_id"] == 1
        assert json["amr"] == ["pwd"]
        assert json["expires_at"] > 0

    def test_after_logout(self, client: TestClient) -> None:
        client.post(
            "/auth/register",
            json={"email": "user@example.com", "password": "herminetincture"},
        )

        response = client.post("/auth/logout")
        assert response.status_code == 204

        client.cookies.clear()
        response = client.get("/auth/session")
        assert response.status_code == 401


class TestPasswordRouter:
    def test_register_login_me_logout(self, client: TestClient) -> None:
        response = client.post(
            "/auth/register",
            json={"email": "user@example.com", "password": "herminetincture"},
        )
        assert response.status_code == 201
        assert response.json() == {"status": "complete", "factors": []}
        assert "aegistry_session" in response.cookies

        response = client.get("/me")
        assert response.status_code == 200
        assert response.json() == {"identity_id": 1}

        response = client.post("/auth/logout")
        assert response.status_code == 204

        client.cookies.clear()
        response = client.get("/me")
        assert response.status_code == 401

        response = client.post(
            "/auth/login",
            json={"email": "user@example.com", "password": "herminetincture"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "complete"

        response = client.get("/me")
        assert response.status_code == 200

    def test_invalid_credentials(self, client: TestClient) -> None:
        client.post(
            "/auth/register",
            json={"email": "user@example.com", "password": "herminetincture"},
        )
        client.cookies.clear()

        wrong_password = client.post(
            "/auth/login",
            json={"email": "user@example.com", "password": "wrong"},
        )
        unknown_email = client.post(
            "/auth/login",
            json={"email": "nobody@example.com", "password": "herminetincture"},
        )

        # Identical responses for unknown email and wrong password
        assert wrong_password.status_code == unknown_email.status_code == 401
        assert wrong_password.json() == unknown_email.json()

    def test_duplicate_register(self, client: TestClient) -> None:
        client.post(
            "/auth/register",
            json={"email": "user@example.com", "password": "herminetincture"},
        )
        response = client.post(
            "/auth/register",
            json={"email": "user@example.com", "password": "other"},
        )
        assert response.status_code == 409


class TestOAuth2Router:
    def test_full_login_flow(self, client: TestClient) -> None:
        response = client.get("/auth/fake/authorize", follow_redirects=False)
        assert response.status_code == 303
        location = response.headers["location"]
        assert location.startswith("https://provider.example.com/authorize")
        state = location.split("state=")[1]
        assert response.cookies.get("aegistry_oauth2_state") == state
        assert "aegistry_auth_session" in response.cookies

        response = client.get(
            f"/auth/fake/callback?code=CODE&state={state}",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/"
        assert "aegistry_session" in response.cookies

        response = client.get("/me")
        assert response.status_code == 200
        assert response.json() == {"identity_id": 1}

    def test_state_mismatch(self, client: TestClient) -> None:
        client.get("/auth/fake/authorize", follow_redirects=False)

        response = client.get(
            "/auth/fake/callback?code=CODE&state=forged",
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"].startswith("/auth/error")

    def test_missing_state_cookie(self, client: TestClient) -> None:
        response = client.get("/auth/fake/authorize", follow_redirects=False)
        state = response.headers["location"].split("state=")[1]
        client.cookies.clear()

        response = client.get(
            f"/auth/fake/callback?code=CODE&state={state}",
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"].startswith("/auth/error")

    def test_existing_enrollment_reuses_identity(self, client: TestClient) -> None:
        # First login creates the identity and enrollment
        response = client.get("/auth/fake/authorize", follow_redirects=False)
        state = response.headers["location"].split("state=")[1]
        client.get(f"/auth/fake/callback?code=CODE&state={state}")

        # Second login finds the enrollment and maps to the same identity
        client.cookies.clear()
        response = client.get("/auth/fake/authorize", follow_redirects=False)
        state = response.headers["location"].split("state=")[1]
        client.get(f"/auth/fake/callback?code=CODE&state={state}")

        response = client.get("/me")
        assert response.json() == {"identity_id": 1}
