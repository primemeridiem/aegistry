import typing
import urllib.parse

import httpx
import jwt
import pytest

from aegistry.crypto import TokenHash
from aegistry.factors.oauth2.base import OAuth2Enrollment
from aegistry.factors.oauth2.line import LineOAuth2Factor
from aegistry.factors.oauth2.oidc import InvalidIDTokenException
from aegistry.factors.oauth2.state import OAuth2State
from aegistry.timestamp import get_current_timestamp

CLIENT_ID = "test-channel-id"
CLIENT_SECRET = "test-channel-secret-0123456789abcdef"
DISCOVERY_ENDPOINT = LineOAuth2Factor.DISCOVERY_ENDPOINT
VERIFY_ENDPOINT = LineOAuth2Factor.VERIFY_ENDPOINT
AUTHORIZATION_ENDPOINT = "https://access.line.me/oauth2/v2.1/authorize"
TOKEN_ENDPOINT = "https://api.line.me/oauth2/v2.1/token"

# Real-world shape: LINE's discovery document advertises ES256 only and omits
# token_endpoint_auth_methods_supported, while web login id_tokens are HS256.
LINE_DISCOVERY_DOCUMENT = {
    "issuer": "https://access.line.me",
    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
    "token_endpoint": TOKEN_ENDPOINT,
    "userinfo_endpoint": "https://api.line.me/oauth2/v2.1/userinfo",
    "jwks_uri": "https://api.line.me/oauth2/v2.1/certs",
    "id_token_signing_alg_values_supported": ["ES256"],
}


def create_hs256_id_token(
    *,
    audience: str = CLIENT_ID,
    subject: str = "U1234567890",
    nonce: str | None = "NONCE",
) -> str:
    claims: dict[str, typing.Any] = {
        "iss": "https://access.line.me",
        "sub": subject,
        "aud": audience,
        "exp": get_current_timestamp() + 3600,
        "iat": get_current_timestamp(),
        "name": "Test User",
        "email": "user@example.com",
    }
    if nonce is not None:
        claims["nonce"] = nonce
    return jwt.encode(claims, CLIENT_SECRET, algorithm="HS256")


def verify_response_payload(id_token: str) -> dict[str, typing.Any]:
    """Decode the claims the way LINE's verify endpoint echoes them back."""
    return jwt.decode_complete(id_token, options={"verify_signature": False})["payload"]


class MockedLineFactor(LineOAuth2Factor):
    def __init__(self, state_service: typing.Any, id_token: str) -> None:
        super().__init__(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            state_service=state_service,
        )
        self.requests: list[httpx.Request] = []
        self.response_map = {
            DISCOVERY_ENDPOINT: httpx.Response(200, json=LINE_DISCOVERY_DOCUMENT),
            TOKEN_ENDPOINT: httpx.Response(
                200,
                json={
                    "access_token": "test-access-token",
                    "expires_in": 3600,
                    "refresh_token": "test-refresh-token",
                    "id_token": id_token,
                },
            ),
            VERIFY_ENDPOINT: httpx.Response(
                200, json=verify_response_payload(id_token)
            ),
        }

    def _get_client(self) -> httpx.AsyncClient:
        def handle_request(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            url = str(request.url)
            return self.response_map.get(
                url, httpx.Response(404, json={"error": "Not found"})
            )

        return httpx.AsyncClient(transport=httpx.MockTransport(handle_request))

    async def insert(self, enrollment: OAuth2Enrollment) -> int:
        raise NotImplementedError()

    async def update(self, enrollment: OAuth2Enrollment) -> None:
        raise NotImplementedError()

    async def get_enrollment(self, identity_id: int) -> OAuth2Enrollment | None:
        raise NotImplementedError()

    async def get_enrollment_by_provider_and_account(
        self, provider: str, account_id: str
    ) -> OAuth2Enrollment | None:
        raise NotImplementedError()


@pytest.fixture(scope="module")
def oauth2_state() -> OAuth2State:
    return OAuth2State(
        id=None,
        state_hash=TokenHash("test-hash"),
        provider="line",
        code_verifier=None,
        nonce="NONCE",
        redirect_uri="https://redirect.example.com",
        identity_id=None,
        scope=None,
        expires_at=9999999999,
        context=None,
    )


@pytest.fixture
def line_factor(oauth2_state_service: typing.Any) -> MockedLineFactor:
    return MockedLineFactor(oauth2_state_service, create_hs256_id_token())


@pytest.mark.anyio
class TestGetAuthorizationURL:
    async def test_authorization_url(self, line_factor: MockedLineFactor) -> None:
        url = await line_factor.get_authorization_url(
            redirect_uri="https://redirect.example.com",
            scope=["profile", "email"],
            state="STATE",
            nonce="NONCE",
        )

        assert url.startswith(AUTHORIZATION_ENDPOINT)
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        assert params["client_id"] == CLIENT_ID
        assert params["nonce"] == "NONCE"
        assert "openid" in params["scope"]


@pytest.mark.anyio
class TestExchangeCode:
    async def test_success(
        self, line_factor: MockedLineFactor, oauth2_state: OAuth2State
    ) -> None:
        result = await line_factor.exchange_code(
            code="CODE",
            redirect_uri="https://redirect.example.com",
            nonce="NONCE",
            state=oauth2_state,
        )

        assert result.account_id == "U1234567890"
        assert result.access_token == "test-access-token"
        assert result.id_token is not None

    async def test_client_secret_post(
        self, line_factor: MockedLineFactor, oauth2_state: OAuth2State
    ) -> None:
        await line_factor.exchange_code(
            code="CODE",
            redirect_uri="https://redirect.example.com",
            nonce="NONCE",
            state=oauth2_state,
        )

        token_requests = [
            r for r in line_factor.requests if str(r.url) == TOKEN_ENDPOINT
        ]
        assert len(token_requests) == 1
        body = dict(urllib.parse.parse_qsl(token_requests[0].content.decode()))
        # LINE requires credentials in the body, not HTTP Basic auth
        assert body["client_id"] == CLIENT_ID
        assert body["client_secret"] == CLIENT_SECRET
        assert "authorization" not in {k.lower() for k in token_requests[0].headers}


@pytest.mark.anyio
class TestValidateIDToken:
    async def test_valid(self, line_factor: MockedLineFactor) -> None:
        payload = await line_factor._validate_id_token(
            create_hs256_id_token(), nonce="NONCE"
        )

        assert payload["sub"] == "U1234567890"
        assert payload["email"] == "user@example.com"

    async def test_verify_endpoint_error(self, line_factor: MockedLineFactor) -> None:
        line_factor.response_map[VERIFY_ENDPOINT] = httpx.Response(
            400, json={"error": "invalid_request"}
        )

        with pytest.raises(InvalidIDTokenException):
            await line_factor._validate_id_token(create_hs256_id_token(), nonce="NONCE")

    async def test_audience_mismatch(self, line_factor: MockedLineFactor) -> None:
        bad_token = create_hs256_id_token(audience="other-channel")
        line_factor.response_map[VERIFY_ENDPOINT] = httpx.Response(
            200, json=verify_response_payload(bad_token)
        )

        with pytest.raises(InvalidIDTokenException):
            await line_factor._validate_id_token(bad_token, nonce="NONCE")

    async def test_nonce_mismatch(self, line_factor: MockedLineFactor) -> None:
        bad_token = create_hs256_id_token(nonce="OTHER")
        line_factor.response_map[VERIFY_ENDPOINT] = httpx.Response(
            200, json=verify_response_payload(bad_token)
        )

        with pytest.raises(InvalidIDTokenException):
            await line_factor._validate_id_token(bad_token, nonce="NONCE")
