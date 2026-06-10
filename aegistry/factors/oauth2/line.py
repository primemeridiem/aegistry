"""LINE Login v2.1 factor.

References:
    - LINE Login: https://developers.line.biz/en/docs/line-login/integrate-line-login/
    - ID token verification: https://developers.line.biz/en/docs/line-login/verify-id-token/
"""

import abc
import typing

import httpx

from aegistry.factors.oauth2.oidc import InvalidIDTokenException, OIDCFactor
from aegistry.factors.oauth2.state import OAuth2StateService
from aegistry.logging import get_logger

logger = get_logger(__name__)


class LineOAuth2Factor(OIDCFactor, abc.ABC):
    """
    LINE Login factor implementation, using the OpenID Connect protocol.

    LINE publishes an OIDC discovery document, but ID tokens issued for web
    login are signed with HS256 using the channel secret — not with a key
    from the JWKS endpoint. ID tokens are therefore validated through LINE's
    dedicated verify endpoint instead of locally against the JWKS, as
    recommended by LINE's documentation.

    Notes:
        - Requesting the ``email`` scope requires applying for the email
          permission in the LINE Developers console.
        - LINE never exposes an ``email_verified`` claim. Do NOT auto-link a
          LINE account to an existing identity by email without an additional
          verification step.
    """

    DISCOVERY_ENDPOINT = "https://access.line.me/.well-known/openid-configuration"
    VERIFY_ENDPOINT = "https://api.line.me/oauth2/v2.1/verify"

    def __init__(
        self,
        *,
        identifier: str = "line",
        client_id: str,
        client_secret: str,
        state_service: OAuth2StateService,
        step: int = 0,
    ) -> None:
        super().__init__(
            identifier=identifier,
            step=step,
            client_id=client_id,
            client_secret=client_secret,
            state_service=state_service,
        )

    async def _get_discovery_document(self) -> dict[str, typing.Any]:
        """Fetch the discovery document, forcing client_secret_post.

        LINE's discovery document omits ``token_endpoint_auth_methods_supported``,
        but its token endpoint requires client credentials in the request body
        rather than HTTP Basic auth.
        """
        discovery_document = await super()._get_discovery_document()
        discovery_document.setdefault(
            "token_endpoint_auth_methods_supported", ["client_secret_post"]
        )
        return discovery_document

    async def _validate_id_token(
        self,
        id_token: str,
        *,
        nonce: str | None = None,
        access_token: str | None = None,
    ) -> dict[str, typing.Any]:
        """Validate a LINE ID Token through the verify endpoint.

        The verify endpoint checks the token signature (HS256 or ES256),
        expiration, issuer, audience, and — when provided — the nonce.
        Audience and nonce are nevertheless double-checked locally.

        Args:
            id_token: The ID Token JWT string.
            nonce: Expected nonce value for replay attack protection.
            access_token: Unused; the verify endpoint covers token integrity,
                so no at_hash validation is performed.

        Returns:
            The token claims as a dictionary.

        Raises:
            InvalidIDTokenException: If the token is invalid.
        """
        data = {"id_token": id_token, "client_id": self.client_id}
        if nonce is not None:
            data["nonce"] = nonce

        client = self._get_client()
        try:
            response = await client.post(self.VERIFY_ENDPOINT, data=data)
        except httpx.RequestError as e:
            raise InvalidIDTokenException() from e

        if not response.is_success:
            logger.warning(
                "LINE ID token verification failed",
                extra={"status_code": response.status_code},
            )
            raise InvalidIDTokenException()

        payload: dict[str, typing.Any] = response.json()

        if payload.get("aud") != self.client_id:
            logger.warning("LINE ID token audience mismatch")
            raise InvalidIDTokenException()

        if nonce is not None and payload.get("nonce") != nonce:
            logger.warning("LINE ID token nonce mismatch")
            raise InvalidIDTokenException()

        return payload
