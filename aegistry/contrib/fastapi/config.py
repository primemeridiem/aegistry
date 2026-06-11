"""Configuration for the FastAPI integration."""

import dataclasses
import typing


@dataclasses.dataclass
class AuthConfig:
    """Settings shared by the aegistry FastAPI routers and dependencies.

    Attributes:
        session_cookie_name: Cookie holding the post-login session token.
        authentication_session_cookie_name: Cookie holding the pre-login
            (MFA flow) authentication session token.
        state_cookie_name: Cookie binding the OAuth2 state to the user agent.
        cookie_secure: Whether cookies are flagged Secure. Disable only for
            local development over plain HTTP.
        cookie_domain: Optional explicit cookie domain.
        success_redirect_url: Where browser flows land after full login.
        mfa_redirect_url: Where browser flows land when more factors are
            required to complete the authentication session.
        error_redirect_url: Where browser flows land on authentication
            errors; the error message is appended as an ``error`` query
            parameter.
    """

    session_cookie_name: str = "aegistry_session"
    authentication_session_cookie_name: str = "aegistry_auth_session"
    state_cookie_name: str = "aegistry_oauth2_state"
    cookie_secure: bool = True
    cookie_domain: str | None = None
    success_redirect_url: str = "/"
    mfa_redirect_url: str = "/auth/mfa"
    error_redirect_url: str = "/auth/error"


class IdentityResolver(typing.Protocol):
    """Application hook mapping provider emails to identity IDs.

    Implementations typically wrap the application's user repository.
    """

    async def get_id_by_email(self, email: str) -> typing.Any | None:
        """Return the identity ID for an email, or None if unknown."""
        ...

    async def get_or_create_by_email(self, email: str) -> typing.Any:
        """Return the identity ID for an email, creating the identity if needed.

        Only called after the factor authenticated the user. Implementations
        should treat emails from providers without verified-email semantics
        (e.g. LINE) carefully — see the factor's documentation.
        """
        ...


class EmailResolvingOAuth2Factor(typing.Protocol):
    """OAuth2 factors used with the login router must expose the account email."""

    async def get_email(self, callback_result: typing.Any) -> str:
        """Extract the email from an OAuth2Account or OAuth2Enrollment."""
        ...


class EmailOTPSender(typing.Protocol):
    """Application hook delivering OTP codes — wrap your email provider here."""

    async def send_code(self, email: str, code: str) -> None:
        """Send a one-time code to an email address."""
        ...
