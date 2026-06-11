"""FastAPI integration for aegistry. Requires ``aegistry[fastapi]``."""

from aegistry.contrib.fastapi.config import (
    AuthConfig,
    EmailOTPSender,
    EmailResolvingOAuth2Factor,
    IdentityResolver,
)
from aegistry.contrib.fastapi.dependencies import (
    build_current_identity_id,
    build_current_session,
)
from aegistry.contrib.fastapi.email_otp import get_email_otp_router
from aegistry.contrib.fastapi.flow import LoginResult, advance_and_complete
from aegistry.contrib.fastapi.oauth2 import get_oauth2_login_router
from aegistry.contrib.fastapi.password import get_password_router
from aegistry.contrib.fastapi.session import SessionInfo, get_session_router

__all__ = [
    "AuthConfig",
    "EmailOTPSender",
    "EmailResolvingOAuth2Factor",
    "IdentityResolver",
    "LoginResult",
    "SessionInfo",
    "advance_and_complete",
    "build_current_identity_id",
    "build_current_session",
    "get_email_otp_router",
    "get_oauth2_login_router",
    "get_password_router",
    "get_session_router",
]
