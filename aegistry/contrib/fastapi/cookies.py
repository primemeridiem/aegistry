"""Cookie helpers for the FastAPI integration."""

from fastapi import Response

from aegistry.contrib.fastapi.config import AuthConfig


def set_session_cookie(
    response: Response, config: AuthConfig, token: str, expires_at: int
) -> None:
    response.set_cookie(
        config.session_cookie_name,
        token,
        path="/",
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        domain=config.cookie_domain,
        expires=expires_at,
    )


def clear_session_cookie(response: Response, config: AuthConfig) -> None:
    response.delete_cookie(
        config.session_cookie_name,
        path="/",
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        domain=config.cookie_domain,
    )


def set_authentication_session_cookie(
    response: Response, config: AuthConfig, token: str, expires_at: int
) -> None:
    response.set_cookie(
        config.authentication_session_cookie_name,
        token,
        path="/",
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        domain=config.cookie_domain,
        expires=expires_at,
    )


def clear_authentication_session_cookie(response: Response, config: AuthConfig) -> None:
    response.delete_cookie(
        config.authentication_session_cookie_name,
        path="/",
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        domain=config.cookie_domain,
    )


def set_state_cookie(
    response: Response, config: AuthConfig, state: str, expires_at: int
) -> None:
    response.set_cookie(
        config.state_cookie_name,
        state,
        path="/",
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        domain=config.cookie_domain,
        expires=expires_at,
    )


def clear_state_cookie(response: Response, config: AuthConfig) -> None:
    response.delete_cookie(
        config.state_cookie_name,
        path="/",
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        domain=config.cookie_domain,
    )
