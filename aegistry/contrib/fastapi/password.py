"""Email/password login router factory (JSON API).

Produces::

    POST /login    {"email": ..., "password": ...}
    POST /register {"email": ..., "password": ...}   (optional)

Logout and session introspection live in the session router
(:func:`~aegistry.contrib.fastapi.session.get_session_router`).

Login responses:
    200 {"status": "complete"} with the session cookie set, or
    200 {"status": "mfa_required", "factors": [...]} with the
        authentication session cookie set for the next factor.
    401 {"detail": "invalid_credentials"} on failure — identical for
        unknown email and wrong password to avoid user enumeration.
"""

import typing
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr

from aegistry.authentication_session import AuthenticationSessionService
from aegistry.contrib.fastapi import cookies
from aegistry.contrib.fastapi.config import AuthConfig, IdentityResolver
from aegistry.contrib.fastapi.flow import advance_and_complete
from aegistry.factors.password import PasswordFactor
from aegistry.session import SessionService


class PasswordCredentials(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    status: typing.Literal["complete", "mfa_required"]
    factors: list[str] = []


def get_password_router(
    *,
    factor_dependency: Callable[..., Awaitable[PasswordFactor] | PasswordFactor],
    authentication_session_service_dependency: Callable[
        ..., Awaitable[AuthenticationSessionService] | AuthenticationSessionService
    ],
    session_service_dependency: Callable[
        ..., Awaitable[SessionService] | SessionService
    ],
    identity_resolver_dependency: Callable[
        ..., Awaitable[IdentityResolver] | IdentityResolver
    ],
    config: AuthConfig,
    enable_register: bool = True,
) -> APIRouter:
    """Build the email/password login router.

    Args:
        factor_dependency: Dependency providing the password factor.
        authentication_session_service_dependency: Dependency providing the
            pre-login authentication session service.
        session_service_dependency: Dependency providing the post-login
            session service.
        identity_resolver_dependency: Dependency providing the application's
            identity resolver.
        config: Shared auth configuration.
        enable_register: Whether to expose the /register route.

    Returns:
        A FastAPI APIRouter with login, logout and (optionally) register routes.
    """
    router = APIRouter()

    @router.post("/login")
    async def _login(
        credentials: PasswordCredentials,
        response: Response,
        factor: PasswordFactor = Depends(factor_dependency),
        authentication_session_service: AuthenticationSessionService = Depends(
            authentication_session_service_dependency
        ),
        session_service: SessionService = Depends(session_service_dependency),
        identity_resolver: IdentityResolver = Depends(identity_resolver_dependency),
    ) -> LoginResponse:
        identity_id = await identity_resolver.get_id_by_email(credentials.email)
        # authenticate() burns comparable CPU time for unknown identities,
        # so unknown email and wrong password are indistinguishable.
        enrollment = await factor.authenticate(identity_id, credentials.password)
        if identity_id is None or enrollment is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_credentials",
            )

        (
            authentication_session_token,
            authentication_session,
        ) = await authentication_session_service.start()
        result = await advance_and_complete(
            authentication_session_service=authentication_session_service,
            session_service=session_service,
            authentication_session=authentication_session,
            identity_id=identity_id,
            factor=factor,
        )

        if result.completed:
            assert result.session_token is not None and result.session is not None
            cookies.set_session_cookie(
                response, config, result.session_token, result.session.expires_at
            )
            return LoginResponse(status="complete")

        cookies.set_authentication_session_cookie(
            response,
            config,
            authentication_session_token,
            authentication_session.expires_at,
        )
        return LoginResponse(status="mfa_required", factors=result.remaining_factors)

    if enable_register:

        @router.post("/register", status_code=status.HTTP_201_CREATED)
        async def _register(
            credentials: PasswordCredentials,
            response: Response,
            factor: PasswordFactor = Depends(factor_dependency),
            authentication_session_service: AuthenticationSessionService = Depends(
                authentication_session_service_dependency
            ),
            session_service: SessionService = Depends(session_service_dependency),
            identity_resolver: IdentityResolver = Depends(identity_resolver_dependency),
        ) -> LoginResponse:
            existing_id = await identity_resolver.get_id_by_email(credentials.email)
            if existing_id is not None:
                enrollment = await factor.get_enrollment(existing_id)
                if enrollment is not None:
                    # Same response as a success would leak less, but a 409
                    # is unavoidable for a credential-creating endpoint;
                    # rate-limit this route in production.
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="already_registered",
                    )
            identity_id = await identity_resolver.get_or_create_by_email(
                credentials.email
            )
            await factor.enroll(identity_id, credentials.password)

            (
                authentication_session_token,
                authentication_session,
            ) = await authentication_session_service.start()
            result = await advance_and_complete(
                authentication_session_service=authentication_session_service,
                session_service=session_service,
                authentication_session=authentication_session,
                identity_id=identity_id,
                factor=factor,
            )

            if result.completed:
                assert result.session_token is not None and result.session is not None
                cookies.set_session_cookie(
                    response, config, result.session_token, result.session.expires_at
                )
                return LoginResponse(status="complete")

            cookies.set_authentication_session_cookie(
                response,
                config,
                authentication_session_token,
                authentication_session.expires_at,
            )
            return LoginResponse(
                status="mfa_required", factors=result.remaining_factors
            )

    return router
