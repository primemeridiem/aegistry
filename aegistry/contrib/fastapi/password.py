"""Email/password login router factory (JSON API).

Produces::

    POST /login           {"email": ..., "password": ...}
    POST /register        {"email": ..., "password": ...}   (optional)
    POST /change-password {"new_password": ..., "current_password": ...?}

Logout and session introspection live in the session router
(:func:`~aegistry.contrib.fastapi.session.get_session_router`).

Login responses:
    200 {"status": "complete"} with the session cookie set, or
    200 {"status": "mfa_required", "factors": [...]} with the
        authentication session cookie set for the next factor.
    401 {"detail": "invalid_credentials"} on failure — identical for
        unknown email and wrong password to avoid user enumeration.

Change-password requires an authenticated session plus one proof:
the current password, or a session whose AMR includes "email" (the user
just proved ownership through an OTP — this is the password recovery
path). On success all sessions are revoked and a fresh one is issued.
"""

import typing
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr

from aegistry.amr import AuthenticationMethodReference
from aegistry.authentication_session import AuthenticationSessionService
from aegistry.contrib.fastapi import cookies
from aegistry.contrib.fastapi.config import AuthConfig, IdentityResolver
from aegistry.contrib.fastapi.dependencies import build_current_session
from aegistry.contrib.fastapi.flow import advance_and_complete
from aegistry.factors.password import PasswordFactor
from aegistry.session import Session, SessionService


class PasswordCredentials(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    status: typing.Literal["complete", "mfa_required"]
    factors: list[str] = []


class ChangePassword(BaseModel):
    new_password: str
    current_password: str | None = None


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

    required_session = build_current_session(
        session_service_dependency, config, auto_error=True
    )

    @router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
    async def _change_password(
        payload: ChangePassword,
        response: Response,
        session: Session | None = Depends(required_session),
        factor: PasswordFactor = Depends(factor_dependency),
        session_service: SessionService = Depends(session_service_dependency),
    ) -> None:
        assert session is not None
        enrollment = await factor.get_enrollment(session.identity_id)

        if enrollment is None:
            # First password for an identity that signed up via OTP/OAuth.
            await factor.enroll(session.identity_id, payload.new_password)
        else:
            if payload.current_password is not None:
                verified = await factor.authenticate(
                    session.identity_id, payload.current_password
                )
                if verified is None:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="invalid_current_password",
                    )
            elif AuthenticationMethodReference.EMAIL not in session.amr:
                # Recovery path: an OTP-authenticated session proves email
                # ownership; anything else must present the current password.
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="current_password_required",
                )
            await factor.change(session.identity_id, payload.new_password)

        # Invalidate every session (including any attacker's), then keep the
        # user signed in with a fresh one.
        await session_service.revoke_all(session.identity_id)
        token, new_session = await session_service.create(
            session.identity_id, session.amr
        )
        cookies.set_session_cookie(response, config, token, new_session.expires_at)

    return router
