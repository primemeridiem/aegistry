"""Email OTP login router factory (JSON API).

Produces::

    POST /email-otp/request {"email": ...}  -> 202 (code sent; always the
        same response whether or not the email is known — no enumeration)
    POST /email-otp/verify  {"code": ...}   -> LoginResponse

One flow, three features: passwordless sign-in, email verification at
signup (the identity is only created after the code is verified), and
password recovery — after an OTP login the session carries
``amr: ["email"]``, which the change-password route accepts as proof of
ownership in place of the current password.

Rate-limit ``/email-otp/request`` in production (proxy or middleware);
each request sends an email.
"""

import typing
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr

from aegistry.authentication_session import (
    AuthenticationSession,
    AuthenticationSessionException,
    AuthenticationSessionService,
)
from aegistry.contrib.fastapi import cookies
from aegistry.contrib.fastapi.config import (
    AuthConfig,
    EmailOTPSender,
    IdentityResolver,
)
from aegistry.contrib.fastapi.flow import advance_and_complete
from aegistry.contrib.fastapi.password import LoginResponse
from aegistry.factors.email_otp import (
    EmailOTPFactor,
    ExpiredOTPException,
    InvalidOTPException,
)
from aegistry.session import SessionService


class EmailOTPRequest(BaseModel):
    email: EmailStr


class EmailOTPVerify(BaseModel):
    code: str


async def _get_or_start_authentication_session(
    request: Request,
    authentication_session_service: AuthenticationSessionService,
    config: AuthConfig,
) -> tuple[str, AuthenticationSession]:
    token = request.cookies.get(config.authentication_session_cookie_name)
    if token is not None:
        try:
            return token, await authentication_session_service.get_by_token(token)
        except AuthenticationSessionException:
            pass
    return await authentication_session_service.start()


def get_email_otp_router(
    *,
    factor_dependency: Callable[..., Awaitable[EmailOTPFactor] | EmailOTPFactor],
    authentication_session_service_dependency: Callable[
        ..., Awaitable[AuthenticationSessionService] | AuthenticationSessionService
    ],
    session_service_dependency: Callable[
        ..., Awaitable[SessionService] | SessionService
    ],
    identity_resolver_dependency: Callable[
        ..., Awaitable[IdentityResolver] | IdentityResolver
    ],
    email_sender_dependency: Callable[..., Awaitable[EmailOTPSender] | EmailOTPSender],
    config: AuthConfig,
) -> APIRouter:
    """Build the email OTP login router.

    Args:
        factor_dependency: Dependency providing the email OTP factor.
        authentication_session_service_dependency: Dependency providing the
            pre-login authentication session service.
        session_service_dependency: Dependency providing the post-login
            session service.
        identity_resolver_dependency: Dependency providing the application's
            identity resolver.
        email_sender_dependency: Dependency providing the email sender hook.
        config: Shared auth configuration.

    Returns:
        A FastAPI APIRouter with the request and verify routes.
    """
    router = APIRouter(prefix="/email-otp")

    @router.post("/request", status_code=status.HTTP_202_ACCEPTED)
    async def _request(
        payload: EmailOTPRequest,
        request: Request,
        response: Response,
        factor: EmailOTPFactor = Depends(factor_dependency),
        authentication_session_service: AuthenticationSessionService = Depends(
            authentication_session_service_dependency
        ),
        identity_resolver: IdentityResolver = Depends(identity_resolver_dependency),
        email_sender: EmailOTPSender = Depends(email_sender_dependency),
    ) -> None:
        (
            authentication_session_token,
            authentication_session,
        ) = await _get_or_start_authentication_session(
            request, authentication_session_service, config
        )

        # identity_id stays None for unknown emails: the identity is created
        # only after the code is verified (signup with verified email).
        identity_id = await identity_resolver.get_id_by_email(payload.email)
        code, _ = await factor.create(
            payload.email,
            authentication_session.id,
            identity_id,
        )
        await email_sender.send_code(payload.email, code)

        cookies.set_authentication_session_cookie(
            response,
            config,
            authentication_session_token,
            authentication_session.expires_at,
        )

    @router.post("/verify")
    async def _verify(
        payload: EmailOTPVerify,
        request: Request,
        response: Response,
        factor: EmailOTPFactor = Depends(factor_dependency),
        authentication_session_service: AuthenticationSessionService = Depends(
            authentication_session_service_dependency
        ),
        session_service: SessionService = Depends(session_service_dependency),
        identity_resolver: IdentityResolver = Depends(identity_resolver_dependency),
    ) -> LoginResponse:
        token = request.cookies.get(config.authentication_session_cookie_name)
        if token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_code"
            )
        try:
            authentication_session = await authentication_session_service.get_by_token(
                token
            )
        except AuthenticationSessionException as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_code"
            ) from e

        try:
            identity_id, email = await factor.consume(
                payload.code, authentication_session.id
            )
        except (InvalidOTPException, ExpiredOTPException) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_code"
            ) from e

        if identity_id is None:
            identity_id = await identity_resolver.get_or_create_by_email(email)

        result = await advance_and_complete(
            authentication_session_service=authentication_session_service,
            session_service=session_service,
            authentication_session=authentication_session,
            identity_id=identity_id,
            factor=typing.cast(typing.Any, factor),
        )

        if result.completed:
            assert result.session_token is not None and result.session is not None
            cookies.set_session_cookie(
                response, config, result.session_token, result.session.expires_at
            )
            cookies.clear_authentication_session_cookie(response, config)
            return LoginResponse(status="complete")

        return LoginResponse(status="mfa_required", factors=result.remaining_factors)

    return router
