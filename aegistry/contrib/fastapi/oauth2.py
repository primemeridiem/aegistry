"""OAuth2/OIDC login router factory.

Produces, per provider, a browser-flow router with::

    GET  /{identifier}/authorize  -> 303 redirect to the provider
    GET  /{identifier}/callback   -> 303 redirect to success/MFA/error URL

The flow is adapted from Polar's production implementation: server-side
state (consumed atomically) plus a state cookie binding the flow to the
user agent, PKCE (S256) and an OIDC nonce, and an authentication session
carried in a cookie — with a token-hash fallback through the OAuth2 state
context for POST callbacks (e.g. Apple), where cookies may not be sent.
"""

import secrets
import typing
import urllib.parse
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import RedirectResponse

from aegistry.authentication_session import (
    AuthenticationSession,
    AuthenticationSessionException,
    AuthenticationSessionService,
)
from aegistry.contrib.fastapi import cookies
from aegistry.contrib.fastapi.config import (
    AuthConfig,
    EmailResolvingOAuth2Factor,
    IdentityResolver,
)
from aegistry.contrib.fastapi.flow import advance_and_complete
from aegistry.factors.oauth2.base import (
    OAuth2CallbackException,
    OAuth2Exception,
    OAuth2Factor,
    OAuth2TokenException,
)
from aegistry.factors.oauth2.state import (
    ExpiredStateException,
    InvalidStateException,
)
from aegistry.logging import get_logger
from aegistry.session import SessionService

logger = get_logger(__name__)

AUTHENTICATION_SESSION_TOKEN_HASH_CONTEXT_KEY = "authentication_session_token_hash"


def _error_redirect(config: AuthConfig, message: str) -> RedirectResponse:
    query = urllib.parse.urlencode({"error": message})
    return RedirectResponse(f"{config.error_redirect_url}?{query}", status_code=303)


def get_oauth2_login_router(
    *,
    identifier: str,
    factor_dependency: Callable[..., Awaitable[OAuth2Factor[typing.Any]]],
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
    scope: list[str] | None = None,
    callback_method: typing.Literal["GET", "POST"] = "GET",
    callback_base_url: str | None = None,
) -> APIRouter:
    """Build a login router for one OAuth2/OIDC provider.

    Args:
        identifier: The factor identifier; also used as the route prefix.
        factor_dependency: Dependency providing the OAuth2 factor. The factor
            must also implement ``get_email()``
            (see :class:`~aegistry.contrib.fastapi.config.EmailResolvingOAuth2Factor`).
        authentication_session_service_dependency: Dependency providing the
            pre-login authentication session service.
        session_service_dependency: Dependency providing the post-login
            session service.
        identity_resolver_dependency: Dependency providing the application's
            identity resolver.
        config: Shared auth configuration.
        scope: Scopes to request; the OIDC factor adds ``openid`` itself.
        callback_method: HTTP method of the provider callback. Use "POST"
            for providers using ``response_mode=form_post`` (e.g. Apple).
        callback_base_url: Base URL used to build the provider redirect_uri,
            producing ``{callback_base_url}/{identifier}/callback``. Required
            when the routes are served behind a same-origin proxy (e.g. a
            Next.js rewrite), where ``request.url_for()`` would generate the
            backend host instead of the public one. Defaults to deriving the
            redirect_uri from the incoming request.

    Returns:
        A FastAPI APIRouter with the authorize and callback routes.
    """
    router = APIRouter(prefix=f"/{identifier}", include_in_schema=False)

    @router.get("/authorize", name=f"aegistry.{identifier}.authorize")
    async def _authorize(
        request: Request,
        factor: OAuth2Factor[typing.Any] = Depends(factor_dependency),
        authentication_session_service: AuthenticationSessionService = Depends(
            authentication_session_service_dependency
        ),
    ) -> RedirectResponse:
        # Reuse the pending authentication session, or start a fresh one.
        authentication_session: AuthenticationSession | None = None
        authentication_session_token = request.cookies.get(
            config.authentication_session_cookie_name
        )
        if authentication_session_token is not None:
            try:
                authentication_session = (
                    await authentication_session_service.get_by_token(
                        authentication_session_token
                    )
                )
            except AuthenticationSessionException:
                authentication_session = None
        if authentication_session is None:
            (
                authentication_session_token,
                authentication_session,
            ) = await authentication_session_service.start()

        available_factors = await authentication_session_service.get_available_factors(
            authentication_session
        )
        if factor.identifier not in {f.identifier for f in available_factors}:
            return _error_redirect(config, "factor_not_available")

        if callback_base_url is not None:
            redirect_uri = f"{callback_base_url.rstrip('/')}/{identifier}/callback"
        else:
            redirect_uri = str(request.url_for(f"aegistry.{identifier}.callback"))
        try:
            authorization_url, state, oauth2_state = await factor.start(
                redirect_uri=redirect_uri,
                scope=scope,
                code_challenge_method="S256",
                nonce=secrets.token_urlsafe(16),
                **{
                    AUTHENTICATION_SESSION_TOKEN_HASH_CONTEXT_KEY: (
                        authentication_session.token_hash
                    )
                },
            )
        except OAuth2Exception:
            logger.exception("OAuth2 authorize failed", extra={"provider": identifier})
            return _error_redirect(config, "authorization_failed")

        response = RedirectResponse(authorization_url, status_code=303)
        cookies.set_state_cookie(response, config, state, oauth2_state.expires_at)
        cookies.set_authentication_session_cookie(
            response,
            config,
            authentication_session_token,
            authentication_session.expires_at,
        )
        return response

    QueryOrForm = Query if callback_method == "GET" else Form

    @router.api_route(
        "/callback",
        name=f"aegistry.{identifier}.callback",
        methods=[callback_method],
    )
    async def _callback(
        request: Request,
        code: str | None = QueryOrForm(None),
        error: str | None = QueryOrForm(None),
        error_description: str | None = QueryOrForm(None),
        error_uri: str | None = QueryOrForm(None),
        state: str | None = QueryOrForm(None),
        factor: OAuth2Factor[typing.Any] = Depends(factor_dependency),
        authentication_session_service: AuthenticationSessionService = Depends(
            authentication_session_service_dependency
        ),
        session_service: SessionService = Depends(session_service_dependency),
        identity_resolver: IdentityResolver = Depends(identity_resolver_dependency),
    ) -> RedirectResponse:
        if state is None:
            return _error_redirect(config, "missing_state")

        # Bind the flow to the user agent through the state cookie. POST
        # callbacks are cross-site, so the cookie may not be sent; the
        # server-side state consumption still protects those flows.
        if request.method != "POST":
            state_cookie = request.cookies.get(config.state_cookie_name)
            if state_cookie is None or state != state_cookie:
                return _error_redirect(config, "invalid_state")

        try:
            enrollment, oauth2_account, oauth2_state = await factor.callback(
                code=code,
                state=state,
                error=error,
                error_description=error_description,
                error_uri=error_uri,
            )
        except (ExpiredStateException, InvalidStateException):
            return _error_redirect(config, "expired_state")
        except (OAuth2CallbackException, OAuth2TokenException, OAuth2Exception):
            logger.exception("OAuth2 callback failed", extra={"provider": identifier})
            return _error_redirect(config, "callback_failed")

        # Resolve the authentication session: cookie first, then the token
        # hash stored in the OAuth2 state context (POST callback fallback).
        authentication_session: AuthenticationSession | None = None
        authentication_session_token = request.cookies.get(
            config.authentication_session_cookie_name
        )
        if authentication_session_token is not None:
            try:
                authentication_session = (
                    await authentication_session_service.get_by_token(
                        authentication_session_token
                    )
                )
            except AuthenticationSessionException:
                authentication_session = None
        if authentication_session is None and oauth2_state.context is not None:
            token_hash = oauth2_state.context.get(
                AUTHENTICATION_SESSION_TOKEN_HASH_CONTEXT_KEY
            )
            if token_hash is not None:
                authentication_session = (
                    await authentication_session_service.get_by_token_hash(token_hash)
                )
        if authentication_session is None:
            return _error_redirect(config, "no_authentication_session")

        # Existing or linked account
        if enrollment is not None:
            identity_id = enrollment.identity_id
        # New account: resolve or create the identity by email
        else:
            assert oauth2_account is not None
            email_factor = typing.cast(EmailResolvingOAuth2Factor, factor)
            try:
                email = await email_factor.get_email(oauth2_account)
            except Exception:
                logger.exception(
                    "OAuth2 email resolution failed", extra={"provider": identifier}
                )
                return _error_redirect(config, "email_unavailable")
            identity_id = await identity_resolver.get_or_create_by_email(email)
            await factor.enroll(identity_id, oauth2_account)

        result = await advance_and_complete(
            authentication_session_service=authentication_session_service,
            session_service=session_service,
            authentication_session=authentication_session,
            identity_id=identity_id,
            factor=factor,
        )

        if result.completed:
            assert result.session_token is not None and result.session is not None
            response = RedirectResponse(config.success_redirect_url, status_code=303)
            cookies.set_session_cookie(
                response, config, result.session_token, result.session.expires_at
            )
            cookies.clear_authentication_session_cookie(response, config)
        else:
            response = RedirectResponse(config.mfa_redirect_url, status_code=303)

        cookies.clear_state_cookie(response, config)
        return response

    return router
