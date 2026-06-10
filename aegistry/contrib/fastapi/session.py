"""Session router factory (JSON API).

Produces::

    GET  /session  -> 200 SessionInfo | 401
    POST /logout   -> 204 (revokes the session, clears the cookie)

``GET /session`` is the endpoint client SDKs poll to know whether the user
is signed in; it intentionally exposes only non-sensitive session metadata.
"""

import typing
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel

from aegistry.contrib.fastapi import cookies
from aegistry.contrib.fastapi.config import AuthConfig
from aegistry.contrib.fastapi.dependencies import build_current_session
from aegistry.session import Session, SessionService


class SessionInfo(BaseModel):
    identity_id: typing.Any
    amr: list[str]
    expires_at: int


def get_session_router(
    *,
    session_service_dependency: Callable[
        ..., Awaitable[SessionService] | SessionService
    ],
    config: AuthConfig,
) -> APIRouter:
    """Build the session introspection/logout router.

    Args:
        session_service_dependency: Dependency providing the post-login
            session service.
        config: Shared auth configuration.

    Returns:
        A FastAPI APIRouter with the session and logout routes.
    """
    router = APIRouter()

    required_session = build_current_session(
        session_service_dependency, config, auto_error=True
    )
    optional_session = build_current_session(
        session_service_dependency, config, auto_error=False
    )

    @router.get("/session", response_model=SessionInfo)
    async def _session(
        session: Session | None = Depends(required_session),
    ) -> SessionInfo:
        assert session is not None
        return SessionInfo(
            identity_id=session.identity_id,
            amr=[str(amr) for amr in session.amr],
            expires_at=session.expires_at,
        )

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def _logout(
        request: Request,
        response: Response,
        session: Session | None = Depends(optional_session),
        session_service: SessionService = Depends(session_service_dependency),
    ) -> None:
        if session is not None:
            await session_service.revoke(session)
        cookies.clear_session_cookie(response, config)

    return router
