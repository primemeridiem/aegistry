"""Dependency builders for the FastAPI integration.

All builders take *dependency callables* (not instances) so that services
can themselves depend on request-scoped resources like database sessions::

    async def get_session_service(db=Depends(get_db)) -> SessionService: ...

    current_session = build_current_session(get_session_service, config)

    @app.get("/me")
    async def me(session: Session = Depends(current_session)) -> ...: ...
"""

import typing
from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status

from aegistry.contrib.fastapi.config import AuthConfig
from aegistry.session import (
    ExpiredSessionException,
    InvalidSessionTokenException,
    Session,
    SessionService,
)

SessionServiceDependency = Callable[..., Awaitable[SessionService] | SessionService]


def build_current_session(
    session_service_dependency: SessionServiceDependency,
    config: AuthConfig,
    *,
    auto_error: bool = True,
) -> Callable[..., Awaitable[Session | None]]:
    """Build a dependency resolving the current post-login session.

    Args:
        session_service_dependency: Dependency providing the SessionService.
        config: The shared auth configuration.
        auto_error: If True, missing or invalid sessions raise a 401;
            otherwise the dependency resolves to None.

    Returns:
        A FastAPI dependency resolving to the current Session (or None).
    """

    async def current_session(
        request: Request,
        session_service: SessionService = Depends(session_service_dependency),
    ) -> Session | None:
        token = request.cookies.get(config.session_cookie_name)
        if token is None:
            if auto_error:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
            return None
        try:
            return await session_service.get_by_token(token)
        except (InvalidSessionTokenException, ExpiredSessionException) as e:
            if auto_error:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED) from e
            return None

    return current_session


def build_current_identity_id(
    session_service_dependency: SessionServiceDependency,
    config: AuthConfig,
) -> Callable[..., Awaitable[typing.Any]]:
    """Build a dependency resolving the current identity ID, or 401."""

    current_session = build_current_session(
        session_service_dependency, config, auto_error=True
    )

    async def current_identity_id(
        session: Session | None = Depends(current_session),
    ) -> typing.Any:
        assert session is not None
        return session.identity_id

    return current_identity_id
