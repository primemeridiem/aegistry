"""Shared login flow logic for the FastAPI routers."""

import dataclasses
import typing

from aegistry.authentication_session import (
    AuthenticationSession,
    AuthenticationSessionService,
    FactorsRemainingException,
)
from aegistry.factors import FactorBase
from aegistry.session import Session, SessionService


@dataclasses.dataclass
class LoginResult:
    """Outcome of advancing an authentication session with a factor.

    If ``completed`` is True, ``session_token``/``session`` hold the new
    post-login session. Otherwise more factors are required and
    ``remaining_factors`` lists the identifiers the user can continue with.
    """

    completed: bool
    authentication_session: AuthenticationSession
    session_token: str | None = None
    session: Session | None = None
    remaining_factors: list[str] = dataclasses.field(default_factory=list)


async def advance_and_complete(
    *,
    authentication_session_service: AuthenticationSessionService,
    session_service: SessionService,
    authentication_session: AuthenticationSession,
    identity_id: typing.Any,
    factor: FactorBase[typing.Any],
    **session_context: typing.Any,
) -> LoginResult:
    """Advance an authentication session and, if complete, open a session.

    Args:
        authentication_session_service: The pre-login session service.
        session_service: The post-login session service.
        authentication_session: The current authentication session.
        identity_id: The identity that completed the factor.
        factor: The factor that was completed.
        **session_context: Extra context stored on the post-login session.

    Returns:
        A LoginResult describing whether login completed or MFA continues.

    Raises:
        UnavailableFactorException: If the factor is not available for the session.
    """
    authentication_session = await authentication_session_service.advance(
        authentication_session, identity_id, factor
    )

    try:
        completed_identity_id, amr = await authentication_session_service.complete(
            authentication_session
        )
    except FactorsRemainingException as e:
        return LoginResult(
            completed=False,
            authentication_session=authentication_session,
            remaining_factors=[f.identifier for f in e.factors],
        )

    token, session = await session_service.create(
        completed_identity_id, amr, **session_context
    )
    return LoginResult(
        completed=True,
        authentication_session=authentication_session,
        session_token=token,
        session=session,
    )
