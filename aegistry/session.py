"""Post-login session management.

While ``aegistry.authentication_session`` models the *pre-login* MFA flow,
this module manages the session a user holds *after* authentication
completes: an opaque, prefixed token whose HMAC-SHA256 hash is persisted,
with optional sliding expiration.
"""

import abc
import dataclasses
import datetime
import typing

from aegistry.amr import AuthenticationMethodReference
from aegistry.crypto import TokenHash, generate_token_hash_pair, get_token_hash
from aegistry.exceptions import AegistryException
from aegistry.logging import get_logger
from aegistry.timestamp import get_current_timestamp

logger = get_logger(__name__)


@dataclasses.dataclass
class Session:
    id: typing.Any | None
    token_hash: TokenHash
    identity_id: typing.Any
    expires_at: int
    amr: list[AuthenticationMethodReference] = dataclasses.field(default_factory=list)
    context: dict[str, typing.Any] | None = None

    def is_expired(self) -> bool:
        """
        Check if the session has expired.

        Returns:
            True if the session has expired, False otherwise.
        """
        return get_current_timestamp() >= self.expires_at


class SessionException(AegistryException):
    """Base exception for session errors."""


class InvalidSessionTokenException(SessionException):
    """Raised when a token is invalid or does not correspond to any session."""


class ExpiredSessionException(SessionException):
    """Raised when a session has expired."""


class SessionService(abc.ABC):
    """
    Abstract base class for managing post-login sessions.

    A session is created once an authentication session completes, typically
    from the ``(identity_id, amr)`` tuple returned by
    ``AuthenticationSessionService.complete()``.
    """

    def __init__(
        self,
        *,
        hash_secret: str,
        token_prefix: str = "aegistry_s_",
        lifetime: datetime.timedelta = datetime.timedelta(days=30),
        sliding: bool = True,
    ) -> None:
        """
        Initialize the session service.

        Args:
            hash_secret: The secret key used for HMAC token hashing.
            token_prefix: Prefix prepended to generated session tokens.
            lifetime: Session lifetime from creation or last extension.
            sliding: If True, sessions past half their lifetime are extended
                on each successful ``get_by_token`` call.
        """
        logger.debug(
            "SessionService initialized",
            extra={
                "token_prefix": token_prefix,
                "lifetime_seconds": int(lifetime.total_seconds()),
                "sliding": sliding,
            },
        )
        self.hash_secret = hash_secret
        self.token_prefix = token_prefix
        self.lifetime = lifetime
        self.sliding = sliding

    async def create(
        self,
        identity_id: typing.Any,
        amr: list[AuthenticationMethodReference] | None = None,
        **context: typing.Any,
    ) -> tuple[str, Session]:
        """
        Create a new session for an identity.

        Args:
            identity_id: The ID of the authenticated identity.
            amr: Authentication Method References used to authenticate,
                as returned by ``AuthenticationSessionService.complete()``.
            **context: Optional keyword arguments for any additional data to
                store with the session (e.g., user_agent="...").

        Returns:
            A tuple of (token, Session instance).
            Only the hash of the token is persisted; the raw token must be
            handed to the user agent (e.g., as an httpOnly cookie).
        """
        token, token_hash = generate_token_hash_pair(
            secret=self.hash_secret, prefix=self.token_prefix
        )
        session = Session(
            id=None,
            token_hash=token_hash,
            identity_id=identity_id,
            expires_at=get_current_timestamp() + int(self.lifetime.total_seconds()),
            amr=amr or [],
            context=context if context else None,
        )
        session.id = await self.insert(session)
        logger.info(
            "Session created",
            extra={
                "session_id": session.id,
                "identity_id": identity_id,
                "expires_at": session.expires_at,
            },
        )
        return token, session

    async def get_by_token(self, token: str) -> Session:
        """
        Validate a token and return the corresponding session.

        If sliding expiration is enabled and the session is past half its
        lifetime, the expiration is extended and persisted.

        Args:
            token: The session token to validate.

        Returns:
            The corresponding Session instance.

        Raises:
            InvalidSessionTokenException: If the token is invalid or does not correspond to any session.
            ExpiredSessionException: If the session corresponding to the token has expired.
        """
        logger.debug("Session token validation attempted")
        token_hash = get_token_hash(token, secret=self.hash_secret)
        session = await self.get_by_token_hash(token_hash)
        if session is None:
            logger.warning("Invalid session token provided")
            raise InvalidSessionTokenException()
        if session.is_expired():
            logger.warning("Session expired", extra={"session_id": session.id})
            raise ExpiredSessionException()

        if self.sliding:
            lifetime_seconds = int(self.lifetime.total_seconds())
            remaining = session.expires_at - get_current_timestamp()
            if remaining < lifetime_seconds / 2:
                session.expires_at = get_current_timestamp() + lifetime_seconds
                await self.update(session)
                logger.info(
                    "Session extended",
                    extra={
                        "session_id": session.id,
                        "expires_at": session.expires_at,
                    },
                )

        return session

    async def revoke(self, session: Session) -> None:
        """
        Revoke a single session.

        Args:
            session: The Session instance to revoke.
        """
        await self.delete(session)
        logger.info(
            "Session revoked",
            extra={"session_id": session.id, "identity_id": session.identity_id},
        )

    async def revoke_all(self, identity_id: typing.Any) -> None:
        """
        Revoke all sessions of an identity, e.g. after a password change.

        Args:
            identity_id: The ID of the identity whose sessions to revoke.
        """
        await self.delete_by_identity_id(identity_id)
        logger.info("All sessions revoked", extra={"identity_id": identity_id})

    @abc.abstractmethod
    async def insert(self, session: Session) -> typing.Any:
        """
        Insert a session into a persistent store.

        Args:
            session: The Session instance to insert.

        Returns:
            The ID of the inserted session.
        """
        ...

    @abc.abstractmethod
    async def get_by_token_hash(self, token_hash: TokenHash) -> Session | None:
        """
        Retrieve a session by its token hash from the persistent store.

        Args:
            token_hash: The hash of the token to look up.

        Returns:
            The corresponding Session instance, or None if not found.
        """
        ...

    @abc.abstractmethod
    async def update(self, session: Session) -> None:
        """
        Update a session in the persistent store.

        Args:
            session: The Session instance to update.
        """
        ...

    @abc.abstractmethod
    async def delete(self, session: Session) -> None:
        """
        Delete a session from the persistent store.

        Args:
            session: The Session instance to delete.
        """
        ...

    @abc.abstractmethod
    async def delete_by_identity_id(self, identity_id: typing.Any) -> None:
        """
        Delete all sessions of an identity from the persistent store.

        Args:
            identity_id: The ID of the identity whose sessions to delete.
        """
        ...
