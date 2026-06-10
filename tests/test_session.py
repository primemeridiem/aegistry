import datetime
import typing

import pytest

from aegistry.amr import AuthenticationMethodReference
from aegistry.crypto import TokenHash
from aegistry.session import (
    ExpiredSessionException,
    InvalidSessionTokenException,
    Session,
    SessionService,
)
from aegistry.timestamp import get_current_timestamp


class InMemorySessionService(SessionService):
    def __init__(self, **kwargs: typing.Any) -> None:
        self.storage: dict[int, Session] = {}
        self._id = 0
        super().__init__(hash_secret="test-secret", **kwargs)

    async def insert(self, session: Session) -> int:
        self._id += 1
        self.storage[self._id] = session
        return self._id

    async def get_by_token_hash(self, token_hash: TokenHash) -> Session | None:
        for session in self.storage.values():
            if session.token_hash == token_hash:
                return session
        return None

    async def update(self, session: Session) -> None:
        assert session.id is not None
        self.storage[session.id] = session

    async def delete(self, session: Session) -> None:
        assert session.id is not None
        del self.storage[session.id]

    async def delete_by_identity_id(self, identity_id: typing.Any) -> None:
        self.storage = {
            id_: session
            for id_, session in self.storage.items()
            if session.identity_id != identity_id
        }


@pytest.fixture
def session_service() -> InMemorySessionService:
    return InMemorySessionService()


@pytest.mark.anyio
class TestCreate:
    async def test_create(self, session_service: InMemorySessionService) -> None:
        token, session = await session_service.create(
            42, [AuthenticationMethodReference.PWD], user_agent="test"
        )

        assert token.startswith("aegistry_s_")
        assert session.id == 1
        assert session.identity_id == 42
        assert session.amr == [AuthenticationMethodReference.PWD]
        assert session.context == {"user_agent": "test"}
        assert not session.is_expired()


@pytest.mark.anyio
class TestGetByToken:
    async def test_invalid_token(self, session_service: InMemorySessionService) -> None:
        with pytest.raises(InvalidSessionTokenException):
            await session_service.get_by_token("aegistry_s_invalid")

    async def test_expired_session(
        self, session_service: InMemorySessionService
    ) -> None:
        token, session = await session_service.create(42)
        session.expires_at = get_current_timestamp() - 1

        with pytest.raises(ExpiredSessionException):
            await session_service.get_by_token(token)

    async def test_valid_session(self, session_service: InMemorySessionService) -> None:
        token, session = await session_service.create(42)

        retrieved = await session_service.get_by_token(token)

        assert retrieved.id == session.id
        assert retrieved.identity_id == 42

    async def test_sliding_extends_session(
        self, session_service: InMemorySessionService
    ) -> None:
        token, session = await session_service.create(42)
        # Simulate a session past half its lifetime
        session.expires_at = get_current_timestamp() + 60

        retrieved = await session_service.get_by_token(token)

        lifetime_seconds = int(session_service.lifetime.total_seconds())
        assert retrieved.expires_at > get_current_timestamp() + lifetime_seconds / 2

    async def test_sliding_disabled(self) -> None:
        session_service = InMemorySessionService(sliding=False)
        token, session = await session_service.create(42)
        session.expires_at = get_current_timestamp() + 60

        retrieved = await session_service.get_by_token(token)

        assert retrieved.expires_at == session.expires_at


@pytest.mark.anyio
class TestRevoke:
    async def test_revoke(self, session_service: InMemorySessionService) -> None:
        token, session = await session_service.create(42)

        await session_service.revoke(session)

        with pytest.raises(InvalidSessionTokenException):
            await session_service.get_by_token(token)

    async def test_revoke_all(self, session_service: InMemorySessionService) -> None:
        token_a, _ = await session_service.create(42)
        token_b, _ = await session_service.create(42)
        token_other, _ = await session_service.create(43)

        await session_service.revoke_all(42)

        for token in (token_a, token_b):
            with pytest.raises(InvalidSessionTokenException):
                await session_service.get_by_token(token)
        assert (await session_service.get_by_token(token_other)).identity_id == 43


@pytest.mark.anyio
class TestExpiration:
    async def test_short_lifetime(self) -> None:
        session_service = InMemorySessionService(lifetime=datetime.timedelta(seconds=0))
        token, _ = await session_service.create(42)

        with pytest.raises(ExpiredSessionException):
            await session_service.get_by_token(token)
