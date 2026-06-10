import typing
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import BigInteger, MetaData
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from aegistry.amr import AuthenticationMethodReference
from aegistry.contrib.sqlalchemy import (
    AegistryTables,
    SQLAlchemyAuthenticationSessionService,
    SQLAlchemyOAuth2StateService,
    SQLAlchemyPasswordFactorPersistence,
    SQLAlchemySessionService,
    create_tables,
)
from aegistry.factors.password import PasswordFactor
from aegistry.session import InvalidSessionTokenException

metadata = MetaData()
tables = create_tables(metadata, identity_id_type=BigInteger())


@pytest.fixture
async def connection(
    sqlalchemy_engine: AsyncEngine,
) -> AsyncGenerator[AsyncConnection]:
    async with sqlalchemy_engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        yield conn
        await conn.run_sync(metadata.drop_all)


@pytest.fixture
def aegistry_tables() -> AegistryTables:
    return tables


class SQLAlchemyPasswordFactor(SQLAlchemyPasswordFactorPersistence, PasswordFactor):
    def __init__(self, executor: typing.Any, aegistry_tables: AegistryTables) -> None:
        self.executor = executor
        self.password_enrollments_table = aegistry_tables.password_enrollments
        super().__init__()


@pytest.mark.anyio
class TestOAuth2StateService:
    async def test_roundtrip(
        self, connection: AsyncConnection, aegistry_tables: AegistryTables
    ) -> None:
        service = SQLAlchemyOAuth2StateService(
            connection, aegistry_tables.oauth2_states, hash_secret="test-secret"
        )

        token, _ = await service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            nonce="NONCE",
            scope=["openid", "email"],
            return_to="/dashboard",
        )
        consumed = await service.consume(token)

        assert consumed.provider == "google"
        assert consumed.scope == ["openid", "email"]
        assert consumed.context == {"return_to": "/dashboard"}


@pytest.mark.anyio
class TestAuthenticationSessionService:
    async def test_roundtrip_with_amr(
        self, connection: AsyncConnection, aegistry_tables: AegistryTables
    ) -> None:
        password_factor = SQLAlchemyPasswordFactor(connection, aegistry_tables)
        service = SQLAlchemyAuthenticationSessionService(
            connection,
            aegistry_tables.authentication_sessions,
            hash_secret="test-secret",
            factors={password_factor},
        )

        token, authentication_session = await service.start(return_to="/here")
        await password_factor.enroll(42, "herminetincture")
        authentication_session = await service.advance(
            authentication_session, 42, password_factor
        )

        retrieved = await service.get_by_token(token)
        assert retrieved is not None
        assert retrieved.identity_id == 42
        assert retrieved.amr == [AuthenticationMethodReference.PWD]
        assert retrieved.used_factors == ["password"]
        assert retrieved.step == 1
        assert retrieved.context == {"return_to": "/here"}

        identity_id, amr = await service.complete(retrieved)
        assert identity_id == 42
        assert amr == [AuthenticationMethodReference.PWD]


@pytest.mark.anyio
class TestSessionService:
    async def test_roundtrip(
        self, connection: AsyncConnection, aegistry_tables: AegistryTables
    ) -> None:
        service = SQLAlchemySessionService(
            connection, aegistry_tables.sessions, hash_secret="test-secret"
        )

        token, _ = await service.create(
            42, [AuthenticationMethodReference.OAUTH2], user_agent="test"
        )
        session = await service.get_by_token(token)

        assert session.identity_id == 42
        assert session.amr == [AuthenticationMethodReference.OAUTH2]
        assert session.context == {"user_agent": "test"}

    async def test_revoke_all(
        self, connection: AsyncConnection, aegistry_tables: AegistryTables
    ) -> None:
        service = SQLAlchemySessionService(
            connection, aegistry_tables.sessions, hash_secret="test-secret"
        )

        token_a, _ = await service.create(42)
        token_b, _ = await service.create(42)

        await service.revoke_all(42)

        for token in (token_a, token_b):
            with pytest.raises(InvalidSessionTokenException):
                await service.get_by_token(token)


@pytest.mark.anyio
class TestPasswordFactorPersistence:
    async def test_enroll_and_authenticate(
        self, connection: AsyncConnection, aegistry_tables: AegistryTables
    ) -> None:
        factor = SQLAlchemyPasswordFactor(connection, aegistry_tables)

        await factor.enroll(42, "herminetincture")

        assert await factor.authenticate(42, "herminetincture") is not None
        assert await factor.authenticate(42, "wrong") is None
        assert await factor.authenticate(99, "herminetincture") is None
