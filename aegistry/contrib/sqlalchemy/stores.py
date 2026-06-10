"""Concrete aegistry services and factor persistence backed by SQLAlchemy.

All classes accept any object with an async ``execute()`` method — both
``AsyncConnection`` (Core) and ``AsyncSession`` (ORM) work. Transaction
management (commit/rollback) is left to the application.
"""

import datetime
import typing

from sqlalchemy import Table, delete, insert, select, update

from aegistry.amr import AuthenticationMethodReference
from aegistry.authentication_session import (
    AuthenticationSession,
    AuthenticationSessionService,
)
from aegistry.crypto import TokenHash
from aegistry.factors import FactorBase
from aegistry.factors.oauth2.base import OAuth2Enrollment
from aegistry.factors.oauth2.state import OAuth2State, OAuth2StateService
from aegistry.factors.password import PasswordEnrollment
from aegistry.session import Session, SessionService


class SQLAlchemyExecutor(typing.Protocol):
    """Structural type satisfied by AsyncConnection and AsyncSession."""

    async def execute(self, statement: typing.Any) -> typing.Any: ...


class SQLAlchemyOAuth2StateService(OAuth2StateService):
    """OAuth2 state storage backed by SQLAlchemy."""

    def __init__(
        self,
        executor: SQLAlchemyExecutor,
        table: Table,
        *,
        hash_secret: str,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=10),
        token_prefix: str = "aegistry_oauth2_",
    ) -> None:
        self.executor = executor
        self.table = table
        super().__init__(
            hash_secret=hash_secret, lifetime=lifetime, token_prefix=token_prefix
        )

    async def get_by_state_hash(self, state_hash: TokenHash) -> OAuth2State | None:
        result = await self.executor.execute(
            select(self.table).where(self.table.c.state_hash == state_hash)
        )
        row = result.fetchone()
        if row is None:
            return None
        return OAuth2State(**row._asdict())

    async def insert(self, oauth2_state: OAuth2State) -> typing.Any:
        values = dict(oauth2_state.__dict__)
        values.pop("id")
        result = await self.executor.execute(
            insert(self.table).values(**values).returning(self.table.c.id)
        )
        return result.scalar_one()

    async def delete(self, oauth2_state: OAuth2State) -> None:
        await self.executor.execute(
            delete(self.table).where(self.table.c.id == oauth2_state.id)
        )


class SQLAlchemyAuthenticationSessionService(AuthenticationSessionService):
    """Pre-login authentication session storage backed by SQLAlchemy."""

    def __init__(
        self,
        executor: SQLAlchemyExecutor,
        table: Table,
        *,
        hash_secret: str,
        factors: set[FactorBase[typing.Any]],
        token_prefix: str = "aegistry_as_",
        lifetime: datetime.timedelta = datetime.timedelta(minutes=15),
    ) -> None:
        self.executor = executor
        self.table = table
        super().__init__(
            hash_secret=hash_secret,
            factors=factors,
            token_prefix=token_prefix,
            lifetime=lifetime,
        )

    def _to_values(
        self, authentication_session: AuthenticationSession
    ) -> dict[str, typing.Any]:
        return {
            "token_hash": authentication_session.token_hash,
            "expires_at": authentication_session.expires_at,
            "identity_id": authentication_session.identity_id,
            "step": authentication_session.step,
            "amr": [str(amr) for amr in authentication_session.amr],
            "used_factors": authentication_session.used_factors,
            "context": authentication_session.context,
        }

    def _from_row(self, row: typing.Any) -> AuthenticationSession:
        data = row._asdict()
        data["amr"] = [AuthenticationMethodReference(amr) for amr in data["amr"]]
        return AuthenticationSession(**data)

    async def get_by_token_hash(self, token_hash: str) -> AuthenticationSession | None:
        result = await self.executor.execute(
            select(self.table).where(self.table.c.token_hash == token_hash)
        )
        row = result.fetchone()
        if row is None:
            return None
        return self._from_row(row)

    async def insert(self, authentication_session: AuthenticationSession) -> typing.Any:
        result = await self.executor.execute(
            insert(self.table)
            .values(**self._to_values(authentication_session))
            .returning(self.table.c.id)
        )
        return result.scalar_one()

    async def update(self, authentication_session: AuthenticationSession) -> None:
        await self.executor.execute(
            update(self.table)
            .where(self.table.c.id == authentication_session.id)
            .values(**self._to_values(authentication_session))
        )

    async def delete(self, authentication_session: AuthenticationSession) -> None:
        await self.executor.execute(
            delete(self.table).where(self.table.c.id == authentication_session.id)
        )


class SQLAlchemySessionService(SessionService):
    """Post-login session storage backed by SQLAlchemy."""

    def __init__(
        self,
        executor: SQLAlchemyExecutor,
        table: Table,
        *,
        hash_secret: str,
        token_prefix: str = "aegistry_s_",
        lifetime: datetime.timedelta = datetime.timedelta(days=30),
        sliding: bool = True,
    ) -> None:
        self.executor = executor
        self.table = table
        super().__init__(
            hash_secret=hash_secret,
            token_prefix=token_prefix,
            lifetime=lifetime,
            sliding=sliding,
        )

    def _to_values(self, session: Session) -> dict[str, typing.Any]:
        return {
            "token_hash": session.token_hash,
            "identity_id": session.identity_id,
            "expires_at": session.expires_at,
            "amr": [str(amr) for amr in session.amr],
            "context": session.context,
        }

    def _from_row(self, row: typing.Any) -> Session:
        data = row._asdict()
        data["amr"] = [AuthenticationMethodReference(amr) for amr in data["amr"]]
        return Session(**data)

    async def get_by_token_hash(self, token_hash: TokenHash) -> Session | None:
        result = await self.executor.execute(
            select(self.table).where(self.table.c.token_hash == token_hash)
        )
        row = result.fetchone()
        if row is None:
            return None
        return self._from_row(row)

    async def insert(self, session: Session) -> typing.Any:
        result = await self.executor.execute(
            insert(self.table)
            .values(**self._to_values(session))
            .returning(self.table.c.id)
        )
        return result.scalar_one()

    async def update(self, session: Session) -> None:
        await self.executor.execute(
            update(self.table)
            .where(self.table.c.id == session.id)
            .values(**self._to_values(session))
        )

    async def delete(self, session: Session) -> None:
        await self.executor.execute(
            delete(self.table).where(self.table.c.id == session.id)
        )

    async def delete_by_identity_id(self, identity_id: typing.Any) -> None:
        await self.executor.execute(
            delete(self.table).where(self.table.c.identity_id == identity_id)
        )


class SQLAlchemyOAuth2FactorPersistence:
    """Mixin implementing OAuth2 factor persistence against SQLAlchemy.

    Mix into an OAuth2 factor class and set ``executor`` and
    ``oauth2_enrollments_table`` in the constructor::

        class GoogleFactor(SQLAlchemyOAuth2FactorPersistence, GoogleOAuth2Factor):
            def __init__(self, executor, tables, **kwargs):
                self.executor = executor
                self.oauth2_enrollments_table = tables.oauth2_enrollments
                super().__init__(**kwargs)
    """

    executor: SQLAlchemyExecutor
    oauth2_enrollments_table: Table

    async def get_enrollment(self, identity_id: typing.Any) -> OAuth2Enrollment | None:
        table = self.oauth2_enrollments_table
        result = await self.executor.execute(
            select(table).where(
                table.c.identity_id == identity_id,
                table.c.provider == typing.cast(typing.Any, self).identifier,
            )
        )
        row = result.fetchone()
        if row is None:
            return None
        return OAuth2Enrollment(**row._asdict())

    async def get_enrollment_by_provider_and_account(
        self, provider: str, account_id: str
    ) -> OAuth2Enrollment | None:
        table = self.oauth2_enrollments_table
        result = await self.executor.execute(
            select(table).where(
                table.c.provider == provider,
                table.c.account_id == account_id,
            )
        )
        row = result.fetchone()
        if row is None:
            return None
        return OAuth2Enrollment(**row._asdict())

    async def insert(self, enrollment: OAuth2Enrollment) -> typing.Any:
        table = self.oauth2_enrollments_table
        values = dict(enrollment.__dict__)
        values.pop("id")
        result = await self.executor.execute(
            insert(table).values(**values).returning(table.c.id)
        )
        return result.scalar_one()

    async def update(self, enrollment: OAuth2Enrollment) -> None:
        table = self.oauth2_enrollments_table
        values = dict(enrollment.__dict__)
        values.pop("id")
        await self.executor.execute(
            update(table).where(table.c.id == enrollment.id).values(**values)
        )


class SQLAlchemyPasswordFactorPersistence:
    """Mixin implementing password factor persistence against SQLAlchemy.

    Mix into ``PasswordFactor`` and set ``executor`` and
    ``password_enrollments_table`` in the constructor.
    """

    executor: SQLAlchemyExecutor
    password_enrollments_table: Table

    async def get_enrollment(
        self, identity_id: typing.Any
    ) -> PasswordEnrollment | None:
        table = self.password_enrollments_table
        result = await self.executor.execute(
            select(table).where(table.c.identity_id == identity_id)
        )
        row = result.fetchone()
        if row is None:
            return None
        return PasswordEnrollment(**row._asdict())

    async def insert(self, enrollment: PasswordEnrollment) -> typing.Any:
        table = self.password_enrollments_table
        result = await self.executor.execute(
            insert(table)
            .values(identity_id=enrollment.identity_id, hash=enrollment.hash)
            .returning(table.c.id)
        )
        return result.scalar_one()

    async def update(self, enrollment: PasswordEnrollment) -> None:
        table = self.password_enrollments_table
        await self.executor.execute(
            update(table)
            .where(table.c.id == enrollment.id)
            .values(hash=enrollment.hash)
        )

    async def delete(self, enrollment: PasswordEnrollment) -> None:
        table = self.password_enrollments_table
        await self.executor.execute(delete(table).where(table.c.id == enrollment.id))
