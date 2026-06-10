"""SQLAlchemy persistence for aegistry. Requires ``aegistry[sqlalchemy]``."""

from aegistry.contrib.sqlalchemy.stores import (
    SQLAlchemyAuthenticationSessionService,
    SQLAlchemyExecutor,
    SQLAlchemyOAuth2FactorPersistence,
    SQLAlchemyOAuth2StateService,
    SQLAlchemyPasswordFactorPersistence,
    SQLAlchemySessionService,
)
from aegistry.contrib.sqlalchemy.tables import AegistryTables, create_tables

__all__ = [
    "AegistryTables",
    "SQLAlchemyAuthenticationSessionService",
    "SQLAlchemyExecutor",
    "SQLAlchemyOAuth2FactorPersistence",
    "SQLAlchemyOAuth2StateService",
    "SQLAlchemyPasswordFactorPersistence",
    "SQLAlchemySessionService",
    "create_tables",
]
