"""SQLAlchemy Core table definitions for aegistry stores.

These tables use ``Integer`` autoincrement primary keys and a configurable
identity ID type. Applications with different conventions (e.g. UUID primary
keys) can define their own tables — the stores in
``aegistry.contrib.sqlalchemy.stores`` accept any tables with matching
column names.
"""

import dataclasses
import typing

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
)
from sqlalchemy.types import TypeEngine


@dataclasses.dataclass
class AegistryTables:
    oauth2_states: Table
    oauth2_enrollments: Table
    authentication_sessions: Table
    sessions: Table
    password_enrollments: Table
    email_otps: Table


def create_tables(
    metadata: MetaData,
    *,
    prefix: str = "aegistry_",
    identity_id_type: TypeEngine[typing.Any]
    | type[TypeEngine[typing.Any]]
    | None = None,
) -> AegistryTables:
    """Define the aegistry tables on a metadata object.

    Args:
        metadata: The SQLAlchemy MetaData to attach the tables to.
        prefix: Prefix for all table names.
        identity_id_type: Column type of identity (user) IDs, matching the
            application's user table primary key type. Defaults to String(255).

    Returns:
        An AegistryTables instance holding the Table objects.
    """
    if identity_id_type is None:
        identity_id_type = String(255)
    oauth2_states = Table(
        f"{prefix}oauth2_states",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("state_hash", String(64), nullable=False, unique=True),
        Column("provider", String(64), nullable=False),
        Column("code_verifier", String(128), nullable=True),
        Column("nonce", String(128), nullable=True),
        Column("redirect_uri", String(512), nullable=False),
        Column("identity_id", identity_id_type, nullable=True),
        Column("scope", JSON, nullable=True),
        Column("expires_at", BigInteger, nullable=False),
        Column("context", JSON, nullable=True),
    )

    oauth2_enrollments = Table(
        f"{prefix}oauth2_enrollments",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("identity_id", identity_id_type, nullable=False),
        Column("provider", String(64), nullable=False),
        Column("account_id", String(128), nullable=False),
        Column("access_token", String(1024), nullable=False),
        Column("expires_at", BigInteger, nullable=True),
        Column("refresh_token", String(1024), nullable=True),
        Column("refresh_token_expires_at", BigInteger, nullable=True),
        Column("scope", JSON, nullable=True),
        Column("id_token", String(4096), nullable=True),
        UniqueConstraint("provider", "account_id", name=f"{prefix}provider_account"),
    )

    authentication_sessions = Table(
        f"{prefix}authentication_sessions",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("token_hash", String(64), nullable=False, unique=True),
        Column("expires_at", BigInteger, nullable=False),
        Column("identity_id", identity_id_type, nullable=True),
        Column("step", Integer, nullable=False, default=0),
        Column("amr", JSON, nullable=False, default=list),
        Column("used_factors", JSON, nullable=False, default=list),
        Column("context", JSON, nullable=True),
    )

    sessions = Table(
        f"{prefix}sessions",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("token_hash", String(64), nullable=False, unique=True),
        Column("identity_id", identity_id_type, nullable=False),
        Column("expires_at", BigInteger, nullable=False),
        Column("amr", JSON, nullable=False, default=list),
        Column("context", JSON, nullable=True),
    )

    password_enrollments = Table(
        f"{prefix}password_enrollments",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("identity_id", identity_id_type, nullable=False, unique=True),
        Column("hash", String(512), nullable=False),
    )

    email_otps = Table(
        f"{prefix}email_otps",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("identity_id", identity_id_type, nullable=True),
        Column("email", String(320), nullable=False),
        Column("code_hash", String(64), nullable=False),
        Column("expires_at", BigInteger, nullable=False),
        Column("authentication_session_id", Integer, nullable=False),
    )

    return AegistryTables(
        oauth2_states=oauth2_states,
        oauth2_enrollments=oauth2_enrollments,
        authentication_sessions=authentication_sessions,
        sessions=sessions,
        password_enrollments=password_enrollments,
        email_otps=email_otps,
    )
