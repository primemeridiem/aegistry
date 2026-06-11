"""Demo aegistry server: SQLite + email/password, Google, and LINE login.

Run from the repository root::

    uv run uvicorn examples.server.main:app --reload --port 8000

Pair it with the Next.js app in ``examples/web``, which proxies
``/api/auth/*`` to this server's ``/auth/*`` routes so session cookies stay
first-party.

Google and LINE routers are only mounted when their credentials are set:

    GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
    LINE_CHANNEL_ID  / LINE_CHANNEL_SECRET

Register the redirect URI ``http://localhost:3000/api/auth/{provider}/callback``
in the provider console.
"""

import contextlib
import os
import typing
from collections.abc import AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import Column, Integer, MetaData, String, Table, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from aegistry.contrib.fastapi import (
    AuthConfig,
    OAuthProfile,
    build_current_session,
    get_email_otp_router,
    get_oauth2_login_router,
    get_password_router,
    get_session_router,
)
from aegistry.contrib.sqlalchemy import (
    SQLAlchemyAuthenticationSessionService,
    SQLAlchemyEmailOTPFactorPersistence,
    SQLAlchemyOAuth2FactorPersistence,
    SQLAlchemyOAuth2StateService,
    SQLAlchemyPasswordFactorPersistence,
    SQLAlchemySessionService,
    create_tables,
)
from aegistry.factors.base import FactorBase
from aegistry.factors.email_otp import EmailOTPEnrollment, EmailOTPFactor
from aegistry.factors.oauth2.google import GoogleOAuth2Factor
from aegistry.factors.oauth2.line import LineOAuth2Factor
from aegistry.factors.oauth2.state import OAuth2StateService
from aegistry.factors.password import PasswordFactor
from aegistry.session import Session

SECRET = os.environ.get("AEGISTRY_SECRET", "demo-secret-do-not-use-in-production")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./demo.db")
# Public origin of the Next.js app; auth routes are reached through its proxy.
WEB_BASE_URL = os.environ.get("WEB_BASE_URL", "http://localhost:3000")
CALLBACK_BASE_URL = f"{WEB_BASE_URL}/api/auth"

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
LINE_CHANNEL_ID = os.environ.get("LINE_CHANNEL_ID")
LINE_CHANNEL_SECRET = os.environ.get("LINE_CHANNEL_SECRET")

metadata = MetaData()
tables = create_tables(metadata, identity_id_type=Integer())
users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(320), nullable=False, unique=True),
    Column("name", String(255), nullable=True),
    Column("picture_url", String(1024), nullable=True),
)

engine = create_async_engine(DATABASE_URL)

config = AuthConfig(
    cookie_secure=False,  # local HTTP demo only
    # Relative URLs: OAuth callbacks arrive through the Next.js proxy, so the
    # browser is already on the web app's origin.
    success_redirect_url="/",
    mfa_redirect_url="/login?mfa=1",
    error_redirect_url="/login",
)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    yield
    await engine.dispose()


async def get_connection() -> AsyncGenerator[AsyncConnection]:
    async with engine.begin() as connection:
        yield connection


# --- Identity resolver -----------------------------------------------------


class UsersIdentityResolver:
    def __init__(self, connection: AsyncConnection) -> None:
        self.connection = connection

    async def get_id_by_email(self, email: str) -> int | None:
        result = await self.connection.execute(
            select(users_table.c.id).where(users_table.c.email == email)
        )
        return result.scalar_one_or_none()

    async def get_or_create_by_email(self, email: str) -> int:
        existing = await self.get_id_by_email(email)
        if existing is not None:
            return existing
        result = await self.connection.execute(
            insert(users_table).values(email=email).returning(users_table.c.id)
        )
        return result.scalar_one()

    async def apply_profile(self, identity_id: int, profile: OAuthProfile) -> None:
        values: dict[str, typing.Any] = {}
        if profile.name is not None:
            values["name"] = profile.name
        if profile.picture is not None:
            values["picture_url"] = profile.picture
        if values:
            await self.connection.execute(
                update(users_table)
                .where(users_table.c.id == identity_id)
                .values(**values)
            )


def get_identity_resolver(
    connection: AsyncConnection = Depends(get_connection),
) -> UsersIdentityResolver:
    return UsersIdentityResolver(connection)


# --- Factors ---------------------------------------------------------------


class DemoPasswordFactor(SQLAlchemyPasswordFactorPersistence, PasswordFactor):
    def __init__(self, connection: AsyncConnection) -> None:
        self.executor = connection
        self.password_enrollments_table = tables.password_enrollments
        super().__init__()


class DemoEmailOTPFactor(SQLAlchemyEmailOTPFactorPersistence, EmailOTPFactor):
    def __init__(self, connection: AsyncConnection) -> None:
        self.executor = connection
        self.email_otps_table = tables.email_otps
        super().__init__(hash_secret=SECRET)

    async def get_enrollment(
        self, identity_id: typing.Any
    ) -> EmailOTPEnrollment | None:
        result = await self.executor.execute(
            select(users_table.c.email).where(users_table.c.id == identity_id)
        )
        email = result.scalar_one_or_none()
        if email is None:
            return None
        return EmailOTPEnrollment(id=identity_id, identity_id=identity_id, email=email)


class LogEmailSender:
    """Demo email "delivery": prints the code to the server log."""

    async def send_code(self, email: str, code: str) -> None:
        print(
            "\n"
            "+----------------------------------------------------+\n"
            f"|  LOGIN CODE for {email:<34} |\n"
            f"|  >>> {code:<45} |\n"
            "+----------------------------------------------------+\n",
            flush=True,
        )


class DemoGoogleFactor(SQLAlchemyOAuth2FactorPersistence, GoogleOAuth2Factor):
    def __init__(
        self, connection: AsyncConnection, state_service: OAuth2StateService
    ) -> None:
        assert GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET
        self.executor = connection
        self.oauth2_enrollments_table = tables.oauth2_enrollments
        super().__init__(
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            state_service=state_service,
        )

    async def get_email(self, callback_result: typing.Any) -> str:
        if callback_result.id_token is not None:
            claims = await self.get_id_token_claims(callback_result.id_token)
            return claims["email"]
        profile = await self.get_profile(callback_result.access_token)
        return profile["email"]


class DemoLineFactor(SQLAlchemyOAuth2FactorPersistence, LineOAuth2Factor):
    def __init__(
        self, connection: AsyncConnection, state_service: OAuth2StateService
    ) -> None:
        assert LINE_CHANNEL_ID and LINE_CHANNEL_SECRET
        self.executor = connection
        self.oauth2_enrollments_table = tables.oauth2_enrollments
        super().__init__(
            client_id=LINE_CHANNEL_ID,
            client_secret=LINE_CHANNEL_SECRET,
            state_service=state_service,
        )

    async def get_email(self, callback_result: typing.Any) -> str:
        # LINE only exposes the email in the id_token, and only when the
        # channel has been granted the email permission.
        if callback_result.id_token is not None:
            claims = await self.get_id_token_claims(callback_result.id_token)
            if "email" in claims:
                return claims["email"]
        raise RuntimeError(
            "LINE did not return an email; apply for the email scope "
            "permission in the LINE Developers console"
        )


# --- Service dependencies ---------------------------------------------------


def get_state_service(
    connection: AsyncConnection = Depends(get_connection),
) -> SQLAlchemyOAuth2StateService:
    return SQLAlchemyOAuth2StateService(
        connection, tables.oauth2_states, hash_secret=SECRET
    )


def get_password_factor(
    connection: AsyncConnection = Depends(get_connection),
) -> DemoPasswordFactor:
    return DemoPasswordFactor(connection)


def get_google_factor(
    connection: AsyncConnection = Depends(get_connection),
    state_service: SQLAlchemyOAuth2StateService = Depends(get_state_service),
) -> DemoGoogleFactor | None:
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        return None
    return DemoGoogleFactor(connection, state_service)


def get_line_factor(
    connection: AsyncConnection = Depends(get_connection),
    state_service: SQLAlchemyOAuth2StateService = Depends(get_state_service),
) -> DemoLineFactor | None:
    if not (LINE_CHANNEL_ID and LINE_CHANNEL_SECRET):
        return None
    return DemoLineFactor(connection, state_service)


def get_email_otp_factor(
    connection: AsyncConnection = Depends(get_connection),
) -> DemoEmailOTPFactor:
    return DemoEmailOTPFactor(connection)


def get_email_sender() -> LogEmailSender:
    return LogEmailSender()


def get_factors(
    # The session service must hold the SAME factor instances the routers
    # receive (advance() checks membership by instance). FastAPI's
    # per-request dependency cache guarantees that when factors are wired
    # through Depends() like this.
    password_factor: DemoPasswordFactor = Depends(get_password_factor),
    email_otp_factor: DemoEmailOTPFactor = Depends(get_email_otp_factor),
    google_factor: DemoGoogleFactor | None = Depends(get_google_factor),
    line_factor: DemoLineFactor | None = Depends(get_line_factor),
) -> set[FactorBase[typing.Any]]:
    factors: set[FactorBase[typing.Any]] = {password_factor, email_otp_factor}
    if google_factor is not None:
        factors.add(google_factor)
    if line_factor is not None:
        factors.add(line_factor)
    return factors


def get_authentication_session_service(
    connection: AsyncConnection = Depends(get_connection),
    factors: set[FactorBase[typing.Any]] = Depends(get_factors),
) -> SQLAlchemyAuthenticationSessionService:
    return SQLAlchemyAuthenticationSessionService(
        connection,
        tables.authentication_sessions,
        hash_secret=SECRET,
        factors=factors,
    )


def get_session_service(
    connection: AsyncConnection = Depends(get_connection),
) -> SQLAlchemySessionService:
    return SQLAlchemySessionService(connection, tables.sessions, hash_secret=SECRET)


# --- App -------------------------------------------------------------------

app = FastAPI(title="aegistry demo", lifespan=lifespan)

app.include_router(
    get_password_router(
        factor_dependency=get_password_factor,
        authentication_session_service_dependency=get_authentication_session_service,
        session_service_dependency=get_session_service,
        identity_resolver_dependency=get_identity_resolver,
        config=config,
    ),
    prefix="/auth",
)
app.include_router(
    get_session_router(
        session_service_dependency=get_session_service,
        config=config,
    ),
    prefix="/auth",
)
app.include_router(
    get_email_otp_router(
        factor_dependency=get_email_otp_factor,
        authentication_session_service_dependency=get_authentication_session_service,
        session_service_dependency=get_session_service,
        identity_resolver_dependency=get_identity_resolver,
        email_sender_dependency=get_email_sender,
        config=config,
    ),
    prefix="/auth",
)

enabled_providers: list[str] = []
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    enabled_providers.append("google")
    app.include_router(
        get_oauth2_login_router(
            identifier="google",
            factor_dependency=get_google_factor,
            authentication_session_service_dependency=(
                get_authentication_session_service
            ),
            session_service_dependency=get_session_service,
            identity_resolver_dependency=get_identity_resolver,
            config=config,
            scope=["openid", "email", "profile"],
            callback_base_url=CALLBACK_BASE_URL,
        ),
        prefix="/auth",
    )
if LINE_CHANNEL_ID and LINE_CHANNEL_SECRET:
    enabled_providers.append("line")
    app.include_router(
        get_oauth2_login_router(
            identifier="line",
            factor_dependency=get_line_factor,
            authentication_session_service_dependency=(
                get_authentication_session_service
            ),
            session_service_dependency=get_session_service,
            identity_resolver_dependency=get_identity_resolver,
            config=config,
            scope=["openid", "profile", "email"],
            callback_base_url=CALLBACK_BASE_URL,
        ),
        prefix="/auth",
    )


@app.get("/auth/providers")
async def providers() -> dict[str, list[str]]:
    """Which OAuth providers are configured — the demo UI adapts to this."""
    return {"providers": enabled_providers}


class Me(BaseModel):
    id: int
    email: str
    name: str | None
    picture_url: str | None
    has_password: bool


_current_session = build_current_session(get_session_service, config, auto_error=True)


@app.get("/auth/me", response_model=Me)
async def me(
    session: Session | None = Depends(_current_session),
    connection: AsyncConnection = Depends(get_connection),
) -> Me:
    """App-level user endpoint: session identity joined to the users table."""
    assert session is not None
    result = await connection.execute(
        select(users_table).where(users_table.c.id == session.identity_id)
    )
    row = result.fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    enrollment_result = await connection.execute(
        select(tables.password_enrollments.c.id).where(
            tables.password_enrollments.c.identity_id == session.identity_id
        )
    )
    has_password = enrollment_result.fetchone() is not None
    return Me(**row._asdict(), has_password=has_password)
