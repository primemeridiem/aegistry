# plan.md — Add aegistry auth to this project

Goal: full authentication (email/password, email-OTP login + forgot password,
Google and LINE OAuth) using **aegistry** on the FastAPI backend and
**@aegistry/react** in the Next.js frontend. Sessions are opaque tokens in an
HttpOnly cookie; the Next.js app proxies `/api/auth/*` to FastAPI so the
cookie stays first-party (no CORS, no token juggling in JS).

```
Browser ── /api/auth/* ──> Next.js rewrite ──> FastAPI /auth/*  ──> DB
        <─ Set-Cookie (first-party, HttpOnly, SameSite=Lax) ─┘
```

Reference implementation: https://github.com/primemeridiem/aegistry —
`examples/server/main.py` (backend) and `examples/web/` (frontend).

---

## Part 1 — FastAPI backend

### 1.1 Install

```bash
uv add "aegistry[all]"        # = [password,sqlalchemy,fastapi]
uv add aiosqlite              # or asyncpg for Postgres
```

Environment variables (e.g. `.env`, never committed):

```env
AEGISTRY_SECRET=<long random string — HMACs all stored tokens>
DATABASE_URL=sqlite+aiosqlite:///./app.db
WEB_BASE_URL=http://localhost:3000
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
LINE_CHANNEL_ID=...
LINE_CHANNEL_SECRET=...
```

### 1.2 Tables

aegistry ships its own SQLAlchemy Core tables; you keep your own `users`
table — aegistry only ever stores your user PK as an opaque `identity_id`.

```python
from sqlalchemy import Column, Integer, MetaData, String, Table
from aegistry.contrib.sqlalchemy import create_tables

metadata = MetaData()  # or your existing metadata
tables = create_tables(metadata, identity_id_type=Integer())
# -> tables.{sessions, authentication_sessions, oauth2_states,
#            oauth2_enrollments, password_enrollments, email_otps}

users_table = Table(  # app-owned; add whatever columns you need
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(320), nullable=False, unique=True),
    Column("name", String(255), nullable=True),
    Column("picture_url", String(1024), nullable=True),
)
```

Create them with `metadata.create_all` in the lifespan (or your migrations).

### 1.3 Identity resolver

Maps verified emails ⇄ your user rows. `apply_profile` is optional — when
present it is called on every OAuth login with normalized claims so you can
store the display name / avatar.

```python
from aegistry.contrib.fastapi import OAuthProfile

class UsersIdentityResolver:
    def __init__(self, connection: AsyncConnection) -> None:
        self.connection = connection

    async def get_id_by_email(self, email: str) -> int | None:
        ...  # SELECT id FROM users WHERE email = :email

    async def get_or_create_by_email(self, email: str) -> int:
        ...  # get, else INSERT and return new id

    async def apply_profile(self, identity_id: int, profile: OAuthProfile) -> None:
        ...  # UPDATE users SET name=profile.name, picture_url=profile.picture
```

### 1.4 Factors (combine logic class + SQLAlchemy persistence mixin)

```python
from aegistry.factors.password import PasswordFactor
from aegistry.factors.email_otp import EmailOTPEnrollment, EmailOTPFactor
from aegistry.factors.oauth2.google import GoogleOAuth2Factor
from aegistry.factors.oauth2.line import LineOAuth2Factor
from aegistry.contrib.sqlalchemy import (
    SQLAlchemyPasswordFactorPersistence,
    SQLAlchemyEmailOTPFactorPersistence,
    SQLAlchemyOAuth2FactorPersistence,
)

class AppPasswordFactor(SQLAlchemyPasswordFactorPersistence, PasswordFactor):
    def __init__(self, connection):
        self.executor = connection
        self.password_enrollments_table = tables.password_enrollments
        super().__init__()

class AppEmailOTPFactor(SQLAlchemyEmailOTPFactorPersistence, EmailOTPFactor):
    def __init__(self, connection):
        self.executor = connection
        self.email_otps_table = tables.email_otps
        super().__init__(hash_secret=SECRET)

    async def get_enrollment(self, identity_id):
        # every user with an email is implicitly enrolled
        email = ...  # SELECT email FROM users WHERE id = :identity_id
        if email is None:
            return None
        return EmailOTPEnrollment(id=identity_id, identity_id=identity_id, email=email)

class AppGoogleFactor(SQLAlchemyOAuth2FactorPersistence, GoogleOAuth2Factor):
    def __init__(self, connection, state_service):
        self.executor = connection
        self.oauth2_enrollments_table = tables.oauth2_enrollments
        super().__init__(client_id=GOOGLE_CLIENT_ID,
                         client_secret=GOOGLE_CLIENT_SECRET,
                         state_service=state_service)

    async def get_email(self, callback_result):
        if callback_result.id_token is not None:
            return (await self.get_id_token_claims(callback_result.id_token))["email"]
        return (await self.get_profile(callback_result.access_token))["email"]

# LINE: identical shape with LineOAuth2Factor; email only exists in the
# id_token and only after the channel's email permission is approved in the
# LINE Developers console. See examples/server/main.py::DemoLineFactor.
```

Email delivery hook (forgot password / OTP login). Dev: print to log.
Prod: wrap Resend/SES/Postmark or SMTP — aegistry never sends mail itself.

```python
class LogEmailSender:
    async def send_code(self, email: str, code: str) -> None:
        print(f">>> login code for {email}: {code}", flush=True)
```

### 1.5 Dependencies — ⚠️ the one critical rule

**Every factor must be wired through `Depends()`**, including into the
factor-set used by the authentication session service. `advance()` checks
factor membership **by instance**; FastAPI's per-request dependency cache is
what guarantees routers and services see the same instances. Constructing a
factor twice in one request breaks login with `UnavailableFactorException`.

```python
from aegistry.contrib.sqlalchemy import (
    SQLAlchemyAuthenticationSessionService,
    SQLAlchemyOAuth2StateService,
    SQLAlchemySessionService,
)

def get_state_service(connection=Depends(get_connection)):
    return SQLAlchemyOAuth2StateService(connection, tables.oauth2_states, hash_secret=SECRET)

def get_password_factor(connection=Depends(get_connection)):
    return AppPasswordFactor(connection)

def get_email_otp_factor(connection=Depends(get_connection)):
    return AppEmailOTPFactor(connection)

def get_google_factor(connection=Depends(get_connection),
                      state_service=Depends(get_state_service)):
    return AppGoogleFactor(connection, state_service)

def get_factors(password=Depends(get_password_factor),
                email_otp=Depends(get_email_otp_factor),
                google=Depends(get_google_factor)):
    return {password, email_otp, google}

def get_authentication_session_service(connection=Depends(get_connection),
                                       factors=Depends(get_factors)):
    return SQLAlchemyAuthenticationSessionService(
        connection, tables.authentication_sessions,
        hash_secret=SECRET, factors=factors)

def get_session_service(connection=Depends(get_connection)):
    return SQLAlchemySessionService(connection, tables.sessions, hash_secret=SECRET)

def get_identity_resolver(connection=Depends(get_connection)):
    return UsersIdentityResolver(connection)

def get_email_sender():
    return LogEmailSender()
```

### 1.6 Config + routers

```python
from aegistry.contrib.fastapi import (
    AuthConfig, get_password_router, get_session_router,
    get_email_otp_router, get_oauth2_login_router,
)

CALLBACK_BASE_URL = f"{WEB_BASE_URL}/api/auth"  # OAuth callbacks go through the proxy

config = AuthConfig(
    cookie_secure=False,            # True in production (HTTPS)
    success_redirect_url="/",       # after OAuth login
    mfa_redirect_url="/login?mfa=1",
    error_redirect_url="/login",
)

app.include_router(get_password_router(
    factor_dependency=get_password_factor,
    authentication_session_service_dependency=get_authentication_session_service,
    session_service_dependency=get_session_service,
    identity_resolver_dependency=get_identity_resolver,
    config=config), prefix="/auth")

app.include_router(get_session_router(
    session_service_dependency=get_session_service,
    config=config), prefix="/auth")

app.include_router(get_email_otp_router(
    factor_dependency=get_email_otp_factor,
    authentication_session_service_dependency=get_authentication_session_service,
    session_service_dependency=get_session_service,
    identity_resolver_dependency=get_identity_resolver,
    email_sender_dependency=get_email_sender,
    config=config), prefix="/auth")

app.include_router(get_oauth2_login_router(
    identifier="google",
    factor_dependency=get_google_factor,
    authentication_session_service_dependency=get_authentication_session_service,
    session_service_dependency=get_session_service,
    identity_resolver_dependency=get_identity_resolver,
    config=config,
    scope=["openid", "email", "profile"],
    callback_base_url=CALLBACK_BASE_URL), prefix="/auth")
# repeat with identifier="line" for LINE
```

Routes this exposes under `/auth`:

| Route | Purpose |
|---|---|
| `POST /auth/register`, `POST /auth/login` | email + password |
| `POST /auth/change-password` | also "set first password"; current password not needed when session AMR includes `email` (OTP recovery) |
| `POST /auth/email-otp/request`, `POST /auth/email-otp/verify` | passwordless login & forgot-password |
| `GET /auth/{provider}/authorize`, `GET /auth/{provider}/callback` | OAuth |
| `GET /auth/session`, `POST /auth/logout` | session info / sign out |

### 1.7 Protecting your own endpoints

```python
from aegistry.contrib.fastapi import build_current_session

current_session = build_current_session(get_session_service, config, auto_error=True)

@app.get("/auth/me")
async def me(session = Depends(current_session)):
    # session.identity_id is your users.id; join your user row here
    ...
```

### 1.8 Provider console setup

- **Google** (console.cloud.google.com → Credentials → OAuth client, type Web):
  authorized redirect URI `http://localhost:3000/api/auth/google/callback`
  (plus the production equivalent).
- **LINE** (developers.line.biz → LINE Login channel): same callback pattern
  with `line`; email requires applying for the **email permission** under the
  channel's Basic settings. aegistry already handles LINE's quirks
  (HS256 id_tokens via the verify endpoint, `client_secret_post`).

---

## Part 2 — Next.js frontend

### 2.1 Install + proxy

```bash
pnpm add @aegistry/react        # pulls in @aegistry/client
```

`next.config.mjs` — the piece that makes cookies first-party:

```js
const nextConfig = {
  async rewrites() {
    return [{
      source: "/api/auth/:path*",
      destination: `${process.env.API_URL ?? "http://127.0.0.1:8000"}/auth/:path*`,
    }];
  },
};
export default nextConfig;
```

### 2.2 Client singleton

```ts
// lib/auth.ts
import { createAuthClient } from "@aegistry/react";

export const auth = createAuthClient();      // baseURL defaults to /api/auth
export const { useSession } = auth;
```

### 2.3 Use it

```tsx
"use client";
import { auth, useSession } from "@/lib/auth";

// sign in / up
await auth.signIn.password({ email, password });
await auth.signUp.password({ email, password });

// passwordless / forgot password
await auth.signIn.emailOtp.request({ email });
await auth.signIn.emailOtp.verify({ email, code });

// OAuth — full-page redirect
auth.signIn.oauth("google");   // or "line"

// session-aware component
const { data: session, isPending } = useSession();

// change/set password (currentPassword optional after OTP recovery
// or when setting a first password on an OAuth-only account)
await auth.changePassword({ newPassword, currentPassword });

await auth.signOut();
```

### 2.4 Server Components / route handlers

```ts
// lib/session.ts
import { getServerSession } from "@aegistry/client";
import { cookies } from "next/headers";

const API_URL = process.env.API_URL ?? "http://127.0.0.1:8000";

export async function getSession() {
  return getServerSession({
    baseURL: `${API_URL}/auth`,
    cookie: (await cookies()).toString(),
  });
}
```

```tsx
// app/page.tsx
const session = await getSession();
if (!session) redirect("/login");
// session: { identity_id, amr: string[], expires_at }
```

Forgot-password UX: request OTP → verify → user is signed in with
`amr: ["email"]` → show the change-password form without the
current-password field (`session.amr.includes("email")`).

---

## Part 3 — Verify

1. `uvicorn app.main:app --port 8000` + `next dev` (port 3000).
2. Register → cookie set → `GET /api/auth/session` returns identity + `amr: ["pwd"]`.
3. OTP flow: request (code in server log) → verify → signed in with `amr: ["email"]` → change password without current password.
4. Google/LINE: button → consent → lands on `success_redirect_url` signed in; name/avatar stored via `apply_profile`.
5. Logout clears the cookie; `GET /api/auth/session` → null.

## Production checklist

- [ ] `cookie_secure=True` (HTTPS) and a strong, secret `AEGISTRY_SECRET`
- [ ] Real `EmailOTPSender` (Resend / SES / Postmark / SMTP)
- [ ] Rate-limit `POST /auth/email-otp/request` (per IP and per email)
- [ ] Postgres (`asyncpg`) instead of SQLite; manage tables via migrations
- [ ] Production redirect URIs registered in Google/LINE consoles
- [ ] `WEB_BASE_URL` set to the real origin (drives OAuth `callback_base_url`)
