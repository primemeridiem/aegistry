# aegistry demo

End-to-end example: FastAPI + SQLite backend (`server/`) and a Next.js app
(`web/`) using `@aegistry/react`, connected through a same-origin rewrite
proxy.

## Run it

```bash
# 1. Backend (repository root) — http://127.0.0.1:8000
uv sync
cp .env.example .env   # fill in provider credentials (optional)
uv run uvicorn examples.server.main:app --reload --port 8000 --env-file .env

# 2. Frontend — http://localhost:3000
pnpm install && pnpm build   # builds @aegistry/client and @aegistry/react
cd examples/web
pnpm dev
```

Open http://localhost:3000 — you'll be redirected to `/login`. Create an
account with email/password; you land on a server-rendered page showing the
session. Sign out and sign back in.

Email/password works with zero configuration. The SQLite database is
`./demo.db` (created on startup; delete it to reset).

## Enabling Google Sign-In

1. Create OAuth credentials at https://console.cloud.google.com/apis/credentials
   (type: Web application).
2. Add the authorized redirect URI:
   `http://localhost:3000/api/auth/google/callback`
3. Put the credentials in `.env` (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`)
   and restart the backend.

The login page detects configured providers via `GET /auth/providers` and
shows the button automatically.

## Enabling LINE Login

1. Create a LINE Login channel at https://developers.line.biz/console/
2. Register the callback URL: `http://localhost:3000/api/auth/line/callback`
3. Apply for the **email** permission (OpenID Connect → email) on the
   channel — without it LINE never returns an email and login is rejected.
4. Put the credentials in `.env` (`LINE_CHANNEL_ID`, `LINE_CHANNEL_SECRET`)
   and restart the backend.

## How the pieces fit

```
Browser ── localhost:3000 (Next.js)
   │            │  rewrites /api/auth/* ──► 127.0.0.1:8000/auth/*  (FastAPI)
   │            │
   │            └─ Server Components call FastAPI directly,
   │               forwarding the request cookies (lib/session.ts)
   │
   └─ session cookie is first-party for localhost:3000 (SameSite=Lax)
```

- OAuth redirect URIs point at the *proxy* path
  (`callback_base_url` in `server/main.py`), so the provider sends the user
  back through the Next.js origin where the state cookie lives.
- The server redirects with relative URLs (`success_redirect_url="/"`),
  which resolve against the web app's origin because the callback arrives
  through the proxy.
