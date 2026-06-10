# Aegistry

<p align="center">
    <em>Batteries-included authentication for FastAPI</em>
</p>

Aegistry is an authentication toolkit for Python with first-class FastAPI
integration: Email/Password, Email OTP, Google Sign-In, LINE Login, MFA
(TOTP, backup codes), and session management — on Python 3.12+.

> [!NOTE]
> Aegistry's core is a friendly fork of [reauth](https://github.com/frankie567/reauth)
> 0.1.8 (MIT, © 2026 François Voron), backported to Python 3.12. Aegistry adds the
> integration layers reauth doesn't ship yet: password & LINE factors, post-login
> session management, SQLAlchemy stores, and ready-made FastAPI routers. We aim to
> stay architecturally compatible with reauth and upstream what makes sense.

## Architecture

```
aegistry/
├── crypto.py                  # opaque tokens + HMAC-SHA256 hash pairs
├── amr.py                     # RFC 8176 Authentication Method References
├── authentication_session.py  # pre-login MFA state machine (steps, AMR)
├── session.py                 # post-login sessions (sliding expiration)
├── factors/
│   ├── password.py            # argon2id via pwdlib          [aegistry]
│   ├── email_otp.py           # one-time codes by email
│   ├── totp.py / hotp.py / backup_codes.py
│   └── oauth2/
│       ├── base.py            # OAuth2 authorization code + PKCE
│       ├── oidc.py            # discovery, JWKS, id_token validation
│       ├── google.py / github.py / apple.py
│       └── line.py            # LINE Login v2.1               [aegistry]
└── contrib/
    ├── sqlalchemy/            # ready-made async stores        [aegistry]
    └── fastapi/               # routers, dependencies, cookies [aegistry]
```

Design principles (inherited from reauth, shared with Better Auth):

- **Framework-agnostic core.** Factors and services are plain async Python with
  abstract persistence methods. `contrib/` packages depend on the core — never
  the reverse.
- **Tokens are opaque, prefixed, and stored hashed.** Only HMAC-SHA256 hashes
  hit the database.
- **MFA by construction.** Login is an *authentication session* that factors
  advance step by step; it completes only when no required factor remains.
- **PKCE + state + nonce** on every OAuth2/OIDC flow.

## Installation

```bash
pip install "aegistry[all]"            # everything
pip install "aegistry[fastapi,sqlalchemy,password]"
```

## Quickstart (FastAPI + SQLAlchemy)

```python
from aegistry.contrib.fastapi import AuthConfig, get_password_router, get_oauth2_login_router
from aegistry.contrib.sqlalchemy import create_tables

config = AuthConfig(success_redirect_url="/app")
tables = create_tables(metadata)  # or define your own tables/stores

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
    get_oauth2_login_router(
        identifier="google",
        factor_dependency=get_google_factor,
        authentication_session_service_dependency=get_authentication_session_service,
        session_service_dependency=get_session_service,
        identity_resolver_dependency=get_identity_resolver,
        scope=["openid", "email", "profile"],
        config=config,
    ),
    prefix="/auth",
)
```

Your app provides the *dependencies* (wired to your database session) and an
``IdentityResolver`` mapping verified emails to your user rows; aegistry
provides the flows. See ``tests/contrib/test_fastapi_routers.py`` for a
complete, runnable wiring.

### Provider notes

- **Google** — pure OIDC; `GoogleOAuth2Factor` validates id_tokens against
  Google's JWKS. Email arrives with `email_verified`.
- **LINE** — `LineOAuth2Factor` validates id_tokens through LINE's verify
  endpoint (web-login tokens are HS256-signed with the channel secret, so
  JWKS validation can't be used). The `email` scope requires applying for
  permission in the LINE Developers console, and LINE never returns
  `email_verified` — don't auto-link LINE accounts to existing users by
  email without an extra verification step.

## Status

Early scaffold — APIs unstable. See upstream reauth for the core roadmap.

## License

MIT. Contains code from reauth, © 2026 François Voron, MIT licensed.
