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

## Status

Early scaffold — APIs unstable. See upstream reauth for the core roadmap.

## License

MIT. Contains code from reauth, © 2026 François Voron, MIT licensed.
