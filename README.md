# VPSPilot API

The control-plane API for VPSPilot: a self-hosted dashboard for managing VPS
servers, deployments and databases. Built on FastAPI, SQLAlchemy 2.0 and
PostgreSQL.

This first slice is **authentication**: a single owner account, password
login with an emailed 6-digit code (two-factor), rotating refresh sessions and
password resets. Email is sent through [Resend](https://resend.com).

## Quick start

```bash
uv sync                      # install Python and dependencies
cp .env.example .env         # then fill in the values below
uv run poe migrate           # create the tables
uv run poe dev               # http://localhost:8000, docs at /docs
```

The Next.js dashboard proxies `/api/*` to this server, so open
<http://localhost:3000/setup> to create the owner account.

### `.env`

| Variable | Notes |
|---|---|
| `DATABASE_*` | PostgreSQL connection. Create the database first (`createdb vpspilot`). |
| `SECRET_KEY` | `openssl rand -hex 32`. Signs access tokens and keys the 2FA code hashes. |
| `RESEND_API_KEY` | Without it, emails (codes, reset links) are printed to the server log instead of sent. |
| `EMAIL_FROM` | `VPSPilot <onboarding@resend.dev>` works without a verified domain. |
| `EMAIL_OVERRIDE_TO` | Resend's test sender only delivers to your own Resend account address. Set this to that address and every email goes there (the real recipient is added to the subject). Remove it once your domain is verified. |
| `COOKIE_SECURE` | `true` in production so the refresh cookie is HTTPS-only. |
| `FRONTEND_URL` | Used in password-reset links. |

> **Shell note:** if `uv` is wrapped by a tool such as safe-chain, empty
> variables (`RESEND_API_KEY= uv run …`) may be dropped before Python sees
> them, so `.env` wins. Use `.venv/bin/uvicorn` directly, or edit `.env`, when
> you need to override a value with an empty one.

## Authentication flow

All routes are under `/api/v1/auth`.

```
GET  /setup-status         → {needs_setup}            first run only
POST /setup                → challenge, emails code   creates the owner (admin)
POST /login                → challenge, emails code   password check + lockout
POST /2fa/verify           → access token + cookie    code → session
POST /2fa/resend           → new challenge            30 s cooldown
POST /refresh              → access token + cookie    rotates the refresh token
POST /logout               → 204                      revokes the session
GET  /me                   → user
GET  /sessions             → signed-in devices
DELETE /sessions/{id}      → revoke one device
POST /sessions/revoke-others
POST /forgot-password      → same reply for any email; emails a reset link
POST /reset-password       → sets the password and signs out every device
```

**How it is protected**

- **Codes**: 6 digits, valid 10 minutes, 5 attempts, single use. Only an HMAC
  of the code (keyed with `SECRET_KEY`, bound to the challenge) is stored.
- **Lockout**: 5 wrong passwords lock the account for 15 minutes. Unknown
  emails get the same error and similar timing as wrong passwords.
- **Sessions**: access tokens last 15 minutes and carry a session id; revoking
  the session invalidates them immediately. The refresh token lives in an
  httpOnly, `SameSite=Lax` cookie scoped to `/api/v1/auth`, is stored as a
  hash, and rotates on every refresh.
- **No public sign-up**: the owner is created once through `/setup`. Further
  admins: `uv run poe createadmin you@example.com`.

The users API (`/api/v1/users`) keeps the starter's role checks.

## Project layout

Code is grouped by feature. Features import from `core/`, never the reverse.

```
app/
├── main.py              # app, middleware, routers, logging
├── core/
│   ├── config.py        # Settings from .env
│   ├── database.py      # engine, Base, get_db, DbSession
│   ├── security.py      # password hashing, JWTs, OTP and token helpers
│   ├── email.py         # Resend client (logs instead when no API key)
│   └── crud.py          # generic DB helpers
├── auth/
│   ├── router.py        # /api/v1/auth/*
│   ├── service.py       # setup, login, challenges, sessions, resets
│   ├── emails.py        # code and reset email templates
│   ├── models.py        # TwoFactorChallenge, AuthSession, PasswordResetToken
│   ├── schemas.py
│   └── dependencies.py  # CurrentUser, AdminUser, require_roles()
└── users/               # User model, /api/v1/users, createadmin
migrations/              # Alembic
tests/                   # pytest on in-memory SQLite; email is captured
```

## Commands

Run `uv run poe` to list them.

| Command | What it does |
|---|---|
| `uv run poe dev` | Dev server with reload |
| `uv run poe test` | Tests (no Postgres or email needed) |
| `uv run poe lint` | Fix lint issues and format |
| `uv run poe check` | Lint, format check and tests, for CI |
| `uv run poe migrate` | Apply migrations |
| `uv run poe makemigration "message"` | Generate a migration from model changes |
| `uv run poe createadmin <email>` | Create an admin, or promote a user |
