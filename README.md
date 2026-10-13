# FastAPI Starter

A starter template for FastAPI projects: feature-based layout, JWT auth,
SQLAlchemy 2.0, Alembic migrations, and pytest.

## Stack

- **FastAPI** with `Annotated` dependencies
- **SQLAlchemy 2.0** (typed `Mapped[...]` models) on **PostgreSQL**
- **Alembic** for migrations
- **PyJWT** for access tokens, **pwdlib** (Argon2) for password hashing
- **pydantic-settings** for config from `.env`
- **pytest** (in-memory SQLite, no Postgres needed) and **ruff**
- **uv** for Python and dependency management

## Project layout

Code is grouped by feature, not by layer. Each feature folder owns everything
for that domain.

```
app/
├── main.py              # creates the app, adds middleware, includes routers
├── core/                # shared, app-wide; never imports from features
│   ├── config.py        # Settings, loaded from .env
│   ├── database.py      # engine, Base, get_db, DbSession
│   ├── security.py      # password hashing, JWT create/decode
│   └── crud.py          # generic DB helpers (fetch, create, update, ...)
├── auth/
│   ├── router.py        # /login, /forgot-password, /reset-password
│   ├── schemas.py       # Token, reset password requests
│   ├── models.py        # PasswordResetToken
│   ├── service.py       # authenticate(), password reset
│   └── dependencies.py  # CurrentUser, AdminUser, require_roles()
└── users/               # copy this folder's shape when adding a feature
    ├── router.py        # HTTP only: parse request, call service, return
    ├── schemas.py       # Pydantic request/response models
    ├── models.py        # SQLAlchemy tables (User, Role)
    ├── service.py       # business logic and DB queries
    └── create_admin.py  # `poe createadmin` command
migrations/              # Alembic
tests/
```

**Rules**

- Dependencies point one way: features import from `core/`, never the reverse.
  `auth` imports from `users`, so `users` must not import from `auth` except
  in its router (for `CurrentUser` / `AdminUser`).
- Routers stay thin. Logic lives in `service.py` so it can be tested and reused.
- Request and response schemas are separate (`UserCreate` vs `UserResponse`),
  so fields like `password` never leak into responses.

## Starting a new project from this template

```bash
cp -r fast-api-starter my-new-project && cd my-new-project
rm -rf .git .venv && git init
# rename the project in pyproject.toml, and PROJECT_NAME in .env if you like

uv sync                       # installs Python 3.12 and all dependencies
cp .env.example .env          # then fill in your database and SECRET_KEY
uv run poe migrate            # create the tables
uv run poe dev
```

Open http://127.0.0.1:8000/docs for the interactive API docs.

## Everyday commands

Commands are defined as [poethepoet](https://poethepoet.natn.io) tasks in
`pyproject.toml` under `[tool.poe.tasks]`, like `scripts` in `package.json`.
Run `uv run poe` to list them.

```bash
uv run poe dev                          # dev server with auto-reload
uv run poe test                         # tests (extra args go to pytest: -k auth)
uv run poe lint                         # fix lint issues and format
uv run poe check                        # lint + format check + tests, no changes (CI)
uv run poe makemigration "add user bio" # generate a migration from model changes
uv run poe migrate                      # apply pending migrations
uv run poe downgrade                    # undo the last migration
uv run poe clean                        # delete __pycache__ and tool caches
uv run poe createadmin you@example.com  # create an admin (or promote a user)
uv run poe start                        # production server
```

Add a dependency with `uv add <package>` (or `uv add --dev <package>`).

## Database migrations

Tables are managed by Alembic, not `create_all`. After changing a model:

```bash
uv run poe makemigration "add votes table"
# review the generated file in migrations/versions/, then:
uv run poe migrate
```

Roll back the last migration with `uv run poe downgrade`. For anything else
use Alembic directly, e.g. `uv run alembic history` or `uv run alembic current`.

**Existing database:** if the `users` table already exists (created by the old
`create_all`), mark only the first migration as done, then apply the rest:

```bash
uv run alembic stamp 685c64471cdc   # "create users" already exists
uv run poe migrate                  # adds roles and password reset tokens
```

## Adding a feature

1. Create `app/<feature>/` with `__init__.py`, `router.py`, `schemas.py`,
   `models.py` and `service.py`, plus `dependencies.py` for shared checks such
   as "load this item or 404" and "only its owner or an admin".
2. Include the router in `app/main.py`.
3. Import the models in `migrations/env.py` so autogenerate sees them.
4. `uv run poe makemigration "add <feature>"`, review it, then
   `uv run poe migrate`.
5. Add `tests/test_<feature>.py`. `tests/test_migrations.py` fails until the
   migration matches your models.

## Auth

- `POST /users/` registers; `POST /login` (form fields `username`, `password`)
  returns a bearer token. `GET /users/me` returns the logged-in user.
- New passwords are hashed with Argon2. Older bcrypt hashes still verify and
  are upgraded to Argon2 the next time that user logs in.

### Roles

Every user has a `role`: `user` (the default) or `admin`. Roles live in
`app/users/models.py` (`Role`); add a member there to add a role.

```python
from app.auth.dependencies import AdminUser, CurrentUser, require_roles


def any_logged_in_user(current_user: CurrentUser): ...
def admins_only(admin: AdminUser): ...


# several roles, or a whole router (after adding an EDITOR role):
router = APIRouter(dependencies=[Depends(require_roles(Role.ADMIN, Role.EDITOR))])
```

The role is read from the database on every request, so a role change takes
effect immediately, without a new token.

- Sign-ups are always `user`. Create the first admin with
  `uv run poe createadmin you@example.com` (it promotes the user if the email
  already exists).
- Admins can list users (`GET /users/`), view any user, and change roles
  (`PATCH /users/{id}/role`, but not their own). Regular users can only view
  themselves.

### Forgot password

1. `POST /forgot-password` with `{"email": ...}` creates a reset token and
   always returns the same message, so it doesn't reveal which emails have
   accounts.
2. The email goes out from `forgot_password` in `app/auth/router.py`. That's a
   `TODO` until you plug in a mail provider; the link is
   `{FRONTEND_URL}/reset-password?token=...`.
3. Your frontend posts `{"token": ..., "new_password": ...}` to
   `POST /reset-password`.

Tokens expire after `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES` (30 by default),
work once, and are replaced when a new one is requested. Only a sha256 hash is
stored. Access tokens already issued stay valid until they expire.
