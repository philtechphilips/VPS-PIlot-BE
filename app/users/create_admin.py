"""Create an admin user, or promote an existing user to admin.

uv run poe createadmin admin@example.com
python -m app.users.create_admin --viewer teammate@example.com   (view-only)
"""

import argparse
import getpass
import sys

from pydantic import ValidationError

from app.core.database import SessionLocal
from app.users import service
from app.users.models import Role
from app.users.schemas import UserCreate


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("email")
    parser.add_argument(
        "--viewer", action="store_true", help="view-only: sees all, changes nothing"
    )
    args = parser.parse_args()
    role = Role.VIEWER if args.viewer else Role.ADMIN
    title = "a viewer" if args.viewer else "an admin"

    with SessionLocal() as db:
        user = service.get_user_by_email(db, args.email)
        if user is not None:
            changed = user.role != role
            service.set_role(db, user, role)
            if changed:
                _report(db, user, f"{args.email} is now {title}")
            print(f"{args.email} is now {title}")
            return

        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Confirm password: "):
            sys.exit("Passwords don't match")
        try:
            user_in = UserCreate(email=args.email, password=password)
        except ValidationError as error:
            sys.exit(str(error))

        user = service.create_user(db, user_in, role=role)
        _report(db, user, f"{args.email} was added as {title}")
        print(f"Created {title}: {args.email}")


def _report(db, user, title: str) -> None:
    from app.security import events

    events.record(
        db,
        "role_changed",
        title,
        "Done from the server's command line (vpspilot admin / viewer).",
        user=user,
        actor=("cli", "server command line"),
    )


if __name__ == "__main__":
    main()
