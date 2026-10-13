"""Create an admin user, or promote an existing user to admin.

uv run poe createadmin admin@example.com
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
    args = parser.parse_args()

    with SessionLocal() as db:
        user = service.get_user_by_email(db, args.email)
        if user is not None:
            service.set_role(db, user, Role.ADMIN)
            print(f"{args.email} is now an admin")
            return

        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Confirm password: "):
            sys.exit("Passwords don't match")
        try:
            user_in = UserCreate(email=args.email, password=password)
        except ValidationError as error:
            sys.exit(str(error))

        service.create_user(db, user_in, role=Role.ADMIN)
        print(f"Created admin {args.email}")


if __name__ == "__main__":
    main()
