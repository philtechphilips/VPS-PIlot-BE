"""Encryption key maintenance.

    python -m app.encryption generate-key   print a new ENCRYPTION_KEY
    python -m app.encryption rotate         re-encrypt everything with the
                                            current ENCRYPTION_KEY

Rotating keys: put the new key in ENCRYPTION_KEY and the old one in
ENCRYPTION_KEYS_PREVIOUS (or nothing, if the old key was the SECRET_KEY
fallback), restart, run `rotate`, then remove the old key.
"""

import secrets
import sys

from cryptography.fernet import InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

import app.apps.models  # noqa: F401  (register all tables)
import app.audit.models  # noqa: F401
import app.auth.models  # noqa: F401
import app.github.models  # noqa: F401
import app.jobs.models  # noqa: F401
import app.notifications.models  # noqa: F401
import app.servers.models  # noqa: F401
from app.apps.models import Application
from app.apps.service import ENV_PURPOSE
from app.core.security import encrypt_secret, reencrypt_secret
from app.github.models import GitHubApp
from app.github.service import PURPOSE as GITHUB_PURPOSE
from app.jobs.models import Job
from app.jobs.service import OUTPUT_PURPOSE
from app.users.models import User


def rotate(db: Session) -> dict[str, int]:
    counts = {"totp": 0, "env": 0, "github": 0, "job_output": 0}
    for user in db.scalars(select(User).where(User.totp_secret.is_not(None))):
        user.totp_secret = reencrypt_secret(user.totp_secret, "totp")
        counts["totp"] += 1
    for application in db.scalars(select(Application)):
        application.env = [
            {**e, "value": reencrypt_secret(e["value"], ENV_PURPOSE)}
            for e in application.env or []
        ]
        counts["env"] += len(application.env)
    for gh in db.scalars(select(GitHubApp)):
        gh.client_secret = reencrypt_secret(gh.client_secret, GITHUB_PURPOSE)
        gh.private_key = reencrypt_secret(gh.private_key, GITHUB_PURPOSE)
        if gh.webhook_secret:
            gh.webhook_secret = reencrypt_secret(gh.webhook_secret, GITHUB_PURPOSE)
        counts["github"] += 1
    for job in db.scalars(select(Job).where(Job.output.is_not(None))):
        try:
            job.output = reencrypt_secret(job.output, OUTPUT_PURPOSE)
        except InvalidToken:
            # Stored before job output was encrypted: encrypt it now.
            job.output = encrypt_secret(job.output, OUTPUT_PURPOSE)
        counts["job_output"] += 1
    db.commit()
    return counts


def main(argv: list[str]) -> int:
    command = argv[1] if len(argv) > 1 else ""
    if command == "generate-key":
        print(secrets.token_urlsafe(32))
        return 0
    if command == "rotate":
        from app.core.database import SessionLocal

        with SessionLocal() as db:
            counts = rotate(db)
        print("Re-encrypted: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
