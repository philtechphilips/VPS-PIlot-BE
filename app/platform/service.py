"""Control-plane identity: name, public URL and version."""

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app import __version__
from app.core.config import settings
from app.platform.models import PlatformSettings


def get(db: Session) -> PlatformSettings:
    row = db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1, name="VPSPilot")
        db.add(row)
        db.commit()
    return row


def update(
    db: Session, name: str | None, public_url: str | None, clear_url: bool = False
) -> PlatformSettings:
    row = get(db)
    if name is not None:
        row.name = name
    if clear_url:
        row.public_url = None
    elif public_url is not None:
        row.public_url = public_url.rstrip("/")
    row.updated_at = datetime.now(UTC)
    db.commit()
    return row


def agent_url(db: Session) -> str:
    """What agents (and install commands) use to reach this API."""
    row = db.get(PlatformSettings, 1)
    return (
        row.public_url if row and row.public_url else settings.agent_api_url
    ).rstrip("/")


def webhook_base(db: Session) -> str | None:
    """A public https base for webhooks, if there is one."""
    row = db.get(PlatformSettings, 1)
    if row and row.public_url and row.public_url.startswith("https://"):
        return row.public_url.rstrip("/")
    return settings.webhook_base_url


def version() -> str:
    return __version__


def recovery_kit(db: Session, by: str) -> str:
    """Everything needed to read VPSPilot's encrypted data without this
    control plane: the master keys and the backup key, with instructions."""
    from app.backups import service as backups
    from app.core.security import decrypt_secret

    row = get(db)
    now = datetime.now(UTC)
    backup_key = decrypt_secret(
        backups.get_settings(db).encryption_key, backups.PURPOSE
    )
    previous = [
        k.strip() for k in settings.encryption_keys_previous.split(",") if k.strip()
    ]
    master = settings.encryption_key
    lines = [
        "VPSPilot recovery kit",
        "=====================",
        f"Control plane: {row.name} ({row.public_url or settings.agent_api_url})",
        f"Created: {now:%Y-%m-%d %H:%M} UTC by {by}",
        "",
        "Keep this file offline (a password manager or a printed copy in a safe).",
        "Anyone holding it can decrypt the secrets VPSPilot stores and your backups.",
        "",
        "1. Control plane keys",
        "---------------------",
        "Stored secrets (env vars, tokens, database passwords) are encrypted with",
        "these. Put them in the control plane's .env when reinstalling, together",
        "with a restored copy of its database.",
        "",
    ]
    if master:
        lines.append(f"ENCRYPTION_KEY={master}")
    else:
        lines += [
            "ENCRYPTION_KEY is not set: SECRET_KEY encrypts the secrets.",
            f"SECRET_KEY={settings.secret_key}",
        ]
    if previous:
        lines.append(f"ENCRYPTION_KEYS_PREVIOUS={','.join(previous)}")
    if master:
        lines.append(f"SECRET_KEY={settings.secret_key}")
    lines += [
        "",
        "2. Backup key",
        "-------------",
        "Every database backup is encrypted with this key (AES-256-CBC, PBKDF2,",
        "100000 iterations) before it leaves the server.",
        "",
        f"VPB_KEY={backup_key}",
        "",
        "Decrypt a backup by hand (OpenSSL 1.1.1 or newer):",
        "",
        f"  export VPB_KEY={backup_key}",
        "  # PostgreSQL (*.pgdump.enc):",
        "  openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass env:VPB_KEY \\",
        "    -in backup.pgdump.enc | pg_restore --no-owner -d DATABASE",
        "  # MySQL / MariaDB (*.sql.gz.enc):",
        "  openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass env:VPB_KEY \\",
        "    -in backup.sql.gz.enc | gunzip | mysql DATABASE",
        "  # Redis (*.rdb.gz.enc): gives dump.rdb",
        "  openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass env:VPB_KEY \\",
        "    -in backup.rdb.gz.enc | gunzip > dump.rdb",
        "",
        "If you rotate ENCRYPTION_KEY, download a new kit.",
        "",
    ]
    row.recovery_kit_at = now
    db.commit()
    return "\n".join(lines)
