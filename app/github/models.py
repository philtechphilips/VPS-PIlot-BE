from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class GitHubApp(Base):
    """The GitHub App this VPSPilot install created for itself (one per
    install). Credentials are encrypted at rest."""

    __tablename__ = "github_apps"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    app_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    slug: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    owner_login: Mapped[str] = mapped_column(String(100))
    owner_type: Mapped[str] = mapped_column(String(16))  # User | Organization
    html_url: Mapped[str] = mapped_column(String(300))
    client_id: Mapped[str] = mapped_column(String(100))
    client_secret: Mapped[str] = mapped_column(Text)  # encrypted
    private_key: Mapped[str] = mapped_column(Text)  # encrypted PEM
    webhook_secret: Mapped[str | None] = mapped_column(Text)  # encrypted
    webhook_url: Mapped[str | None] = mapped_column(String(300))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )


class GitHubInstallation(Base):
    """Where the app is installed (a user or organization account)."""

    __tablename__ = "github_installations"

    # GitHub's installation id
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    github_app_id: Mapped[str] = mapped_column(
        ForeignKey("github_apps.id", ondelete="CASCADE"), index=True
    )
    account_login: Mapped[str] = mapped_column(String(100))
    account_type: Mapped[str] = mapped_column(String(16))
    account_avatar_url: Mapped[str | None] = mapped_column(String(300))
    repository_selection: Mapped[str] = mapped_column(String(16))  # all | selected
    suspended_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
