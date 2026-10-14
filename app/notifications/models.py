from datetime import datetime

from sqlalchemy import JSON, TIMESTAMP, ForeignKey, Index, String, Text, func, true
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Notification(Base):
    """One item in a user's inbox (the bell in the dashboard)."""

    __tablename__ = "notifications"
    __table_args__ = (
        Index("notifications_user_id_created_at_idx", "user_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(40))  # e.g. deployment.failed
    level: Mapped[str] = mapped_column(String(8))  # ok | err | warn | info
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str | None] = mapped_column(String(500))
    link: Mapped[str | None] = mapped_column(String(300))  # dashboard path
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    read_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class NotificationSettings(Base):
    """Per-user email preferences (in-app notifications are always on)."""

    __tablename__ = "notification_settings"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    email_deploy_success: Mapped[bool] = mapped_column(server_default=true())
    email_deploy_failure: Mapped[bool] = mapped_column(server_default=true())
    email_alerts: Mapped[bool] = mapped_column(server_default=true())


class AlertChannel(Base):
    """Somewhere alerts and deployment results are also sent: a webhook,
    a Slack (or Slack-compatible) incoming webhook, or a Telegram chat."""

    __tablename__ = "alert_channels"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # webhook | slack | telegram
    name: Mapped[str] = mapped_column(String(60))
    # Encrypted JSON: url (+ signing secret) or bot token + chat id.
    config: Mapped[str] = mapped_column(Text)
    # Shown in lists instead of the config, e.g. "hooks.slack.com" or "chat 12345".
    target_label: Mapped[str] = mapped_column(String(120))
    events: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(server_default=true())
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    last_sent_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(300))
