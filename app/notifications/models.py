from datetime import datetime

from sqlalchemy import TIMESTAMP, ForeignKey, Index, String, func, true
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
