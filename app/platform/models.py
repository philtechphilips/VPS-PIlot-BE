from datetime import datetime

from sqlalchemy import TIMESTAMP, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class PlatformSettings(Base):
    """One row: how this control plane presents itself."""

    __tablename__ = "platform_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(32), server_default="VPSPilot")
    # Public address of this control plane (https://pilot.example.com).
    # When set it's what agents, install commands and webhooks use.
    public_url: Mapped[str | None] = mapped_column(String(300))
    updated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    # Last time someone downloaded the encryption-key recovery kit.
    recovery_kit_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
