from datetime import datetime, timezone
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db import Base


class InferenceRecord(Base):
    __tablename__ = "inference_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    input_sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    model_sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    output_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance_sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="VERIFIED", nullable=False)
    actor: Mapped[str] = mapped_column(String(255), default="web-user", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
