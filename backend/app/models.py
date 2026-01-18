from sqlalchemy import String, Integer, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from uuid import uuid4

from .db import Base


class Signal(Base):
    __tablename__ = "signals"

    id: Mapped[str] = mapped_column(String,
                                    primary_key=True,
                                    default=lambda: str(uuid4()))
    tool: Mapped[str] = mapped_column(String, index=True)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime,
                                                 default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String,
                                    primary_key=True,
                                    default=lambda: str(uuid4()))

    # Dedupe key
    fingerprint: Mapped[str] = mapped_column(String(64),
                                             unique=True,
                                             index=True)

    tool: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str] = mapped_column(String)
    asset: Mapped[str] = mapped_column(String, index=True)
    exposure: Mapped[str] = mapped_column(String)
    criticality: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="open")

    risk_score: Mapped[int] = mapped_column(Integer)

    occurrences: Mapped[int] = mapped_column(Integer, default=1)

    first_seen: Mapped[datetime] = mapped_column(DateTime,
                                                 default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime,
                                                default=datetime.utcnow)

    signal_id: Mapped[str] = mapped_column(String, index=True)
