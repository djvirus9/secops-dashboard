from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import String, Integer, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> str:
    return str(uuid4())


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    key: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String, default="")
    environment: Mapped[str] = mapped_column(String, default="unknown")
    owner: Mapped[str] = mapped_column(String, default="")
    criticality: Mapped[str] = mapped_column(String, default="medium")
    exposure: Mapped[str] = mapped_column(String, default="internal")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="asset_rel")


class Signal(Base):
    __tablename__ = "signals"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tool: Mapped[str] = mapped_column(String, index=True)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)

    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    tool: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str] = mapped_column(String)

    asset: Mapped[str] = mapped_column(String, index=True)
    asset_id: Mapped[str | None] = mapped_column(String, ForeignKey("assets.id"), nullable=True, index=True)
    asset_rel: Mapped["Asset"] = relationship(back_populates="findings")

    exposure: Mapped[str] = mapped_column(String, default="internal")
    criticality: Mapped[str] = mapped_column(String, default="medium")
    status: Mapped[str] = mapped_column(String, default="open", index=True)
    assignee: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    risk_score: Mapped[int] = mapped_column(Integer, default=1)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    signal_id: Mapped[str] = mapped_column(String, index=True)

    comments: Mapped[list["Comment"]] = relationship(back_populates="finding", order_by="Comment.created_at.desc()")


class Comment(Base):
    __tablename__ = "comments"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id"), index=True)
    finding: Mapped["Finding"] = relationship(back_populates="comments")

    author: Mapped[str] = mapped_column(String, default="system")
    content: Mapped[str] = mapped_column(Text)
    action_type: Mapped[str | None] = mapped_column(String, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
