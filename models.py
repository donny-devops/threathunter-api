"""SQLAlchemy ORM models for vulnerability records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import String, Float, Text, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base


class Vulnerability(Base):
    """Core vulnerability / CVE record."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="UNKNOWN")
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    product: Mapped[str | None] = mapped_column(String(256), nullable=True)
    references_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_vuln_severity", "severity"),
        Index("ix_vuln_cvss", "cvss_score"),
    )

    def __repr__(self) -> str:
        return f"<Vulnerability {self.cve_id} ({self.severity})>"
