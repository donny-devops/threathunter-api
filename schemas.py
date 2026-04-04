"""Pydantic schemas for API request/response validation."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


# ── Enums ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


# ── Request Bodies ─────────────────────────────────────────────────────

class VulnerabilityCreate(BaseModel):
    """Schema for creating a vulnerability manually."""
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$", examples=["CVE-2024-12345"])
    description: str = Field(..., min_length=10)
    severity: Severity = Severity.UNKNOWN
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    cwe_id: str | None = Field(None, pattern=r"^CWE-\d+$", examples=["CWE-79"])
    vendor: str | None = None
    product: str | None = None
    references_json: str | None = None
    published_at: datetime | None = None


class VulnerabilityUpdate(BaseModel):
    """Schema for partial updates."""
    description: str | None = None
    severity: Severity | None = None
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    cwe_id: str | None = None
    vendor: str | None = None
    product: str | None = None
    references_json: str | None = None


# ── Responses ──────────────────────────────────────────────────────────

class VulnerabilityResponse(BaseModel):
    """Full vulnerability record returned by the API."""
    id: int
    cve_id: str
    description: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    cwe_id: str | None
    vendor: str | None
    product: str | None
    references_json: str | None
    published_at: datetime | None
    modified_at: datetime | None
    created_at: datetime
    risk_rating: str  # Computed field

    model_config = {"from_attributes": True}


class PaginatedResponse(BaseModel):
    """Paginated wrapper."""
    items: list[VulnerabilityResponse]
    total: int
    page: int
    page_size: int
    pages: int


class DashboardStats(BaseModel):
    """Aggregated stats for the dashboard endpoint."""
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    avg_cvss: float | None
    most_recent_cve: str | None
    severity_breakdown: dict[str, int]


class SyncResult(BaseModel):
    """Result of an NVD sync operation."""
    status: str
    new_records: int
    updated_records: int
    errors: int
    duration_seconds: float
