"""Service layer for vulnerability CRUD operations + risk scoring."""

from __future__ import annotations

import math
from datetime import datetime

from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import Vulnerability
from src.schemas import (
    VulnerabilityCreate,
    VulnerabilityUpdate,
    VulnerabilityResponse,
    PaginatedResponse,
    DashboardStats,
)


def compute_risk_rating(severity: str, cvss_score: float | None) -> str:
    """Derive a human-readable risk rating from severity + CVSS."""
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "CRITICAL — Immediate Action Required"
        if cvss_score >= 7.0:
            return "HIGH — Prioritize Remediation"
        if cvss_score >= 4.0:
            return "MEDIUM — Schedule Fix"
        if cvss_score >= 0.1:
            return "LOW — Monitor"
        return "INFORMATIONAL"
    severity_map = {
        "CRITICAL": "CRITICAL — Immediate Action Required",
        "HIGH": "HIGH — Prioritize Remediation",
        "MEDIUM": "MEDIUM — Schedule Fix",
        "LOW": "LOW — Monitor",
    }
    return severity_map.get(severity.upper(), "UNKNOWN — Needs Assessment")


def _to_response(vuln: Vulnerability) -> VulnerabilityResponse:
    """Convert ORM model to response schema with computed risk rating."""
    return VulnerabilityResponse(
        id=vuln.id,
        cve_id=vuln.cve_id,
        description=vuln.description,
        severity=vuln.severity,
        cvss_score=vuln.cvss_score,
        cvss_vector=vuln.cvss_vector,
        cwe_id=vuln.cwe_id,
        vendor=vuln.vendor,
        product=vuln.product,
        references_json=vuln.references_json,
        published_at=vuln.published_at,
        modified_at=vuln.modified_at,
        created_at=vuln.created_at,
        risk_rating=compute_risk_rating(vuln.severity, vuln.cvss_score),
    )


async def create_vulnerability(
    db: AsyncSession, data: VulnerabilityCreate
) -> VulnerabilityResponse:
    """Insert a new vulnerability record."""
    vuln = Vulnerability(
        cve_id=data.cve_id,
        description=data.description,
        severity=data.severity.value,
        cvss_score=data.cvss_score,
        cvss_vector=data.cvss_vector,
        cwe_id=data.cwe_id,
        vendor=data.vendor,
        product=data.product,
        references_json=data.references_json,
        published_at=data.published_at,
    )
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)
    return _to_response(vuln)


async def get_vulnerability_by_cve(
    db: AsyncSession, cve_id: str
) -> VulnerabilityResponse | None:
    """Fetch a single record by CVE-ID."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.cve_id == cve_id)
    )
    vuln = result.scalar_one_or_none()
    return _to_response(vuln) if vuln else None


async def list_vulnerabilities(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 25,
    severity: str | None = None,
    keyword: str | None = None,
    min_cvss: float | None = None,
    max_cvss: float | None = None,
) -> PaginatedResponse:
    """List vulnerabilities with filtering and pagination."""
    query = select(Vulnerability)
    count_query = select(func.count(Vulnerability.id))

    # Apply filters
    if severity:
        query = query.where(Vulnerability.severity == severity.upper())
        count_query = count_query.where(Vulnerability.severity == severity.upper())
    if keyword:
        pattern = f"%{keyword}%"
        kw_filter = or_(
            Vulnerability.description.ilike(pattern),
            Vulnerability.cve_id.ilike(pattern),
            Vulnerability.vendor.ilike(pattern),
            Vulnerability.product.ilike(pattern),
        )
        query = query.where(kw_filter)
        count_query = count_query.where(kw_filter)
    if min_cvss is not None:
        query = query.where(Vulnerability.cvss_score >= min_cvss)
        count_query = count_query.where(Vulnerability.cvss_score >= min_cvss)
    if max_cvss is not None:
        query = query.where(Vulnerability.cvss_score <= max_cvss)
        count_query = count_query.where(Vulnerability.cvss_score <= max_cvss)

    # Total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    query = query.order_by(Vulnerability.cvss_score.desc().nullslast()).offset(offset).limit(page_size)
    result = await db.execute(query)
    vulns = result.scalars().all()

    return PaginatedResponse(
        items=[_to_response(v) for v in vulns],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


async def update_vulnerability(
    db: AsyncSession, cve_id: str, data: VulnerabilityUpdate
) -> VulnerabilityResponse | None:
    """Partial update of a vulnerability record."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.cve_id == cve_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        return None

    update_data = data.model_dump(exclude_unset=True)
    if "severity" in update_data and update_data["severity"] is not None:
        update_data["severity"] = update_data["severity"].value

    for key, value in update_data.items():
        setattr(vuln, key, value)

    vuln.modified_at = datetime.utcnow()
    await db.commit()
    await db.refresh(vuln)
    return _to_response(vuln)


async def delete_vulnerability(db: AsyncSession, cve_id: str) -> bool:
    """Delete a vulnerability by CVE-ID. Returns True if deleted."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.cve_id == cve_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        return False
    await db.delete(vuln)
    await db.commit()
    return True


async def get_dashboard_stats(db: AsyncSession) -> DashboardStats:
    """Aggregate statistics for the dashboard."""
    total = (await db.execute(select(func.count(Vulnerability.id)))).scalar() or 0

    severity_counts: dict[str, int] = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"):
        count = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.severity == sev
                )
            )
        ).scalar() or 0
        severity_counts[sev] = count

    avg_cvss = (
        await db.execute(select(func.avg(Vulnerability.cvss_score)))
    ).scalar()

    most_recent = (
        await db.execute(
            select(Vulnerability.cve_id)
            .order_by(Vulnerability.published_at.desc().nullslast())
            .limit(1)
        )
    ).scalar()

    return DashboardStats(
        total_vulnerabilities=total,
        critical_count=severity_counts.get("CRITICAL", 0),
        high_count=severity_counts.get("HIGH", 0),
        medium_count=severity_counts.get("MEDIUM", 0),
        low_count=severity_counts.get("LOW", 0),
        avg_cvss=round(avg_cvss, 2) if avg_cvss else None,
        most_recent_cve=most_recent,
        severity_breakdown=severity_counts,
    )
