"""CRUD endpoints for vulnerability records."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.schemas import (
    VulnerabilityCreate,
    VulnerabilityUpdate,
    VulnerabilityResponse,
    PaginatedResponse,
)
from src.services.vuln_service import (
    create_vulnerability,
    get_vulnerability_by_cve,
    list_vulnerabilities,
    update_vulnerability,
    delete_vulnerability,
)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=PaginatedResponse)
async def list_vulns(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    severity: str | None = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    keyword: str | None = Query(None, description="Search CVE ID, description, vendor, product"),
    min_cvss: float | None = Query(None, ge=0, le=10),
    max_cvss: float | None = Query(None, ge=0, le=10),
    db: AsyncSession = Depends(get_db),
):
    """List all vulnerabilities with optional filters and pagination."""
    return await list_vulnerabilities(
        db, page=page, page_size=page_size,
        severity=severity, keyword=keyword,
        min_cvss=min_cvss, max_cvss=max_cvss,
    )


@router.get("/{cve_id}", response_model=VulnerabilityResponse)
async def get_vuln(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single vulnerability by CVE ID."""
    vuln = await get_vulnerability_by_cve(db, cve_id.upper())
    if not vuln:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return vuln


@router.post("", response_model=VulnerabilityResponse, status_code=201)
async def create_vuln(data: VulnerabilityCreate, db: AsyncSession = Depends(get_db)):
    """Create a new vulnerability record manually."""
    existing = await get_vulnerability_by_cve(db, data.cve_id)
    if existing:
        raise HTTPException(status_code=409, detail=f"CVE {data.cve_id} already exists")
    return await create_vulnerability(db, data)


@router.patch("/{cve_id}", response_model=VulnerabilityResponse)
async def patch_vuln(
    cve_id: str, data: VulnerabilityUpdate, db: AsyncSession = Depends(get_db)
):
    """Partially update a vulnerability record."""
    updated = await update_vulnerability(db, cve_id.upper(), data)
    if not updated:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return updated


@router.delete("/{cve_id}", status_code=204)
async def remove_vuln(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a vulnerability record."""
    deleted = await delete_vulnerability(db, cve_id.upper())
    if not deleted:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
