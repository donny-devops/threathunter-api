"""Background sync service — pulls CVEs from the NIST NVD 2.0 API."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.database import async_session
from src.models import Vulnerability
from src.schemas import SyncResult

logger = logging.getLogger("threathunter.sync")

# ── Severity derivation ───────────────────────────────────────────────


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"


# ── NVD response parsing ──────────────────────────────────────────────


def _parse_nvd_item(item: dict) -> dict:
    """Extract fields from a single NVD CVE item."""
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "")

    # Description
    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available",
    )

    # CVSS — try 3.1, fall back to 3.0, then 2.0
    metrics = cve_data.get("metrics", {})
    cvss_score: float | None = None
    cvss_vector: str | None = None

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            break

    severity = _severity_from_cvss(cvss_score)

    # CWE
    weaknesses = cve_data.get("weaknesses", [])
    cwe_id = None
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                cwe_id = desc["value"]
                break
        if cwe_id:
            break

    # Vendor / Product from CPE matches
    configs = cve_data.get("configurations", [])
    vendor, product = None, None
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3] if parts[3] != "*" else None
                    product = parts[4] if parts[4] != "*" else None
                    break

    # References
    refs = cve_data.get("references", [])
    ref_urls = [r.get("url") for r in refs if r.get("url")]

    # Dates
    published = cve_data.get("published")
    modified = cve_data.get("lastModified")

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_id": cwe_id,
        "vendor": vendor,
        "product": product,
        "references_json": json.dumps(ref_urls) if ref_urls else None,
        "published_at": datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
        "modified_at": datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None,
    }


# ── Core sync logic ───────────────────────────────────────────────────


async def sync_from_nvd(keyword: str = "remote code execution") -> SyncResult:
    """
    Pull CVEs from NVD matching *keyword* and upsert into the local DB.
    Default keyword seeds the DB with high-interest vulnerabilities.
    """
    start = time.monotonic()
    new_count, update_count, error_count = 0, 0, 0

    headers: dict[str, str] = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": settings.SYNC_PAGE_SIZE,
        "startIndex": 0,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(settings.NVD_API_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        items = data.get("vulnerabilities", [])
        logger.info("NVD returned %d items for keyword '%s'", len(items), keyword)

        async with async_session() as db:
            for item in items:
                try:
                    parsed = _parse_nvd_item(item)
                    if not parsed["cve_id"]:
                        continue

                    existing = (
                        await db.execute(
                            select(Vulnerability).where(
                                Vulnerability.cve_id == parsed["cve_id"]
                            )
                        )
                    ).scalar_one_or_none()

                    if existing:
                        for k, v in parsed.items():
                            setattr(existing, k, v)
                        update_count += 1
                    else:
                        db.add(Vulnerability(**parsed))
                        new_count += 1
                except Exception as exc:
                    logger.warning("Error processing CVE item: %s", exc)
                    error_count += 1

            await db.commit()

    except httpx.HTTPStatusError as exc:
        logger.error("NVD API HTTP error: %s", exc)
        error_count += 1
    except Exception as exc:
        logger.error("NVD sync failed: %s", exc)
        error_count += 1

    elapsed = round(time.monotonic() - start, 2)
    logger.info(
        "Sync complete — new=%d updated=%d errors=%d (%.2fs)",
        new_count, update_count, error_count, elapsed,
    )
    return SyncResult(
        status="completed",
        new_records=new_count,
        updated_records=update_count,
        errors=error_count,
        duration_seconds=elapsed,
    )


async def schedule_background_sync():
    """Fire-and-forget startup sync."""
    if settings.SYNC_ON_STARTUP:
        logger.info("Scheduling background NVD sync...")
        asyncio.create_task(_background_sync())


async def _background_sync():
    """Run sync with several seed keywords."""
    keywords = [
        "remote code execution",
        "SQL injection",
        "cross-site scripting",
    ]
    for kw in keywords:
        await sync_from_nvd(kw)
        await asyncio.sleep(6)  # Respect NVD rate limits (no API key = 5 req/30s)
