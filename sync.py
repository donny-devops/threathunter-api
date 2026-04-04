"""Endpoint to manually trigger an NVD sync."""

from fastapi import APIRouter, Query

from src.schemas import SyncResult
from src.services.sync_service import sync_from_nvd

router = APIRouter(prefix="/sync", tags=["Sync"])


@router.post("", response_model=SyncResult)
async def trigger_sync(
    keyword: str = Query(
        "remote code execution",
        description="NVD keyword to search for CVEs",
    ),
):
    """Trigger a manual sync from the NIST NVD API."""
    return await sync_from_nvd(keyword)
