"""Dashboard / analytics endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.schemas import DashboardStats
from src.services.vuln_service import get_dashboard_stats

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("", response_model=DashboardStats)
async def dashboard(db: AsyncSession = Depends(get_db)):
    """Return aggregated vulnerability statistics."""
    return await get_dashboard_stats(db)
