"""
ThreatHunter API — Vulnerability Intelligence Platform
=====================================================
A production-grade FastAPI service for aggregating, scoring, and querying
vulnerability intelligence data (CVEs). Supports full CRUD, CVSS-based risk
scoring, keyword search, severity filtering, and background sync from the
NIST NVD public feed.

Author: Donny Jimenez (@donny-devops)
License: MIT
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config import settings
from src.database import engine, Base
from src.routers import vulnerabilities, dashboard, sync
from src.services.sync_service import schedule_background_sync

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("threathunter")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup → shutdown."""
    logger.info("🚀 ThreatHunter API starting — creating tables")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables ready")

    # Kick off initial background sync
    await schedule_background_sync()

    yield

    logger.info("🛑 ThreatHunter API shutting down")
    await engine.dispose()


app = FastAPI(
    title="ThreatHunter API",
    description=(
        "Vulnerability Intelligence Platform — aggregate, score, and query "
        "CVE data with CVSS-based risk analysis."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(vulnerabilities.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(sync.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health_check():
    """Liveness probe."""
    return {"status": "healthy", "service": "threathunter-api", "version": "1.0.0"}
