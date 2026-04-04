# ThreatHunter API

**Vulnerability Intelligence Platform** — A production-grade FastAPI service for aggregating, scoring, and querying CVE data with CVSS-based risk analysis and live sync from the NIST National Vulnerability Database.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-D71F00?logo=sqlalchemy&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

- **Full CRUD API** — Create, read, update, and delete vulnerability records via RESTful endpoints
- **NVD Live Sync** — Background ingestion from the NIST NVD 2.0 API with configurable keyword seeds
- **CVSS Risk Scoring** — Automatic severity classification and human-readable risk ratings derived from CVSS v3.1/v3.0/v2.0 scores
- **Advanced Filtering** — Query by severity level, CVSS score range, keyword search across descriptions/vendors/products
- **Paginated Results** — Offset-based pagination with total counts and page metadata
- **Dashboard Analytics** — Aggregated stats endpoint with severity breakdown, average CVSS, and latest CVE tracking
- **Async Throughout** — Built on async SQLAlchemy + aiosqlite for non-blocking I/O
- **Docker Ready** — Single-command deployment with health checks and persistent volumes
- **CI/CD Pipeline** — GitHub Actions workflow with linting, type checking, multi-version testing, and Docker smoke tests

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | FastAPI 0.115+ |
| ORM | SQLAlchemy 2.0 (async) |
| Database | SQLite (aiosqlite) — swappable to PostgreSQL |
| Validation | Pydantic v2 |
| HTTP Client | httpx (async) |
| Testing | pytest + pytest-asyncio |
| Linting | Ruff |
| Type Checking | mypy (strict mode) |
| Containerization | Docker + Docker Compose |
| CI/CD | GitHub Actions |

## Quick Start

### Local Development

```bash
# Clone the repository
git clone https://github.com/donny-devops/threathunter-api.git
cd threathunter-api

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\Activate.ps1  # Windows PowerShell

# Install dependencies
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env — optionally add your NVD API key for higher rate limits

# Run the server
uvicorn src.main:app --reload --port 8000
```

### Docker

```bash
# Build and run
docker compose up --build -d

# Check health
curl http://localhost:8000/health
```

## API Reference

Once the server is running, interactive docs are available at:

- **Swagger UI** → `http://localhost:8000/docs`
- **ReDoc** → `http://localhost:8000/redoc`

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness probe |
| `GET` | `/api/v1/vulnerabilities` | List CVEs (paginated, filterable) |
| `GET` | `/api/v1/vulnerabilities/{cve_id}` | Get single CVE by ID |
| `POST` | `/api/v1/vulnerabilities` | Create a CVE record manually |
| `PATCH` | `/api/v1/vulnerabilities/{cve_id}` | Partial update |
| `DELETE` | `/api/v1/vulnerabilities/{cve_id}` | Delete a CVE record |
| `GET` | `/api/v1/dashboard` | Aggregated analytics |
| `POST` | `/api/v1/sync` | Trigger NVD sync |

### Query Parameters (List Endpoint)

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `page_size` | int | Results per page, 1–100 (default: 25) |
| `severity` | string | Filter: CRITICAL, HIGH, MEDIUM, LOW |
| `keyword` | string | Search CVE ID, description, vendor, product |
| `min_cvss` | float | Minimum CVSS score (0–10) |
| `max_cvss` | float | Maximum CVSS score (0–10) |

### Example Requests

```bash
# List critical vulnerabilities
curl "http://localhost:8000/api/v1/vulnerabilities?severity=CRITICAL&page_size=10"

# Search for SQL injection CVEs
curl "http://localhost:8000/api/v1/vulnerabilities?keyword=SQL+injection"

# Get dashboard stats
curl http://localhost:8000/api/v1/dashboard

# Trigger NVD sync with custom keyword
curl -X POST "http://localhost:8000/api/v1/sync?keyword=privilege+escalation"

# Create a manual CVE entry
curl -X POST http://localhost:8000/api/v1/vulnerabilities \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-99999",
    "description": "Critical RCE in ExampleLib allowing unauthenticated remote code execution.",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "cwe_id": "CWE-78",
    "vendor": "example_corp",
    "product": "example_lib"
  }'
```

## Testing

```bash
# Run full test suite
pytest -v

# Run with coverage report
pytest --cov=src --cov-report=term-missing -v

# Lint
ruff check src/ tests/

# Type check
mypy src/ --ignore-missing-imports
```

## Project Structure

```
threathunter-api/
├── .github/workflows/ci.yml   # CI/CD pipeline
├── src/
│   ├── main.py                 # FastAPI app + lifespan
│   ├── config.py               # Pydantic settings
│   ├── database.py             # Async SQLAlchemy engine
│   ├── models.py               # ORM models
│   ├── schemas.py              # Pydantic request/response schemas
│   ├── routers/
│   │   ├── vulnerabilities.py  # CRUD endpoints
│   │   ├── dashboard.py        # Analytics endpoint
│   │   └── sync.py             # NVD sync trigger
│   └── services/
│       ├── vuln_service.py     # Business logic + risk scoring
│       └── sync_service.py     # NVD API integration
├── tests/
│   └── test_api.py             # 14 async integration tests
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── .env.example
└── .gitignore
```

## License

MIT — see [LICENSE](LICENSE) for details.
