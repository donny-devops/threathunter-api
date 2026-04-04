"""Application settings loaded from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./threathunter.db"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str = ""  # Optional — increases rate limit
    SYNC_ON_STARTUP: bool = True
    SYNC_PAGE_SIZE: int = 50
    CORS_ORIGINS: list[str] = ["*"]
    LOG_LEVEL: str = "INFO"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
