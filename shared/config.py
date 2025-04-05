import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API settings
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # Redis settings
    REDIS_HOST: str = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB: int = int(os.getenv("REDIS_DB", 0))

    # Scanner settings
    SCAN_TIMEOUT: int = 600  # 10 minutes
    WORKING_DIR: str = "/tmp/mcpscan/working"
    RESULTS_DIR: str = "/app/results"
    COMBINED_DIR: str = "/app/results/combined"

    # Semgrep rules directory
    RULES_DIR: str = "/app/scanner/rules/semgrep"

    # Result expiration (in seconds)
    RESULT_EXPIRATION: int = 60 * 60 * 24 * 7  # 7 days

    # Database settings
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: str = os.getenv("DB_PORT", "5432")
    DB_USER: str = os.getenv("DB_USER", "postgres")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "postgres")
    DB_NAME: str = os.getenv("DB_NAME", "mcpscan")
    DB_ECHO: bool = os.getenv("DB_ECHO", "False").lower() == "true"

    # Celery settings
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND: str = os.getenv(
        "CELERY_RESULT_BACKEND", "redis://localhost:6379/0"
    )

    class Config:
        env_file = ".env"


settings = Settings()
