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

    class Config:
        env_file = ".env"


settings = Settings()
