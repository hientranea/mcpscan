import logging
import sys
from logging.handlers import RotatingFileHandler
import os


def setup_logging(service_name: str, log_level: str = "INFO"):
    """Configure logging for the application"""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    # Create logs directory if it doesn't exist
    os.makedirs("/app/logs", exist_ok=True)

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(numeric_level)

    # Log format
    log_format = logging.Formatter(
        f"%(asctime)s - {service_name} - %(levelname)s - %(name)s - %(message)s"
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_format)
    logger.addHandler(console_handler)

    # File handler
    file_handler = RotatingFileHandler(
        f"/app/logs/{service_name}.log", maxBytes=10485760, backupCount=5  # 10MB
    )
    file_handler.setFormatter(log_format)
    logger.addHandler(file_handler)

    return logger
