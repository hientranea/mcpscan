import os
import shutil
import uuid
from datetime import datetime


def generate_job_id() -> str:
    """Generate a unique job ID"""
    return str(uuid.uuid4())


def get_timestamp() -> str:
    """Get current timestamp in ISO format"""
    return datetime.utcnow().isoformat()


def ensure_directory(directory: str) -> None:
    """Ensure a directory exists, create it if it doesn't"""
    os.makedirs(directory, exist_ok=True)


def clean_directory(directory: str) -> None:
    """Clean a directory by removing and recreating it"""
    if os.path.exists(directory):
        shutil.rmtree(directory)
    os.makedirs(directory, exist_ok=True)


def get_repo_name(repo_url: str) -> str:
    """Extract repository name from URL"""
    # Handle URLs with or without .git extension
    url_parts = repo_url.rstrip("/").split("/")
    repo_name = url_parts[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    return repo_name
