from shared.db.redis_client import RedisClient
from shared.models import ScanStatus
import logging

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, redis_client: RedisClient):
        self.redis_client = redis_client

    def update_job_status(
        self, job_id: str, status: ScanStatus, results=None, error=None
    ):
        """Update job status in Redis"""
        job_data = self.redis_client.get_job(job_id)
        if not job_data:
            logger.warning(f"Job {job_id} not found when updating status")
            return False

        job_data["status"] = status

        if results:
            job_data["results"] = results

        if error:
            job_data["error"] = error

        self.redis_client.set_job(job_id, job_data)
        return True
