import json
from typing import Any, Dict, Optional
import redis
from shared.config import settings


class RedisClient:
    def __init__(self):
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True,
        )

    def set_job(
        self, job_id: str, job_data: Dict[str, Any], expiration: int = None
    ) -> None:
        """Store job data in Redis with optional expiration time"""
        if expiration is None:
            expiration = settings.RESULT_EXPIRATION

        self.redis.set(f"job:{job_id}", json.dumps(job_data), ex=expiration)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job data from Redis"""
        job_data = self.redis.get(f"job:{job_id}")
        if job_data:
            return json.loads(job_data)
        return None

    def add_to_queue(self, job_id: str) -> None:
        """Add job to processing queue"""
        self.redis.lpush("scan_queue", job_id)

    def get_next_job(self) -> Optional[str]:
        """Get next job from processing queue"""
        return self.redis.rpop("scan_queue")

    def queue_length(self) -> int:
        """Get the length of the processing queue"""
        return self.redis.llen("scan_queue")


# Singleton instance
redis_client = RedisClient()
