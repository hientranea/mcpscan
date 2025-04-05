from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from shared.db.redis_client import RedisClient
from shared.models import ScanRequest, ScanResponse, ScanResult, ScanStatus
from shared.utils.helpers import generate_job_id, get_timestamp
from api.services.scan_service import ScanService
from api.dependencies import get_redis_client
import logging

router = APIRouter(prefix="/api/scan", tags=["scan"])
logger = logging.getLogger(__name__)


@router.post("/", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    redis_client: RedisClient = Depends(get_redis_client),
):
    """Start a new scan job"""
    job_id = generate_job_id()

    # Create job data
    job_data = {
        "job_id": job_id,
        "repo_url": str(request.repo_url),
        "status": ScanStatus.QUEUED,
        "created_at": get_timestamp(),
        "results": None,
    }

    # Store job in Redis
    try:
        redis_client.set_job(job_id, job_data)
        redis_client.add_to_queue(job_id)
        logger.info(f"Queued scan job {job_id} for repository {request.repo_url}")
    except Exception as e:
        logger.error(f"Failed to queue scan job: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to queue scan job")

    return ScanResponse(
        job_id=job_id, status=ScanStatus.QUEUED, message="Scan job queued successfully"
    )


@router.get("/{job_id}", response_model=ScanResult)
async def get_scan_status(
    job_id: str, redis_client: RedisClient = Depends(get_redis_client)
):
    """Get the status and results of a scan job"""
    job_data = redis_client.get_job(job_id)

    if not job_data:
        logger.warning(f"Job {job_id} not found")
        raise HTTPException(status_code=404, detail="Job not found")

    try:
        # Convert to ScanResult model
        result = ScanResult(
            job_id=job_id,
            status=job_data["status"],
            repo_url=job_data["repo_url"],
            created_at=job_data["created_at"],
        )

        # Add completed_at if available
        if "completed_at" in job_data:
            result.completed_at = job_data["completed_at"]

        # Add results if available
        if job_data["status"] == ScanStatus.COMPLETED and "results" in job_data:
            result.score = job_data["results"].get("score")
            result.summary = job_data["results"].get("summary")
            result.raw_results = job_data["results"].get("raw_results")

        # Add error if available
        if job_data["status"] == ScanStatus.FAILED and "error" in job_data:
            result.error = job_data["error"]

        return result
    except Exception as e:
        logger.error(f"Error processing job data: {str(e)}")
        raise HTTPException(status_code=500, detail="Error processing job data")
