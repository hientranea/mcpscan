from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from shared.db.redis_client import RedisClient
from shared.models import ScanRequest, ScanResponse, ScanResult, ScanStatus, ScanResultSummary
from shared.utils.helpers import generate_job_id, get_timestamp
from api.dependencies import get_redis_client
import logging
from datetime import datetime

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
        # Convert string timestamps to datetime objects
        created_at = job_data["created_at"]
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        
        completed_at = None
        if "completed_at" in job_data and job_data["completed_at"]:
            completed_at = job_data["completed_at"]
            if isinstance(completed_at, str):
                completed_at = datetime.fromisoformat(completed_at)
        
        # Convert to ScanResult model
        result = ScanResult(
            job_id=job_id,
            status=job_data["status"],
            repo_url=job_data["repo_url"],
            created_at=created_at,
            completed_at=completed_at
        )

        # Add results if available
        if job_data["status"] == ScanStatus.COMPLETED and "results" in job_data and job_data["results"]:
            result.score = job_data["results"].get("score")
            
            # Convert summary dict to ScanResultSummary object
            summary_data = job_data["results"].get("summary")
            if summary_data:
                result.summary = ScanResultSummary(**summary_data)
                
            result.raw_results = job_data["results"].get("raw_results")

        # Add error if available
        if job_data["status"] == ScanStatus.FAILED and "error" in job_data:
            result.error = job_data["error"]

        return result
    except Exception as e:
        logger.error(f"Error processing job data: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing job data: {str(e)}")