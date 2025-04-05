from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlmodel import Session
from uuid import UUID
from datetime import datetime
from shared.db.database import get_session
from shared.db.repositories import (
    ScanJobRepository,
    ScanResultRepository,
    FindingRepository,
    VulnerabilityRepository,
)
from shared.db.models import ScanStatus, RiskLevel
from shared.models import ScanRequest, ScanResponse, ScanResult, ScanResultSummary
from shared.utils.helpers import generate_job_id
from shared.constants import TASK_SCAN_REPOSITORY
from shared.celery_app import celery_app
import logging

router = APIRouter(prefix="/api/scan", tags=["scan"])
logger = logging.getLogger(__name__)


@router.post("/", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    session: Session = Depends(get_session),
):
    """Start a new scan job"""
    try:
        # Create scan job
        scan_job_repo = ScanJobRepository(session)
        job = scan_job_repo.create(repo_url=str(request.repo_url))

        # Queue Celery task
        celery_app.send_task(TASK_SCAN_REPOSITORY, args=[str(job.id)])

        logger.info(f"Queued scan job {job.id} for repository {request.repo_url}")

        return ScanResponse(
            job_id=str(job.id),
            status=ScanStatus.QUEUED,
            message="Scan job queued successfully",
        )
    except Exception as e:
        logger.error(f"Failed to queue scan job: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Failed to queue scan job: {str(e)}"
        )


@router.get("/{job_id}", response_model=ScanResult)
async def get_scan_status(
    job_id: UUID,
    session: Session = Depends(get_session),
):
    """Get the status and results of a scan job"""
    try:
        # Get scan job
        scan_job_repo = ScanJobRepository(session)
        job = scan_job_repo.get_by_id(job_id)

        if not job:
            logger.warning(f"Job {job_id} not found")
            raise HTTPException(status_code=404, detail="Job not found")

        # Create base result
        result = ScanResult(
            job_id=str(job.id),
            status=job.status,
            repo_url=job.repo_url,
            created_at=job.created_at,
            completed_at=job.completed_at,
        )

        # Add results if job is completed
        if job.status == ScanStatus.COMPLETED:
            # Get scan result
            scan_result_repo = ScanResultRepository(session)
            finding_repo = FindingRepository(session)
            vulnerability_repo = VulnerabilityRepository(session)

            scan_result = scan_result_repo.get_by_scan_job_id(job.id)

            if scan_result:
                result.score = scan_result.score

                # Get findings
                findings = finding_repo.get_by_scan_result_id(scan_result.id)
                vulnerabilities = vulnerability_repo.get_by_scan_result_id(
                    scan_result.id
                )

                # Create summary
                finding_counts = {}
                for finding in findings:
                    finding_type = finding.type
                    if finding_type not in finding_counts:
                        finding_counts[finding_type] = 0
                    finding_counts[finding_type] += 1

                # Add vulnerability counts
                if vulnerabilities:
                    finding_counts["vulnerabilities"] = len(vulnerabilities)

                result.summary = ScanResultSummary(
                    score_explanation=scan_result.score_explanation,
                    findings=finding_counts,
                    risk_level=scan_result.risk_level,
                )

                # Add raw results
                result.raw_results = {
                    "findings": [
                        {
                            "rule_id": f.rule_id,
                            "type": f.type,
                            "severity": f.severity,
                            "message": f.message,
                            "path": f.path,
                            "line": f.line,
                            "metadata": f.meta_info,
                        }
                        for f in findings
                    ],
                    "vulnerabilities": [
                        {
                            "package_name": v.package_name,
                            "vulnerable_version": v.vulnerable_version,
                            "fixed_version": v.fixed_version,
                            "severity": v.severity,
                            "description": v.description,
                            "references": v.references,
                        }
                        for v in vulnerabilities
                    ],
                }

        # Add error if job failed
        if job.status == ScanStatus.FAILED and job.error:
            result.error = job.error

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving job {job_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error retrieving job: {str(e)}")
