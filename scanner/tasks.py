from uuid import UUID
from celery import Task
from sqlmodel import Session
from shared.celery_app import celery_app
from shared.constants import TASK_SCAN_REPOSITORY
from shared.db.database import engine
from shared.db.models import ScanStatus
from shared.db.repositories import (
    ScanJobRepository,
    ScanResultRepository,
    FindingRepository,
    VulnerabilityRepository,
)
from scanner.services.repo_service import RepoService
from scanner.services.scan_service import ScanService
from scanner.services.score_service import ScoreService


class DatabaseTask(Task):
    """Base task with database session support"""

    _session = None

    @property
    def session(self):
        if self._session is None:
            self._session = Session(engine)
        return self._session

    def after_return(self, *args, **kwargs):
        if self._session is not None:
            self._session.close()
            self._session = None


# Register the task using the name from constants
@celery_app.task(name=TASK_SCAN_REPOSITORY, base=DatabaseTask, bind=True)
def scan_repository(self, job_id: str):
    """
    Task to scan a repository

    Args:
        job_id: UUID of the scan job
    """
    # The rest of the implementation remains the same
    job_id = UUID(job_id)

    # Get repositories
    job_repo = ScanJobRepository(self.session)
    result_repo = ScanResultRepository(self.session)
    finding_repo = FindingRepository(self.session)
    vulnerability_repo = VulnerabilityRepository(self.session)

    # Get job
    job = job_repo.get_by_id(job_id)
    if not job:
        self.logger.error(f"Job {job_id} not found")
        return

    # Update job status to running
    job = job_repo.update_status(job_id, ScanStatus.RUNNING)

    repo_dir = None
    try:
        # Initialize services
        repo_service = RepoService()
        scan_service = ScanService()
        score_service = ScoreService()

        # Clone repository
        repo_url = job.repo_url
        repo_dir = repo_service.clone_repository(repo_url)

        # Scan repository
        scan_results = scan_service.scan_repository(repo_url)

        # Create scan result
        score_data = scan_results.get("score", 0)
        summary = scan_results.get("summary", {})

        scan_result = result_repo.create(
            scan_job_id=job_id,
            score=score_data,
            risk_level=summary.get("risk_level", "LOW"),
            score_explanation=summary.get("score_explanation", ""),
        )

        # Process findings
        raw_results = scan_results.get("raw_results", {})

        # Process semgrep findings
        semgrep_results = raw_results.get("semgrep", {}).get("results", [])
        findings = []

        for result in semgrep_results:
            findings.append(
                {
                    "scan_result_id": scan_result.id,
                    "type": "semgrep",
                    "rule_id": result.get("check_id", "unknown"),
                    "severity": result.get("extra", {}).get("severity", "medium"),
                    "message": result.get("extra", {}).get("message", ""),
                    "path": result.get("path", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "meta_info": {
                        "rule_name": result.get("rule_name", ""),
                        "pattern": result.get("extra", {}).get("pattern", ""),
                        "lines": result.get("extra", {}).get("lines", ""),
                    },
                }
            )

        if findings:
            finding_repo.bulk_create(findings)

        # Process package vulnerabilities
        npm_vulns = (
            raw_results.get("package_scan", {})
            .get("npm", {})
            .get("vulnerabilities", {})
        )
        pip_vulns = (
            raw_results.get("package_scan", {})
            .get("pip", {})
            .get("vulnerabilities", [])
        )

        vulnerabilities = []

        # Process npm vulnerabilities
        for severity, vulns in npm_vulns.items():
            for vuln in vulns:
                vulnerabilities.append(
                    {
                        "scan_result_id": scan_result.id,
                        "package_name": vuln.get("name", "unknown"),
                        "vulnerable_version": vuln.get("version", "unknown"),
                        "fixed_version": "unknown",  # npm audit doesn't provide fixed version directly
                        "severity": severity,
                        "description": str(vuln.get("via", [])),
                        "references": [],
                    }
                )

        # Process pip vulnerabilities
        for vuln in pip_vulns:
            vulnerabilities.append(
                {
                    "scan_result_id": scan_result.id,
                    "package_name": vuln.get("name", "unknown"),
                    "vulnerable_version": vuln.get("version", "unknown"),
                    "fixed_version": ", ".join(vuln.get("fix_versions", [])),
                    "severity": "high",  # pip-audit doesn't provide severity directly
                    "description": vuln.get("description", ""),
                    "references": vuln.get("aliases", []),
                }
            )

        if vulnerabilities:
            vulnerability_repo.bulk_create(vulnerabilities)

        # Update job status to completed
        job_repo.update_status(job_id, ScanStatus.COMPLETED)

    except Exception as e:
        # Update job status to failed
        error_message = f"Error scanning repository: {str(e)}"
        job_repo.update_status(job_id, ScanStatus.FAILED, error=error_message)

    finally:
        # Clean up repository directory
        if repo_dir:
            repo_service.cleanup(repo_dir)
