import time
import logging
import json
from datetime import datetime
from shared.db.redis_client import redis_client
from shared.models import ScanStatus
from shared.utils.logging import setup_logging
from scanner.services.scan_service import ScanService

# Setup logging
logger = setup_logging(service_name="scanner")


class ScannerWorker:
    """Worker that processes scan jobs from the queue"""

    def __init__(self):
        self.redis_client = redis_client
        self.scan_service = ScanService()
        self.running = True

    def update_job_status(self, job_id, status, results=None, error=None):
        """Update job status in Redis"""
        job_data = self.redis_client.get_job(job_id)
        if not job_data:
            logger.warning(f"Job {job_id} not found when updating status")
            return

        job_data["status"] = status

        if status == ScanStatus.COMPLETED:
            job_data["completed_at"] = datetime.utcnow().isoformat()
            if results:
                job_data["results"] = results

        if status == ScanStatus.FAILED:
            job_data["completed_at"] = datetime.utcnow().isoformat()
            if error:
                job_data["error"] = error

        self.redis_client.set_job(job_id, job_data)

    def process_job(self, job_id):
        """Process a scan job"""
        try:
            # Get job data
            job_data = self.redis_client.get_job(job_id)
            if not job_data:
                logger.warning(f"Job {job_id} not found")
                return

            repo_url = job_data["repo_url"]
            logger.info(f"Processing job {job_id} for repository {repo_url}")

            # Update job status to running
            self.update_job_status(job_id, ScanStatus.RUNNING)

            # Run scan
            try:
                results = self.scan_service.scan_repository(repo_url)
                # Update job status to completed
                self.update_job_status(job_id, ScanStatus.COMPLETED, results=results)
                logger.info(f"Completed job {job_id} with score {results['score']}")
            except Exception as e:
                # Update job status to failed
                error_message = f"Error scanning repository: {str(e)}"
                self.update_job_status(job_id, ScanStatus.FAILED, error=error_message)
                logger.error(error_message)

        except Exception as e:
            logger.error(f"Error processing job {job_id}: {str(e)}")

    def run(self):
        """Run the worker loop"""
        logger.info("Starting scanner worker")

        while self.running:
            try:
                # Get next job from queue
                job_id = self.redis_client.get_next_job()

                if job_id:
                    logger.info(f"Got job {job_id} from queue")
                    self.process_job(job_id)
                else:
                    # No jobs, sleep for a bit
                    time.sleep(1)

            except Exception as e:
                logger.error(f"Error in worker loop: {str(e)}")
                time.sleep(5)  # Sleep longer on error


if __name__ == "__main__":
    worker = ScannerWorker()
    worker.run()
