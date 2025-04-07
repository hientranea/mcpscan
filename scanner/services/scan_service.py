import os
import json
import logging
from typing import Dict, Any
from datetime import datetime
from scanner.analyzers.semgrep_analyzer import SemgrepAnalyzer
from scanner.analyzers.package_analyzer import PackageAnalyzer
from scanner.services.repo_service import RepoService
from scanner.services.score_service import ScoreService
from shared.config import settings
from shared.utils.helpers import ensure_directory, get_repo_name

logger = logging.getLogger(__name__)


class ScanService:
    """Service for scanning repositories"""

    def __init__(self):
        self.repo_service = RepoService()
        self.semgrep_analyzer = SemgrepAnalyzer()
        self.package_analyzer = PackageAnalyzer()
        self.score_service = ScoreService()

        # Ensure results directories exist
        ensure_directory(settings.RESULTS_DIR)
        ensure_directory(settings.COMBINED_DIR)

    def scan_repository(self, repo_url: str) -> Dict[str, Any]:
        """
        Scan a repository and return results

        Args:
            repo_url: URL of the repository to scan

        Returns:
            Dict containing scan results and score
        """
        repo_dir = None
        try:
            # Clone repository
            repo_dir = self.repo_service.clone_repository(repo_url)
            repo_name = get_repo_name(repo_url)

            # Run analyzers
            logger.info(f"Running Semgrep analyzer on {repo_name}")
            semgrep_results = self.semgrep_analyzer.analyze(repo_dir)

            logger.info(f"Running package analyzer on {repo_name}")
            package_results = self.package_analyzer.analyze(repo_dir)

            # Combine results
            combined_results = {
                "semgrep": semgrep_results,
                "package_scan": package_results,
                "repo_url": repo_url,
                "repo_name": repo_name,
                "scan_time": datetime.utcnow().isoformat(),
            }

            # Save combined results
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            result_file = os.path.join(
                settings.COMBINED_DIR, f"{repo_name}_{timestamp}.json"
            )

            with open(result_file, "w") as f:
                json.dump(combined_results, f, indent=2)

            logger.info(f"Saved combined results to {result_file}")

            # Calculate score
            score_data = self.score_service.calculate_score(
                combined_results, working_dir=repo_dir
            )

            # Return results with score
            return {
                "score": score_data["score"],
                "summary": score_data["summary"],
                "raw_results": combined_results,
            }

        except Exception as e:
            logger.error(f"Error scanning repository: {str(e)}")
            raise
        finally:
            # Clean up repository directory
            if repo_dir and os.path.exists(repo_dir):
                self.repo_service.cleanup(repo_dir)
