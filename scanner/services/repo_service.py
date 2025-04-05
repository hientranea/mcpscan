import os
import shutil
import subprocess
import logging
from shared.config import settings
from shared.utils.helpers import clean_directory, get_repo_name

logger = logging.getLogger(__name__)


class RepoService:
    """Service for handling repository operations"""

    def __init__(self):
        self.working_dir = settings.WORKING_DIR

    def clone_repository(self, repo_url: str) -> str:
        """
        Clone a repository to the working directory

        Args:
            repo_url: URL of the repository to clone

        Returns:
            Path to the cloned repository directory
        """
        repo_name = get_repo_name(repo_url)
        repo_dir = os.path.join(self.working_dir, repo_name)

        # Clean working directory
        clean_directory(repo_dir)

        try:
            logger.info(f"Cloning repository: {repo_url}")
            # Clone with depth=1 to speed up cloning
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, repo_dir],
                check=True,
                capture_output=True,
            )
            logger.info(f"Repository cloned successfully to {repo_dir}")
            return repo_dir
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clone repository: {e.stderr.decode()}")
            raise RuntimeError(f"Failed to clone repository: {e.stderr.decode()}")
        except Exception as e:
            logger.error(f"Unexpected error cloning repository: {str(e)}")
            raise

    def cleanup(self, repo_dir: str = None):
        """
        Clean up repository directory

        Args:
            repo_dir: Directory to clean up. If None, clean the entire working directory.
        """
        try:
            if repo_dir and os.path.exists(repo_dir):
                logger.info(f"Cleaning up repository directory: {repo_dir}")
                shutil.rmtree(repo_dir)
            elif not repo_dir:
                logger.info(f"Cleaning up working directory: {self.working_dir}")
                clean_directory(self.working_dir)
        except Exception as e:
            logger.error(f"Error cleaning up repository: {str(e)}")
