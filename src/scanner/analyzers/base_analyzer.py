from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseAnalyzer(ABC):
    """Base class for all analyzers"""

    @abstractmethod
    def analyze(self, working_dir: str) -> Dict[str, Any]:
        """
        Analyze the content of the working directory

        Args:
            working_dir: Path to the directory containing the cloned repository

        Returns:
            Dict containing analysis results
        """
        pass
