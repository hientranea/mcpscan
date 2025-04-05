import os
import subprocess
import json
import logging
from typing import Dict, Any, List
from scanner.analyzers.base_analyzer import BaseAnalyzer
from shared.config import settings
from shared.utils.helpers import ensure_directory

logger = logging.getLogger(__name__)


class SemgrepAnalyzer(BaseAnalyzer):
    """Analyzer that uses Semgrep for static code analysis"""

    def __init__(self):
        self.rules_dir = settings.RULES_DIR
        ensure_directory(self.rules_dir)

    def analyze(self, working_dir: str) -> Dict[str, Any]:
        """Run Semgrep analysis on the repository"""
        results = {"results": [], "errors": []}

        # Get all YAML rule files
        rule_files = [
            os.path.join(self.rules_dir, f)
            for f in os.listdir(self.rules_dir)
            if f.endswith(".yml") or f.endswith(".yaml")
        ]

        if not rule_files:
            logger.warning("No Semgrep rule files found")
            return results

        # Run Semgrep with each rule file
        for rule_file in rule_files:
            try:
                logger.info(f"Running Semgrep with rule: {os.path.basename(rule_file)}")

                # Create a temporary file for the results
                temp_output = f"/tmp/semgrep_{os.path.basename(rule_file)}.json"

                # Run Semgrep
                subprocess.run(
                    [
                        "semgrep",
                        "--config",
                        rule_file,
                        working_dir,
                        "--json",
                        "-o",
                        temp_output,
                    ],
                    check=True,
                )

                # Read results
                try:
                    with open(temp_output, "r") as f:
                        rule_results = json.load(f)
                        # Add rule name to results
                        rule_name = os.path.basename(rule_file).replace(".yml", "")
                        for result in rule_results.get("results", []):
                            result["rule_name"] = rule_name
                            results["results"].append(result)
                except Exception as e:
                    logger.error(f"Error reading Semgrep results: {str(e)}")
                    results["errors"].append(
                        f"Failed to read results for rule {rule_file}: {str(e)}"
                    )

                # Clean up
                if os.path.exists(temp_output):
                    os.remove(temp_output)

            except subprocess.CalledProcessError as e:
                logger.error(f"Semgrep execution failed for rule {rule_file}: {str(e)}")
                results["errors"].append(
                    f"Semgrep execution failed for rule {rule_file}: {str(e)}"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error running Semgrep with rule {rule_file}: {str(e)}"
                )
                results["errors"].append(
                    f"Unexpected error for rule {rule_file}: {str(e)}"
                )

        return results
