import os
import subprocess
import json
import logging
from typing import Dict, Any, List, Optional
from scanner.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class PackageAnalyzer(BaseAnalyzer):
    """Analyzer for package dependencies"""

    def detect_project_type(self, working_dir: str) -> List[str]:
        """
        Detect project types in the repository

        Returns:
            List of detected project types ('npm', 'pip', etc.)
        """
        project_types = []

        # Python project indicators
        python_files = [
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "Pipfile",
            "setup.cfg",
        ]

        # JavaScript/Node.js project indicators
        js_files = [
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "npm-shrinkwrap.json",
        ]

        # Check for Python projects
        for file in python_files:
            if os.path.exists(os.path.join(working_dir, file)):
                project_types.append("pip")
                break

        # Check for JavaScript projects
        for file in js_files:
            if os.path.exists(os.path.join(working_dir, file)):
                project_types.append("npm")
                break

        return project_types

    def analyze_npm(self, working_dir: str) -> Dict[str, Any]:
        """Analyze npm dependencies"""
        results = {"vulnerabilities": {}}

        try:
            # Run npm audit
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=working_dir,
                capture_output=True,
                text=True,
                check=False,  # Don't raise exception on non-zero exit code
            )

            # npm audit returns non-zero if vulnerabilities are found
            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)

                    # Extract vulnerabilities by severity
                    vulnerabilities = {}
                    if "vulnerabilities" in audit_data:
                        for name, vuln in audit_data["vulnerabilities"].items():
                            severity = vuln.get("severity", "unknown")
                            if severity not in vulnerabilities:
                                vulnerabilities[severity] = []

                            vulnerabilities[severity].append(
                                {
                                    "name": name,
                                    "version": vuln.get("version", "unknown"),
                                    "severity": severity,
                                    "via": vuln.get("via", []),
                                    "effects": vuln.get("effects", []),
                                    "range": vuln.get("range", "unknown"),
                                    "nodes": vuln.get("nodes", []),
                                    "fixAvailable": vuln.get("fixAvailable", False),
                                }
                            )

                    results["vulnerabilities"] = vulnerabilities
                    results["metadata"] = audit_data.get("metadata", {})

                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing npm audit output: {str(e)}")
                    results["error"] = f"Error parsing npm audit output: {str(e)}"
            else:
                results["error"] = result.stderr

        except Exception as e:
            logger.error(f"Error running npm audit: {str(e)}")
            results["error"] = f"Error running npm audit: {str(e)}"

        return results

    def analyze_pip(self, working_dir: str) -> Dict[str, Any]:
        """Analyze pip dependencies"""
        results = {"vulnerabilities": []}

        try:
            # Ensure pip-audit is installed
            subprocess.run(
                ["pip", "install", "pip-audit"], capture_output=True, check=True
            )

            # Run pip-audit
            result = subprocess.run(
                ["pip-audit", "--format", "json"],
                cwd=working_dir,
                capture_output=True,
                text=True,
                check=False,  # Don't raise exception on non-zero exit code
            )

            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)

                    # Extract vulnerabilities
                    for vuln in audit_data:
                        if "vulnerabilities" in vuln:
                            for v in vuln["vulnerabilities"]:
                                results["vulnerabilities"].append(
                                    {
                                        "name": vuln.get("name", "unknown"),
                                        "version": vuln.get("version", "unknown"),
                                        "id": v.get("id", "unknown"),
                                        "description": v.get("description", ""),
                                        "fix_versions": v.get("fix_versions", []),
                                        "aliases": v.get("aliases", []),
                                    }
                                )

                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing pip-audit output: {str(e)}")
                    results["error"] = f"Error parsing pip-audit output: {str(e)}"
            else:
                results["error"] = result.stderr

        except Exception as e:
            logger.error(f"Error running pip-audit: {str(e)}")
            results["error"] = f"Error running pip-audit: {str(e)}"

        return results

    def analyze(self, working_dir: str) -> Dict[str, Any]:
        """Analyze dependencies in the repository"""
        results = {}

        # Detect project types
        project_types = self.detect_project_type(working_dir)
        logger.info(f"Detected project types: {project_types}")

        # Run appropriate analyzers
        if "npm" in project_types:
            logger.info("Running npm dependency analysis")
            results["npm"] = self.analyze_npm(working_dir)

        if "pip" in project_types:
            logger.info("Running pip dependency analysis")
            results["pip"] = self.analyze_pip(working_dir)

        return results
