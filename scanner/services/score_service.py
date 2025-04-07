import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from shared.models import RiskLevel

logger = logging.getLogger(__name__)


class ScoreService:
    """Service for calculating trust scores with enhanced features"""

    def __init__(self):
        # Define severity weights for semgrep findings
        self.severity_weights = {
            "ERROR": 8,
            "WARNING": 4,
            "INFO": 1,
            # Default weight for unknown severities
            "DEFAULT": 3,
        }

        # Define impact categories and their weights
        self.impact_categories = {
            "rce": 10,  # Remote Code Execution
            "injection": 8,  # Command/SQL Injection
            "sensitive_data": 6,  # Sensitive Data Exposure
            "insecure_config": 4,  # Insecure Configurations
            "other": 2,  # Other/Unknown issues
        }

        # Map semgrep rule IDs to impact categories
        self.rule_impact_map = {
            # RCE category
            "dangerous-eval": "rce",
            "dangerous-exec": "rce",
            "dangerous-pickle": "rce",
            "dangerous-yaml-load": "rce",
            "js-eval-with-encoded-data": "rce",
            # Injection category
            "system-command-execution": "injection",
            "subprocess-shell-injection": "injection",
            "js-exec-command": "injection",
            "dangerous-shell-true": "injection",
            # Sensitive data category
            "hardcoded-http-url": "sensitive_data",
            "dangerous-file-access": "sensitive_data",
            "path-traversal": "sensitive_data",
            "fs-module-path-traversal": "sensitive_data",
            # Insecure config category
            "insecure-requests": "insecure_config",
            "insecure-urllib3": "insecure_config",
            # Obfuscation (could be suspicious)
            "base64-decode": "other",
            "encoded-commands": "other",
        }

    def _categorize_semgrep_findings(
        self, semgrep_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Categorize semgrep findings by impact and severity

        Args:
            semgrep_results: List of semgrep findings

        Returns:
            Dict with categorized findings and statistics
        """
        impact_counts = {category: 0 for category in self.impact_categories.keys()}
        severity_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}

        for result in semgrep_results:
            # Get rule ID and determine its impact category
            rule_id = result.get("check_id", "")
            impact = self.rule_impact_map.get(rule_id, "other")
            impact_counts[impact] += 1

            # Count by severity
            severity = result.get("extra", {}).get("severity", "WARNING").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Calculate deductions by impact category
        impact_deductions = {
            category: count * self.impact_categories[category]
            for category, count in impact_counts.items()
        }

        # Calculate deductions by severity
        severity_deductions = {
            severity: count
            * self.severity_weights.get(severity, self.severity_weights["DEFAULT"])
            for severity, count in severity_counts.items()
        }

        total_impact_deduction = sum(impact_deductions.values())
        total_severity_deduction = sum(severity_deductions.values())

        # Use the average of both approaches, capped at 50
        semgrep_deduction = min(
            (total_impact_deduction + total_severity_deduction) / 2, 50
        )

        return {
            "impact_counts": impact_counts,
            "severity_counts": severity_counts,
            "impact_deductions": impact_deductions,
            "severity_deductions": severity_deductions,
            "total_deduction": semgrep_deduction,
        }

    def _calculate_positive_factors(
        self, working_dir: Optional[str], repo_url: str
    ) -> Dict[str, Any]:
        """
        Calculate positive factors that can improve the score

        Args:
            working_dir: Path to the repository (if available)
            repo_url: URL of the repository

        Returns:
            Dict with positive factors and their values
        """
        positive_factors = {}
        total_bonus = 0

        # Check for security policy file (if working_dir is available)
        if working_dir:
            import os

            # Check for security policy
            security_files = [
                "SECURITY.md",
                ".github/SECURITY.md",
                "docs/SECURITY.md",
                "security.md",
            ]
            has_security_policy = any(
                os.path.exists(os.path.join(working_dir, file))
                for file in security_files
            )
            if has_security_policy:
                positive_factors["security_policy"] = 5
                total_bonus += 5

            # Check for automated tests
            test_directories = ["test", "tests", "__tests__", "spec", "cypress"]
            has_tests = any(
                os.path.isdir(os.path.join(working_dir, dir))
                for dir in test_directories
            )
            if has_tests:
                positive_factors["automated_tests"] = 5
                total_bonus += 5

            # Check for dependency pinning
            has_dependency_pinning = False
            dep_files = [
                "package-lock.json",
                "yarn.lock",
                "Pipfile.lock",
                "poetry.lock",
                "pnpm-lock.yaml",
            ]
            if any(
                os.path.exists(os.path.join(working_dir, file)) for file in dep_files
            ):
                has_dependency_pinning = True
                positive_factors["dependency_pinning"] = 3
                total_bonus += 3

        return {"factors": positive_factors, "total_bonus": total_bonus}

    def _get_previous_scan_data(self, repo_url: str) -> Dict[str, Any]:
        """
        Get data from previous scans of the same repository

        Args:
            repo_url: URL of the repository

        Returns:
            Dict with previous scan data or empty dict if no previous scan
        """
        # This would typically query the database for previous scan results
        # For now, we'll return a placeholder
        return {
            "has_previous_scan": False,
            "previous_score": None,
            "previous_date": None,
        }

    def calculate_score(
        self, scan_results: Dict[str, Any], working_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Calculate a trust score based on scan results with enhanced features

        Args:
            scan_results: Combined scan results
            working_dir: Path to the repository (if available)

        Returns:
            Dict containing score, summary, and detailed breakdown
        """
        # Starting with a perfect score
        score = 100
        findings = {}
        score_components = {}

        # Process Semgrep findings
        if "semgrep" in scan_results and "results" in scan_results["semgrep"]:
            semgrep_results = scan_results["semgrep"]["results"]
            semgrep_count = len(semgrep_results)

            if semgrep_count > 0:
                # Use enhanced categorization and scoring
                semgrep_analysis = self._categorize_semgrep_findings(semgrep_results)
                semgrep_deduction = semgrep_analysis["total_deduction"]

                score -= semgrep_deduction
                findings["code_issues"] = semgrep_count

                # Add detailed breakdown to score components
                score_components["semgrep"] = {
                    "deduction": semgrep_deduction,
                    "findings_count": semgrep_count,
                    "by_severity": semgrep_analysis["severity_counts"],
                    "by_impact": semgrep_analysis["impact_counts"],
                }

                logger.info(
                    f"Found {semgrep_count} code issues, deducting {semgrep_deduction:.2f} points"
                )

        # Process package vulnerabilities (similar to original implementation)
        if "package_scan" in scan_results:
            package_scan = scan_results["package_scan"]
            vuln_count = 0

            # Process npm vulnerabilities
            npm_severity_counts = {}
            if "npm" in package_scan and "vulnerabilities" in package_scan["npm"]:
                npm_vulns = package_scan["npm"]["vulnerabilities"]

                # Weight by severity
                severity_weights = {"critical": 10, "high": 6, "moderate": 3, "low": 1}

                npm_deduction = 0
                for severity, vulns in npm_vulns.items():
                    weight = severity_weights.get(severity.lower(), 1)
                    count = len(vulns)
                    vuln_count += count
                    npm_deduction += count * weight
                    npm_severity_counts[severity] = count

                # Cap npm deduction at 30 points
                npm_deduction = min(npm_deduction, 30)
                score -= npm_deduction

                score_components["npm_vulnerabilities"] = {
                    "deduction": npm_deduction,
                    "findings_count": vuln_count,
                    "by_severity": npm_severity_counts,
                }

                logger.info(
                    f"Found {vuln_count} npm vulnerabilities, deducting {npm_deduction} points"
                )

            # Process pip vulnerabilities
            if "pip" in package_scan and "vulnerabilities" in package_scan["pip"]:
                pip_vulns = package_scan["pip"]["vulnerabilities"]
                pip_count = len(pip_vulns)
                vuln_count += pip_count

                # Deduct 3 points per vulnerability, up to 30 points
                pip_deduction = min(pip_count * 3, 30)
                score -= pip_deduction

                score_components["pip_vulnerabilities"] = {
                    "deduction": pip_deduction,
                    "findings_count": pip_count,
                }

                logger.info(
                    f"Found {pip_count} pip vulnerabilities, deducting {pip_deduction} points"
                )

            findings["dependency_vulnerabilities"] = vuln_count

        # Add positive factors if working directory is available
        repo_url = scan_results.get("repo_url", "")
        positive_factors = self._calculate_positive_factors(working_dir, repo_url)

        if positive_factors["total_bonus"] > 0:
            score += positive_factors["total_bonus"]
            score_components["positive_factors"] = positive_factors["factors"]
            logger.info(
                f"Added {positive_factors['total_bonus']} points for positive factors"
            )

        # Get previous scan data for trend analysis
        previous_scan = self._get_previous_scan_data(repo_url)

        # Ensure score is between 0 and 100
        score = max(0, min(score, 100))

        # Determine risk level
        risk_level = RiskLevel.LOW
        if score < 50:
            risk_level = RiskLevel.CRITICAL
        elif score < 70:
            risk_level = RiskLevel.HIGH
        elif score < 90:
            risk_level = RiskLevel.MODERATE

        # Create enhanced summary
        summary = {
            "score_explanation": "Score starts at 100, deducts points for security issues, and adds points for security best practices",
            "findings": findings,
            "risk_level": risk_level,
            "score_components": score_components,
        }

        # Add trend information if available
        if previous_scan["has_previous_scan"]:
            summary["trend"] = {
                "previous_score": previous_scan["previous_score"],
                "previous_date": previous_scan["previous_date"],
                "change": score - previous_scan["previous_score"],
                "improved": score > previous_scan["previous_score"],
            }

        # Generate recommendations based on findings
        recommendations = self._generate_recommendations(scan_results, score_components)
        if recommendations:
            summary["recommendations"] = recommendations

        logger.info(f"Calculated trust score: {score}, risk level: {risk_level}")

        return {"score": score, "summary": summary}

    def _generate_recommendations(
        self, scan_results: Dict[str, Any], score_components: Dict[str, Any]
    ) -> List[str]:
        """
        Generate recommendations based on findings

        Args:
            scan_results: Combined scan results
            score_components: Score breakdown by component

        Returns:
            List of recommendation strings
        """
        recommendations = []

        # Check for high-impact security issues
        if "semgrep" in score_components:
            semgrep_by_impact = score_components["semgrep"].get("by_impact", {})

            if semgrep_by_impact.get("rce", 0) > 0:
                recommendations.append(
                    "Fix code issues that could lead to remote code execution (RCE)"
                )

            if semgrep_by_impact.get("injection", 0) > 0:
                recommendations.append(
                    "Address command injection vulnerabilities in your code"
                )

            if semgrep_by_impact.get("sensitive_data", 0) > 0:
                recommendations.append(
                    "Review code that handles sensitive data or file access"
                )

        # Check for package vulnerabilities
        if (
            "npm_vulnerabilities" in score_components
            and score_components["npm_vulnerabilities"]["findings_count"] > 0
        ):
            recommendations.append(
                "Update npm dependencies to fix security vulnerabilities"
            )

        if (
            "pip_vulnerabilities" in score_components
            and score_components["pip_vulnerabilities"]["findings_count"] > 0
        ):
            recommendations.append(
                "Update Python dependencies to fix security vulnerabilities"
            )

        # Check for missing positive factors
        if (
            "positive_factors" not in score_components
            or "security_policy" not in score_components.get("positive_factors", {})
        ):
            recommendations.append(
                "Add a SECURITY.md file to document your security policy"
            )

        if (
            "positive_factors" not in score_components
            or "automated_tests" not in score_components.get("positive_factors", {})
        ):
            recommendations.append(
                "Implement automated tests to catch security issues early"
            )

        if (
            "positive_factors" not in score_components
            or "dependency_pinning" not in score_components.get("positive_factors", {})
        ):
            recommendations.append(
                "Pin your dependencies with lock files for better security"
            )

        return recommendations
