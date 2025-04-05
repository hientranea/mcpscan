import logging
from typing import Dict, Any
from shared.models import RiskLevel

logger = logging.getLogger(__name__)


class ScoreService:
    """Service for calculating trust scores"""

    def calculate_score(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate a trust score based on scan results

        Args:
            scan_results: Combined scan results

        Returns:
            Dict containing score and summary
        """
        # Starting with a perfect score
        score = 100
        findings = {}

        # Process Semgrep findings
        if "semgrep" in scan_results and "results" in scan_results["semgrep"]:
            semgrep_results = scan_results["semgrep"]["results"]
            semgrep_count = len(semgrep_results)

            # Deduct points for semgrep findings
            # Deduct 5 points per finding, up to 50 points
            semgrep_deduction = min(semgrep_count * 5, 50)
            score -= semgrep_deduction

            findings["code_issues"] = semgrep_count
            logger.info(
                f"Found {semgrep_count} code issues, deducting {semgrep_deduction} points"
            )

        # Process package vulnerabilities
        if "package_scan" in scan_results:
            package_scan = scan_results["package_scan"]
            vuln_count = 0

            # Process npm vulnerabilities
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

                # Cap npm deduction at 30 points
                npm_deduction = min(npm_deduction, 30)
                score -= npm_deduction
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
                logger.info(
                    f"Found {pip_count} pip vulnerabilities, deducting {pip_deduction} points"
                )

            findings["dependency_vulnerabilities"] = vuln_count

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

        # Create summary
        summary = {
            "score_explanation": "Score starts at 100 and deducts points for security issues",
            "findings": findings,
            "risk_level": risk_level,
        }

        logger.info(f"Calculated trust score: {score}, risk level: {risk_level}")

        return {"score": score, "summary": summary}
