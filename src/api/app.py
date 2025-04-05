from flask import Flask, request, jsonify
import os
import uuid
import threading
import json
import subprocess
from datetime import datetime

app = Flask(__name__)

# In-memory storage for scan results (could be replaced with Redis/DB in production)
scan_jobs = {}


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.json
    if not data or "repo_url" not in data:
        return jsonify({"error": "Missing repository URL"}), 400

    repo_url = data["repo_url"]

    # Generate unique job ID
    job_id = str(uuid.uuid4())

    # Store job info
    scan_jobs[job_id] = {
        "status": "queued",
        "repo_url": repo_url,
        "created_at": datetime.now().isoformat(),
        "results": None,
    }

    # Start scan in background thread
    threading.Thread(target=run_scan, args=(job_id, repo_url)).start()

    return jsonify(
        {
            "job_id": job_id,
            "status": "queued",
            "message": "Scan job queued successfully",
        }
    )


@app.route("/api/scan/<job_id>", methods=["GET"])
def get_scan_status(job_id):
    print(">>>>")
    print(scan_jobs)
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404

    job = scan_jobs[job_id]
    response = {
        "job_id": job_id,
        "status": job["status"],
        "repo_url": job["repo_url"],
        "created_at": job["created_at"],
    }

    # Include results if available
    if job["status"] == "completed" and job["results"]:
        response["results"] = job["results"]

    return jsonify(response)


def run_scan(job_id, repo_url):
    """Run the scan in a background process"""
    try:
        scan_jobs[job_id]["status"] = "running"

        # Run the existing scan script
        result = subprocess.run(
            ["python", "/app/run_all_repo.py", repo_url],
            capture_output=True,
            text=True,
            check=True,
        )

        # Process results and calculate score
        results = process_scan_results(repo_url)

        scan_jobs[job_id]["status"] = "completed"
        scan_jobs[job_id]["results"] = results
    except Exception as e:
        scan_jobs[job_id]["status"] = "failed"
        scan_jobs[job_id]["error"] = str(e)


def process_scan_results(repo_url):
    """Process scan results and calculate a simple score"""
    repo_name = repo_url.split("/")[-1]

    # Find the most recent combined result file
    combined_dir = "/app/results/combined"
    result_files = [f for f in os.listdir(combined_dir) if f.startswith(repo_name)]

    if not result_files:
        return {"error": "No scan results found"}

    # Get the most recent file
    latest_file = sorted(result_files)[-1]
    result_path = os.path.join(combined_dir, latest_file)

    try:
        with open(result_path, "r") as f:
            scan_data = json.load(f)

        # Simple scoring algorithm
        score = calculate_score(scan_data)

        return {"score": score, "summary": generate_summary(scan_data, score)}
    except Exception as e:
        return {"error": f"Error processing results: {str(e)}"}


def calculate_score(scan_data):
    """Calculate a simple security score from 0-100"""
    # Starting with a perfect score
    score = 100

    # Deduct points for semgrep findings
    if "semgrep" in scan_data:
        # Deduct 5 points per finding, up to 50 points
        semgrep_deduction = min(len(scan_data["semgrep"].get("results", [])) * 5, 50)
        score -= semgrep_deduction

    # Deduct points for dependency vulnerabilities
    if "package_scan" in scan_data:
        # For npm vulnerabilities
        if "npm" in scan_data["package_scan"]:
            npm_data = scan_data["package_scan"]["npm"]
            if "vulnerabilities" in npm_data:
                # Deduct based on severity
                vuln_count = sum(len(v) for k, v in npm_data["vulnerabilities"].items())
                npm_deduction = min(vuln_count * 3, 30)
                score -= npm_deduction

        # For pip vulnerabilities
        if "pip" in scan_data["package_scan"]:
            pip_data = scan_data["package_scan"]["pip"]
            if "vulnerabilities" in pip_data:
                # Simplified: deduct 3 points per vulnerability
                pip_deduction = min(len(pip_data["vulnerabilities"]) * 3, 30)
                score -= pip_deduction

    # Ensure score is between 0 and 100
    return max(0, min(score, 100))


def generate_summary(scan_data, score):
    """Generate a human-readable summary of the scan results"""
    summary = {
        "score_explanation": "Score starts at 100 and deducts points for security issues",
        "findings": {},
    }

    # Count semgrep findings
    if "semgrep" in scan_data:
        semgrep_results = scan_data["semgrep"].get("results", [])
        summary["findings"]["code_issues"] = len(semgrep_results)

    # Count dependency vulnerabilities
    if "package_scan" in scan_data:
        vuln_count = 0

        # Count npm vulnerabilities
        if "npm" in scan_data["package_scan"]:
            npm_data = scan_data["package_scan"]["npm"]
            if "vulnerabilities" in npm_data:
                vuln_count += sum(
                    len(v) for k, v in npm_data["vulnerabilities"].items()
                )

        # Count pip vulnerabilities
        if "pip" in scan_data["package_scan"]:
            pip_data = scan_data["package_scan"]["pip"]
            if "vulnerabilities" in pip_data:
                vuln_count += len(pip_data["vulnerabilities"])

        summary["findings"]["dependency_vulnerabilities"] = vuln_count

    # Score interpretation
    if score >= 90:
        summary["risk_level"] = "Low"
    elif score >= 70:
        summary["risk_level"] = "Moderate"
    elif score >= 50:
        summary["risk_level"] = "High"
    else:
        summary["risk_level"] = "Critical"

    return summary


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
