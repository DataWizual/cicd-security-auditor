#!/usr/bin/env python3
"""
CI/CD Security Auditor - API Version
REST API for running security audits on repositories
"""

import os
import sys

# Fix import path for src/ directory
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

import json
import yaml
import tempfile
import subprocess
import shutil
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import uuid

# Add path to main module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from main import CICDSecurityAuditor

    AUDITOR_AVAILABLE = True
except ImportError:
    AUDITOR_AVAILABLE = False
    print("⚠️  Main auditor module not found")

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global storage for audit results (in production, use a database)
audit_results = {}
audit_queue = []


class AuditJob:
    """Represents an audit job in the queue"""

    def __init__(self, repo_url, mode="full", config=None):
        self.id = str(uuid.uuid4())
        self.repo_url = repo_url
        self.mode = mode
        self.config = config or {}
        self.status = "queued"
        self.progress = 0
        self.result = None
        self.error = None
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None

    def to_dict(self):
        """Convert job to dictionary"""
        return {
            "id": self.id,
            "repo_url": self.repo_url,
            "mode": self.mode,
            "status": self.status,
            "progress": self.progress,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "error": self.error,
        }


def clone_repository(repo_url, temp_dir):
    """Clone repository to temporary directory"""
    try:
        print(f"   📥 Cloning {repo_url}...")

        # Handle both HTTPS and SSH URLs
        if repo_url.startswith("git@"):
            # SSH URL
            cmd = ["git", "clone", "--depth", "1", repo_url, temp_dir]
        else:
            # HTTPS URL
            cmd = ["git", "clone", "--depth", "1", repo_url, temp_dir]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            print(f"   ❌ Clone failed: {result.stderr}")
            return False

        print(f"   ✅ Cloned to {temp_dir}")
        return True

    except subprocess.TimeoutExpired:
        print("   ⏱️  Clone timeout")
        return False
    except Exception as e:
        print(f"   ❌ Clone error: {e}")
        return False


def run_audit_job(job):
    """Run audit for a job (worker function)"""
    try:
        job.status = "running"
        job.started_at = datetime.now()
        job.progress = 10

        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix=f"audit_{job.id}_")
        print(f"🔧 Processing job {job.id}: {job.repo_url}")

        # Clone repository
        job.progress = 20
        if not clone_repository(job.repo_url, temp_dir):
            job.status = "failed"
            job.error = "Failed to clone repository"
            job.completed_at = datetime.now()
            return

        # Run audit
        job.progress = 50
        try:
            auditor = CICDSecurityAuditor(temp_dir)

            # Apply mode configuration
            if job.mode == "quick":
                auditor.config["checks"] = {
                    "secrets": True,
                    "iac": False,
                    "containers": False,
                    "cicd_configs": False,
                    "dependencies": False,
                    "git_history": False,
                }
            elif job.mode == "secrets":
                auditor.config["checks"] = {
                    "secrets": True,
                    "iac": False,
                    "containers": False,
                    "cicd_configs": False,
                    "dependencies": False,
                    "git_history": True,
                }
            elif job.mode == "deps":
                auditor.config["checks"] = {
                    "secrets": False,
                    "iac": True,
                    "containers": True,
                    "cicd_configs": False,
                    "dependencies": True,
                    "git_history": False,
                }
            elif job.mode == "cicd":
                auditor.config["checks"] = {
                    "secrets": False,
                    "iac": False,
                    "containers": False,
                    "cicd_configs": True,
                    "dependencies": False,
                    "git_history": False,
                }

            # Run audit
            job.progress = 70
            results = auditor.run_full_audit()

            # Store results
            job.result = {
                "id": job.id,
                "repo_url": job.repo_url,
                "mode": job.mode,
                "stats": results.get("stats", {}),
                "risk_score": results.get("risk_score", 0),
                "findings_count": len(results.get("findings", [])),
                "report_path": results.get("reports", {}).get("output_dir"),
                "timestamp": datetime.now().isoformat(),
            }

            # Save detailed findings
            report_dir = Path(results.get("reports", {}).get("output_dir", "."))
            if report_dir.exists():
                # Copy reports to job-specific directory
                job_dir = Path(f"./audit_results/{job.id}")
                job_dir.mkdir(parents=True, exist_ok=True)

                # Copy report files
                for report_file in report_dir.glob("*"):
                    if report_file.is_file():
                        shutil.copy(report_file, job_dir)

                job.result["reports_available"] = True
                job.result["report_files"] = [f.name for f in job_dir.glob("*")]
            else:
                job.result["reports_available"] = False

            job.status = "completed"
            job.progress = 100

        except Exception as e:
            job.status = "failed"
            job.error = f"Audit error: {str(e)}"
            print(f"❌ Audit error for job {job.id}: {e}")

        # Clean up
        job.progress = 90
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass

        job.completed_at = datetime.now()
        print(f"✅ Completed job {job.id}")

    except Exception as e:
        job.status = "failed"
        job.error = f"Job processing error: {str(e)}"
        job.completed_at = datetime.now()
        print(f"❌ Job {job.id} failed: {e}")


def worker_thread():
    """Background worker to process audit jobs"""
    while True:
        if audit_queue:
            job = audit_queue.pop(0)
            run_audit_job(job)
            audit_results[job.id] = job
        else:
            # Sleep for a bit if queue is empty
            import time

            time.sleep(1)


# Start worker thread
worker = threading.Thread(target=worker_thread, daemon=True)
worker.start()


@app.route("/")
def index():
    """API root endpoint"""
    return jsonify(
        {
            "service": "CI/CD Security Auditor API",
            "version": "1.0.0",
            "endpoints": {
                "health": "/health",
                "audit": "/audit",
                "status": "/status/<job_id>",
                "result": "/result/<job_id>",
                "report": "/report/<job_id>/<filename>",
                "queue": "/queue",
            },
        }
    )


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "queue_length": len(audit_queue),
            "auditor_available": AUDITOR_AVAILABLE,
        }
    )


@app.route("/audit", methods=["POST"])
def start_audit():
    """Start a new audit job"""
    if not AUDITOR_AVAILABLE:
        return (
            jsonify({"error": "Auditor module not available", "status": "error"}),
            503,
        )

    data = request.get_json()

    if not data or "repo_url" not in data:
        return (
            jsonify({"error": "Missing 'repo_url' in request body", "status": "error"}),
            400,
        )

    repo_url = data.get("repo_url")
    mode = data.get("mode", "full")
    config = data.get("config", {})

    # Validate mode
    valid_modes = ["full", "quick", "secrets", "deps", "cicd", "git"]
    if mode not in valid_modes:
        return (
            jsonify(
                {
                    "error": f"Invalid mode. Must be one of: {', '.join(valid_modes)}",
                    "status": "error",
                }
            ),
            400,
        )

    # Create job
    job = AuditJob(repo_url, mode, config)
    audit_queue.append(job)

    print(f"📋 New audit job queued: {job.id} for {repo_url}")

    return (
        jsonify(
            {
                "status": "queued",
                "job_id": job.id,
                "message": f"Audit job created and queued. Check status at /status/{job.id}",
            }
        ),
        202,
    )


@app.route("/status/<job_id>", methods=["GET"])
def get_status(job_id):
    """Get status of an audit job"""
    if job_id in audit_results:
        job = audit_results[job_id]
        response = job.to_dict()

        # Add result summary if completed
        if job.status == "completed" and job.result:
            response["result"] = {
                "risk_score": job.result.get("risk_score"),
                "findings_count": job.result.get("findings_count"),
                "reports_available": job.result.get("reports_available", False),
            }

        return jsonify(response)
    else:
        # Check if job is still in queue
        for job in audit_queue:
            if job.id == job_id:
                return jsonify(job.to_dict())

        return jsonify({"error": "Job not found", "status": "error"}), 404


@app.route("/result/<job_id>", methods=["GET"])
def get_result(job_id):
    """Get detailed audit results"""
    if job_id not in audit_results:
        return jsonify({"error": "Job not found", "status": "error"}), 404

    job = audit_results[job_id]

    if job.status != "completed":
        return (
            jsonify(
                {
                    "error": "Job not completed yet",
                    "status": job.status,
                    "progress": job.progress,
                }
            ),
            202,
        )

    if not job.result:
        return jsonify({"error": "No result available", "status": "error"}), 404

    return jsonify(job.result)


@app.route("/report/<job_id>/<filename>", methods=["GET"])
def get_report(job_id, filename):
    """Download a report file"""
    if job_id not in audit_results:
        return jsonify({"error": "Job not found", "status": "error"}), 404

    job = audit_results[job_id]

    if job.status != "completed":
        return jsonify({"error": "Job not completed yet", "status": "error"}), 404

    # Check if report exists
    report_path = Path(f"./audit_results/{job_id}/{filename}")
    if not report_path.exists():
        return jsonify({"error": "Report file not found", "status": "error"}), 404

    # Return file
    return send_file(str(report_path), as_attachment=True, download_name=filename)


@app.route("/queue", methods=["GET"])
def get_queue():
    """Get current audit queue"""
    queue_info = []
    for job in audit_queue:
        queue_info.append(
            {
                "id": job.id,
                "repo_url": job.repo_url,
                "mode": job.mode,
                "status": job.status,
                "progress": job.progress,
                "queued_since": job.created_at.isoformat(),
            }
        )

    completed_info = []
    for job_id, job in audit_results.items():
        if job.status == "completed":
            completed_info.append(
                {
                    "id": job.id,
                    "repo_url": job.repo_url,
                    "mode": job.mode,
                    "completed_at": (
                        job.completed_at.isoformat() if job.completed_at else None
                    ),
                    "risk_score": job.result.get("risk_score") if job.result else None,
                }
            )

    return jsonify(
        {
            "queue": queue_info,
            "completed_recently": completed_info[-10:],  # Last 10 completed jobs
            "stats": {
                "queued": len(audit_queue),
                "completed": len(
                    [j for j in audit_results.values() if j.status == "completed"]
                ),
                "failed": len(
                    [j for j in audit_results.values() if j.status == "failed"]
                ),
            },
        }
    )


@app.route("/config", methods=["GET"])
def get_config():
    """Get default configuration"""
    default_config = {
        "scan_depth": "deep",
        "checks": {
            "secrets": True,
            "iac": True,
            "containers": True,
            "cicd_configs": True,
            "dependencies": True,
            "git_history": True,
        },
        "risk_threshold": "medium",
        "report_format": ["html", "txt"],
    }

    return jsonify(
        {
            "default_config": default_config,
            "available_modes": [
                {
                    "id": "full",
                    "name": "Full Audit",
                    "description": "Complete security scan",
                },
                {
                    "id": "quick",
                    "name": "Quick Scan",
                    "description": "Fast scan for secrets only",
                },
                {
                    "id": "secrets",
                    "name": "Secret Scan",
                    "description": "Only secret detection",
                },
                {
                    "id": "deps",
                    "name": "Dependencies",
                    "description": "Only dependency analysis",
                },
                {
                    "id": "cicd",
                    "name": "CI/CD Configs",
                    "description": "Only CI/CD configuration analysis",
                },
                {
                    "id": "git",
                    "name": "Git History",
                    "description": "Only Git history scanning",
                },
            ],
        }
    )


if __name__ == "__main__":
    # Create directories
    Path("./audit_results").mkdir(exist_ok=True)
    Path("./reports").mkdir(exist_ok=True)

    print("🚀 Starting CI/CD Security Auditor API...")
    print(f"📡 API running on http://localhost:5000")
    print(f"📋 Endpoints:")
    print(f"   GET  /           - API information")
    print(f"   GET  /health     - Health check")
    print(f"   POST /audit      - Start new audit")
    print(f"   GET  /status/<id> - Get job status")
    print(f"   GET  /result/<id> - Get audit results")
    print(f"   GET  /queue      - View audit queue")

    app.run(host="0.0.0.0", port=5000, debug=False)
