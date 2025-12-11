#!/usr/bin/env python3
"""
CI/CD Security Auditor - Enhanced Full Version
Automated security scanning for CI/CD pipelines, secrets, and dependencies
"""

import os
import sys
import json
import yaml
import tempfile
import subprocess
import concurrent.futures
import argparse
import re
from datetime import datetime
from pathlib import Path

# ==================== SCANNER CLASSES ====================


class AdvancedSecretScanner:
    """Multi-tool secret scanner using Gitleaks, TruffleHog, and detect-secrets"""

    def __init__(self, config):
        self.config = config
        self.tools = {
            "gitleaks": self._run_gitleaks,
            "trufflehog": self._run_trufflehog,
            "detect_secrets": self._run_detect_secrets,
        }

    def scan(self, repo_path):
        """Run all secret scanners in parallel"""
        print("   🔍 Running multi-scanner secret detection...")
        findings = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            # Run all tools in parallel
            future_to_tool = {
                executor.submit(tool_func, repo_path): tool_name
                for tool_name, tool_func in self.tools.items()
            }

            for future in concurrent.futures.as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    tool_findings = future.result(timeout=180)
                    print(f"      {tool_name}: found {len(tool_findings)}")
                    findings.extend(tool_findings)
                except Exception as e:
                    print(f"      {tool_name}: error - {e}")

        # Remove duplicates
        unique_findings = self._deduplicate_findings(findings)
        return unique_findings

    def _run_gitleaks(self, repo_path):
        """Run Gitleaks (fastest)"""
        findings = []
        try:
            cmd = [
                "gitleaks",
                "detect",
                "--source",
                str(repo_path),
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--verbose",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                encoding="utf-8",
                errors="ignore",
            )

            if result.stdout and "findings" in result.stdout:
                data = json.loads(result.stdout)
                for finding in data.get("findings", []):
                    findings.append(
                        {
                            "type": "secret_leak",
                            "risk": "critical",
                            "tool": "gitleaks",
                            "title": f'Secret detected: {finding.get("rule")}',
                            "description": f'Found in {finding.get("file")}, line {finding.get("startLine")}',
                            "file": finding.get("file"),
                            "line": finding.get("startLine"),
                            "secret": finding.get("secret"),
                            "remediation": "Immediately revoke and replace the secret",
                        }
                    )
        except (
            subprocess.TimeoutExpired,
            json.JSONDecodeError,
            FileNotFoundError,
        ) as e:
            print(f"      Gitleaks unavailable: {e}")

        return findings

    def _run_trufflehog(self, repo_path):
        """Run TruffleHog via Docker (deepest scan)"""
        findings = []
        try:
            cmd = [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{repo_path}:/pwd:ro",
                "trufflesecurity/trufflehog:latest",
                "git",
                "file:///pwd",
                "--json",
                "--only-verified",
                "--no-update",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                encoding="utf-8",
                errors="ignore",
            )

            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            findings.append(
                                {
                                    "type": "secret_leak",
                                    "risk": "critical",
                                    "tool": "trufflehog",
                                    "title": f'Verified secret: {data.get("DetectorName", "unknown")}',
                                    "description": "Verified secret leak",
                                    "file": data.get("SourceMetadata", {})
                                    .get("Data", {})
                                    .get("Git", {})
                                    .get("file", "unknown"),
                                    "line": data.get("SourceMetadata", {})
                                    .get("Data", {})
                                    .get("Git", {})
                                    .get("line", "unknown"),
                                    "secret": data.get("Raw", "hidden")[:50] + "...",
                                    "remediation": "URGENT: Revoke key immediately!",
                                }
                            )
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"      TruffleHog error: {e}")

        return findings

    def _run_detect_secrets(self, repo_path):
        """Run Yelp detect-secrets (Python-based)"""
        findings = []

        try:
            # Run scan directly to stdout
            cmd = [
                "detect-secrets",
                "scan",
                str(repo_path),
                "--no-baseline",  # Don't create baseline file
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                encoding="utf-8",
                errors="ignore",
            )

            # Parse JSON from stdout
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for file_path, secrets in data.get("results", {}).items():
                        for secret_data in secrets:
                            findings.append(
                                {
                                    "type": "secret_leak",
                                    "risk": "high",
                                    "tool": "detect-secrets",
                                    "title": f'Suspicious string: {secret_data.get("type")}',
                                    "description": f"High entropy or pattern detected",
                                    "file": file_path,
                                    "line": secret_data.get("line_number"),
                                    "secret": secret_data.get("secret", "")[:50]
                                    + "...",
                                    "remediation": "Check for actual secrets",
                                }
                            )
                except json.JSONDecodeError:
                    pass

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"      detect-secrets unavailable: {e}")

        return findings

    def _deduplicate_findings(self, findings):
        """Remove duplicates by file+line+secret"""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.get("file"), finding.get("line"), finding.get("secret")[:30])
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique


class DependencyAuditor:
    """Dependency vulnerability scanner"""

    def __init__(self, config):
        self.config = config
        self.vulnerability_sources = {
            "npm": self._audit_npm,
            "python": self._audit_python,
            "go": self._audit_go,
            "docker": self._audit_docker,
        }

    def scan(self, repo_path):
        """Scan dependency files for vulnerabilities"""
        print("   📦 Analyzing dependencies...")
        findings = []

        # Find dependency files
        dependency_files = {
            "npm": list(repo_path.glob("**/package.json")),
            "python": list(repo_path.glob("**/requirements.txt"))
            + list(repo_path.glob("**/pyproject.toml")),
            "go": list(repo_path.glob("**/go.mod")),
            "docker": list(repo_path.glob("**/Dockerfile")),
        }

        for lang, files in dependency_files.items():
            if files and lang in self.vulnerability_sources:
                try:
                    lang_findings = self.vulnerability_sources[lang](repo_path)
                    findings.extend(lang_findings)
                except Exception as e:
                    print(f"      Error checking {lang}: {e}")

        return findings

    def _audit_npm(self, repo_path):
        """Check npm dependencies via npm audit"""
        findings = []
        try:
            # Find package.json
            package_json = next(repo_path.glob("**/package.json"), None)
            if package_json:
                # Run npm audit
                cmd = ["npm", "audit", "--json"]
                result = subprocess.run(
                    cmd,
                    cwd=package_json.parent,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if result.stdout:
                    data = json.loads(result.stdout)
                    for _, advisory in data.get("advisories", {}).items():
                        findings.append(
                            {
                                "type": "dependency_vuln",
                                "risk": self._map_severity(
                                    advisory.get("severity", "low")
                                ),
                                "title": f'NPM vulnerability: {advisory.get("title", "")}',
                                "description": advisory.get("overview", "")[:200],
                                "package": advisory.get("module_name", ""),
                                "version": advisory.get("vulnerable_versions", ""),
                                "fix": advisory.get("recommendation", ""),
                                "remediation": f'Update {advisory.get("module_name")} to {advisory.get("patched_versions", "secure version")}',
                            }
                        )

        except Exception as e:
            print(f"      npm audit unavailable: {e}")

        return findings

    def _audit_python(self, repo_path):
        """Check Python dependencies via safety"""
        findings = []
        try:
            # Find requirements.txt
            req_file = next(repo_path.glob("**/requirements.txt"), None)
            if req_file:
                # Use safety (can be replaced with pip-audit)
                cmd = ["safety", "check", "-r", str(req_file), "--json"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                if result.stdout:
                    data = json.loads(result.stdout)
                    for vuln in data.get("vulnerabilities", []):
                        findings.append(
                            {
                                "type": "dependency_vuln",
                                "risk": self._map_severity(vuln.get("severity", "low")),
                                "title": f'Python vulnerability: {vuln.get("package_name", "")}',
                                "description": vuln.get("advisory", "")[:200],
                                "package": vuln.get("package_name", ""),
                                "version": vuln.get("analyzed_version", ""),
                                "fix": vuln.get("fixed_version", ""),
                                "remediation": f'Update {vuln.get("package_name")} to {vuln.get("fixed_version", "secure version")}',
                            }
                        )

        except Exception as e:
            print(f"      safety check unavailable: {e}")

        return findings

    def _audit_go(self, repo_path):
        """Check Go modules via govulncheck"""
        findings = []
        try:
            # Find go.mod
            go_mod = next(repo_path.glob("**/go.mod"), None)
            if go_mod:
                cmd = ["govulncheck", "./..."]
                result = subprocess.run(
                    cmd, cwd=go_mod.parent, capture_output=True, text=True, timeout=60
                )

                # Parse text output
                if result.stdout:
                    for line in result.stdout.split("\n"):
                        if "Vulnerability found" in line:
                            findings.append(
                                {
                                    "type": "dependency_vuln",
                                    "risk": "high",
                                    "title": f"Go vulnerability: {line}",
                                    "description": "Found in Go modules",
                                    "remediation": "Update dependencies via go get -u",
                                }
                            )

        except Exception as e:
            print(f"      govulncheck unavailable: {e}")

        return findings

    def _audit_docker(self, repo_path):
        """Check Dockerfile for outdated base images"""
        findings = []
        dockerfiles = list(repo_path.glob("**/Dockerfile"))

        for dockerfile in dockerfiles:
            try:
                content = dockerfile.read_text()
                lines = content.split("\n")

                for i, line in enumerate(lines, 1):
                    line_lower = line.lower()

                    # Check for outdated distributions
                    outdated_bases = [
                        "ubuntu:18.04",
                        "ubuntu:16.04",
                        "debian:9",
                        "debian:8",
                        "centos:7",
                        "centos:6",
                        "alpine:3.9",
                        "alpine:3.10",
                        ":latest",
                    ]

                    for base in outdated_bases:
                        if base in line_lower and "from" in line_lower:
                            findings.append(
                                {
                                    "type": "docker_vuln",
                                    "risk": "medium",
                                    "title": f"Outdated base image: {base}",
                                    "description": f"Used at line {i}",
                                    "file": str(dockerfile.relative_to(repo_path)),
                                    "line": i,
                                    "remediation": f"Update base image {base} to current version",
                                }
                            )
                            break

            except Exception as e:
                print(f"      Error reading Dockerfile: {e}")

        return findings

    def _map_severity(self, severity):
        """Map severity to risk levels"""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "moderate": "medium",
        }
        return mapping.get(severity.lower(), "low")


class CICDConfigDeepAnalyzer:
    """Deep analysis of CI/CD configurations"""

    def __init__(self, config):
        self.config = config
        self.workflow_patterns = {
            "hardcoded_secrets": [
                r'(?i)(password|token|secret|api[_-]?key|access[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'(?i)AWS_ACCESS_KEY_ID\s*[:=]\s*["\'][^"\']+["\']',
                r'(?i)AWS_SECRET_ACCESS_KEY\s*[:=]\s*["\'][^"\']+["\']',
                r'(?i)GH_TOKEN\s*[:=]\s*["\'][^"\']+["\']',
                r'(?i)DOCKER_PASSWORD\s*[:=]\s*["\'][^"\']+["\']',
            ],
            "dangerous_commands": [
                r"curl\s+.*\s*\|\s*(bash|sh|zsh)",
                r"wget\s+.*\s*\|\s*(bash|sh|zsh)",
                r"chmod\s+[0-9]{3,4}\s+",
                r"rm\s+-rf\s+/",
                r"mkfs\.|dd\s+if=",
                r"sudo\s+(apt|yum|dnf)\s+install",
            ],
            "excessive_permissions": [
                r"permissions:\s*(write|all)",
                r"GITHUB_TOKEN:\s*(write|all)",
                r"contents:\s*(write|all)",
                r"actions:\s*(write|all)",
                r"checks:\s*(write|all)",
            ],
            "insecure_patterns": [
                r"always()",
                r"continue-on-error:\s*true",
                r'script:\s*echo\s+"\$SECRET"',
                r"run:\s*.*\${{.*secrets.*}}.*\|",
            ],
        }

    def scan(self, repo_path):
        """Deep scan CI/CD configuration files"""
        print("   ⚙️  Deep CI/CD config analysis...")
        findings = []

        # Find all CI/CD files
        ci_patterns = [
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            ".travis.yml",
            "azure-pipelines.yml",
            "Jenkinsfile",
            "*.jenkinsfile",
        ]

        for pattern in ci_patterns:
            for file_path in repo_path.glob(pattern):
                if file_path.is_file():
                    file_findings = self._analyze_file(file_path, repo_path)
                    findings.extend(file_findings)

        return findings

    def _analyze_file(self, file_path, repo_path):
        """Analyze specific CI/CD file"""
        findings = []
        rel_path = file_path.relative_to(repo_path)

        try:
            content = file_path.read_text()
            lines = content.split("\n")

            # Check each pattern rule
            for pattern_type, patterns in self.workflow_patterns.items():
                for i, line in enumerate(lines, 1):
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            finding = self._create_finding(
                                pattern_type, line, i, rel_path
                            )
                            findings.append(finding)

            # Additional check: look for secret-like variables
            if self._has_potential_secret_vars(content):
                findings.append(
                    {
                        "type": "ci_config",
                        "risk": "high",
                        "title": f"Potential secrets in variables: {rel_path}",
                        "description": "Variables with secret-like names found",
                        "file": str(rel_path),
                        "remediation": "Use GitHub Secrets / GitLab CI Variables instead of hardcoding",
                    }
                )

        except Exception as e:
            print(f"      Error analyzing {rel_path}: {e}")

        return findings

    def _create_finding(self, pattern_type, line, line_num, rel_path):
        """Create finding based on pattern type"""
        risk_map = {
            "hardcoded_secrets": ("critical", "Hardcoded secret"),
            "dangerous_commands": ("high", "Dangerous command"),
            "excessive_permissions": ("medium", "Excessive permissions"),
            "insecure_patterns": ("medium", "Insecure pattern"),
        }

        risk, title_prefix = risk_map.get(pattern_type, ("medium", "Issue"))

        return {
            "type": "ci_config",
            "risk": risk,
            "title": f"{title_prefix} at line {line_num}",
            "description": f"Found in {rel_path}: {line.strip()[:100]}",
            "file": str(rel_path),
            "line": line_num,
            "remediation": self._get_remediation(pattern_type),
        }

    def _has_potential_secret_vars(self, content):
        """Check for variables with secret-like names"""
        secret_like_vars = [
            "PASS",
            "TOKEN",
            "SECRET",
            "KEY",
            "AUTH",
            "PRIVATE",
            "ACCESS",
            "CREDENTIAL",
            "API_KEY",
            "AWS_",
            "GITHUB_",
            "DOCKER_",
            "DATABASE_",
        ]

        lines = content.split("\n")
        for line in lines:
            if any(var in line.upper() for var in secret_like_vars):
                if ":" in line or "=" in line:
                    # Check it's not a comment
                    if not line.strip().startswith("#"):
                        return True
        return False

    def _get_remediation(self, pattern_type):
        """Get remediation advice"""
        remediations = {
            "hardcoded_secrets": "Use GitHub Secrets, GitLab CI Variables, or external secret stores",
            "dangerous_commands": "Replace with safer alternatives. Always verify sources.",
            "excessive_permissions": "Apply principle of least privilege. Use read-only tokens.",
            "insecure_patterns": "Review and secure the CI/CD pipeline configuration",
        }
        return remediations.get(pattern_type, "Fix the configuration")


class GitHistoryScanner:
    """Git history scanner for secrets"""

    def __init__(self, config):
        self.config = config
        # Precise patterns (only real secrets)
        self.patterns = {
            # AWS
            r"(?i)AKIA[0-9A-Z]{16}": "AWS Access Key ID",
            r"(?i)ASIA[0-9A-Z]{16}": "AWS Temporary Access Key",
            # GitHub
            r"(?i)gh[ops]_[0-9a-zA-Z]{36}": "GitHub Token",
            r"(?i)github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}": "GitHub Fine-grained Token",
            # Google
            r"(?i)AIza[0-9A-Za-z\\-_]{35}": "Google API Key",
            r"(?i)ya29\\.[0-9A-Za-z\\-_]+": "Google OAuth Token",
            # Stripe
            r"(?i)sk_live_[0-9a-zA-Z]{24}": "Stripe Secret Key",
            r"(?i)rk_live_[0-9a-zA-Z]{24}": "Stripe Restricted Key",
            # Slack
            r"(?i)xox[baprs]-[0-9a-zA-Z]{10,48}": "Slack Token",
            # Generic tokens
            r"(?i)eyJ[a-zA-Z0-9]{17,}\\.eyJ[a-zA-Z0-9/\\-_]{17,}\\.[a-zA-Z0-9/\\-_]+": "JWT Token",
            # Database URLs
            r"(?i)postgres://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9\\-\\.]+:[0-9]+/[a-zA-Z0-9]+": "PostgreSQL URL",
            r"(?i)mysql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9\\-\\.]+:[0-9]+/[a-zA-Z0-9]+": "MySQL URL",
            r"(?i)mongodb[+srv]://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9\\-\\.]+/[a-zA-Z0-9]+": "MongoDB URL",
        }

    def scan(self, repo_path):
        """Scan Git commit history with false positive filtering"""
        print("   📜 Scanning Git history (filtered)...")
        findings = []

        try:
            # Get history with file information
            cmd = ["git", "log", "-p", "--all", "--name-only"]
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120,
                encoding="utf-8",
                errors="ignore",
            )

            if not result.stdout:
                return findings

            lines = result.stdout.split("\n")
            current_commit = None
            current_file = None

            for line in lines:
                line_stripped = line.strip()

                # Detect commit start
                if line.startswith("commit "):
                    current_commit = line[7:19]
                    current_file = None
                    continue

                # Detect file in diff
                elif line.startswith("+++ b/") or line.startswith("--- a/"):
                    # Skip diff header lines
                    continue

                elif line.startswith("diff --git"):
                    # New diff start
                    current_file = None
                    continue

                elif line.startswith("+++"):
                    # File in diff (new)
                    if "/" in line:
                        current_file = line[4:].strip()  # Remove '+++ '
                    continue

                elif line.startswith("---"):
                    # File in diff (old)
                    if current_file is None and "/" in line:
                        current_file = line[4:].strip()  # Remove '--- '
                    continue

                # Look for secret patterns
                for pattern, desc in self.patterns.items():
                    matches = re.findall(pattern, line)
                    for match in matches:
                        # Filter false positives
                        if self._is_false_positive(match, line):
                            continue

                        findings.append(
                            {
                                "type": "git_history_leak",
                                "risk": "critical",
                                "title": f"Secret in Git history: {desc}",
                                "description": f"Found in commit {current_commit}: {match[:30]}...",
                                "file": current_file or "unknown",
                                "commit": current_commit,
                                "secret_preview": match[:20] + "...",
                                "remediation": "1. Revoke the secret immediately\n2. Use git filter-branch or BFG Repo-Cleaner\n3. Force push to rewrite history",
                            }
                        )

                        # Don't look for other patterns in same line
                        break

            # Remove duplicates
            unique_findings = self._deduplicate_findings(findings)

            # Log statistics
            print(
                f"      Found {len(unique_findings)} potential secrets (after filtering)"
            )

            return unique_findings

        except Exception as e:
            print(f"      Error scanning Git history: {e}")
            return findings

    def _is_false_positive(self, match, line):
        """Filter false positives"""
        line_lower = line.lower()

        # Ignore commit hashes and diff markers
        if len(match) == 40 and all(c in "0123456789abcdef" for c in match.lower()):
            # This is a SHA1 commit hash
            return True

        # Ignore lines that look like diff markers
        if line.startswith("+") or line.startswith("-"):
            if "@" not in line and "://" not in line:
                # Probably code, not a secret
                return True

        # Ignore comments
        if line_lower.startswith("#") or "//" in line_lower[:10]:
            return True

        # Ignore test/example lines
        if "example" in line_lower or "test" in line_lower or "sample" in line_lower:
            return True

        # Ignore Base64 in test data
        if "testdata" in line_lower or "mock" in line_lower:
            return True

        return False

    def _deduplicate_findings(self, findings):
        """Remove duplicates"""
        seen = set()
        unique = []

        for finding in findings:
            # Key: commit + first 20 chars of secret + file
            key = (
                finding.get("commit"),
                finding.get("secret_preview")[:20],
                finding.get("file"),
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique


class SimpleContainerAuditor:
    """Simple container configuration auditor"""

    def __init__(self, config):
        self.config = config

    def scan(self, path):
        print("   🐳 Checking Dockerfile...")
        findings = []
        dockerfile = Path(path) / "Dockerfile"

        if dockerfile.exists():
            try:
                content = dockerfile.read_text()
                if re.search(r"FROM.*:latest", content):
                    findings.append(
                        {
                            "type": "docker",
                            "risk": "medium",
                            "title": "Using :latest tag",
                            "description": "Dockerfile uses latest tag",
                            "file": "Dockerfile",
                            "remediation": "Use specific image version",
                        }
                    )
            except:
                pass
        return findings


class SimpleRiskAssessor:
    """Risk assessment engine"""

    def __init__(self, config):
        self.config = config

    def assess(self, findings):
        risk_score = 0
        for finding in findings:
            if finding.get("risk") == "critical":
                risk_score += 30
            elif finding.get("risk") == "high":
                risk_score += 20
            elif finding.get("risk") == "medium":
                risk_score += 10
            elif finding.get("risk") == "low":
                risk_score += 5

        risk_score = min(risk_score, 100)
        return risk_score, findings


class SimpleReportGenerator:
    """Report generator"""

    def __init__(self, config):
        self.config = config

    def generate(self, findings, risk_score, target_path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(f"./reports/audit_{timestamp}")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Text report
        with open(output_dir / "report.txt", "w", encoding="utf-8") as f:
            f.write(f"CI/CD Security Audit Report\n")
            f.write(f"Target: {target_path}\n")
            f.write(f"Date: {datetime.now()}\n")
            f.write(f"Risk Score: {risk_score}/100\n")
            f.write(f"\nIssues Found ({len(findings)}):\n")

            for finding in findings:
                f.write(
                    f"\n[{finding.get('risk', 'unknown').upper()}] {finding.get('title', '')}\n"
                )
                f.write(f"File: {finding.get('file', 'N/A')}\n")
                if finding.get("line"):
                    f.write(f"Line: {finding.get('line')}\n")
                f.write(f"Recommendation: {finding.get('remediation', '')}\n")

        # HTML report
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>CI/CD Audit Report</title>
<style>body{{font-family:Arial;margin:40px;}}
.critical{{color:red;font-weight:bold;}} 
.high{{color:orange;font-weight:bold;}} 
.medium{{color:blue;}} 
.low{{color:green;}}
.finding{{border:1px solid #ddd;padding:15px;margin:10px 0;border-radius:5px;}}
</style></head><body>
<h1>CI/CD Security Audit Report</h1>
<p><strong>Target:</strong> {target_path}</p>
<p><strong>Date:</strong> {datetime.now()}</p>
<p><strong>Risk Score:</strong> <span class="{'critical' if risk_score >= 80 else 'high' if risk_score >= 50 else 'medium'}">{risk_score}/100</span></p>
<h2>Findings ({len(findings)})</h2>"""

        if findings:
            for finding in findings:
                html += f"""
<div class="finding {finding.get('risk', '')}">
<h3>[{finding.get('risk', '').upper()}] {finding.get('title', '')}</h3>
<p><strong>File:</strong> {finding.get('file', '')}</p>"""
                if finding.get("line"):
                    html += f'<p><strong>Line:</strong> {finding.get("line")}</p>'
                html += f"""
<p><strong>Description:</strong> {finding.get('description', '')}</p>
<p><strong>Recommendation:</strong> {finding.get('remediation', '')}</p>
</div>"""
        else:
            html += "<div class='finding'><p>✅ No security issues found!</p></div>"

        html += """</body></html>"""

        with open(output_dir / "report.html", "w", encoding="utf-8") as f:
            f.write(html)

        print(f"   📄 Reports saved to: {output_dir}")
        return {"output_dir": str(output_dir)}


# ==================== MAIN AUDITOR CLASS ====================


class CICDSecurityAuditor:
    """Main CI/CD security auditing class"""

    def __init__(self, target_path, config_path=None):
        self.target_path = Path(target_path).absolute()

        # Load configuration
        self.config = {
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

        if config_path and Path(config_path).exists():
            with open(config_path, "r") as f:
                user_config = json.load(f)
                self.config.update(user_config)

        self.findings = []
        self.risk_score = 0

        # Initialize ALL scanners
        self.secret_scanner = AdvancedSecretScanner(self.config)
        self.dependency_auditor = DependencyAuditor(self.config)
        self.cicd_analyzer = CICDConfigDeepAnalyzer(self.config)
        self.git_history_scanner = GitHistoryScanner(self.config)
        self.container_auditor = SimpleContainerAuditor(self.config)
        self.risk_assessor = SimpleRiskAssessor(self.config)
        self.report_gen = SimpleReportGenerator(self.config)

        print(f"✅ Initialized scanners: 6")

    def _analyze_env_files(self):
        """Analyze .env files"""
        findings = []
        for env_file in self.target_path.glob("**/.env"):
            rel_path = env_file.relative_to(self.target_path)
            print(f"   ⚠️  Found .env file: {rel_path}")

            findings.append(
                {
                    "type": "env_file",
                    "risk": "high",
                    "title": ".env file in repository",
                    "description": f"File {rel_path} may contain secrets",
                    "file": str(rel_path),
                    "remediation": "Add .env to .gitignore. Use .env.example for templates.",
                }
            )

        return findings

    def run_full_audit(self):
        """Run full enhanced security audit"""
        print("🔍 Starting ENHANCED CI/CD security audit...")
        print(f"📁 Target: {self.target_path}")
        print(
            f"⚙️  Enabled checks: {[k for k, v in self.config['checks'].items() if v]}"
        )

        # 1. Multi-scanner secret detection
        if self.config["checks"]["secrets"]:
            print("\n1. 🔐 Multi-scanner secret detection...")
            secret_findings = self.secret_scanner.scan(self.target_path)
            self.findings.extend(secret_findings)
            print(f"   Secrets found: {len(secret_findings)}")

        # 2. Git history scanning
        if self.config["checks"]["git_history"]:
            print("\n2. 📜 Git history scanning...")
            git_history_findings = self.git_history_scanner.scan(self.target_path)
            self.findings.extend(git_history_findings)
            print(f"   Git history issues: {len(git_history_findings)}")

        # 3. Dependency analysis
        if self.config["checks"]["dependencies"]:
            print("\n3. 📦 Dependency analysis...")
            dependency_findings = self.dependency_auditor.scan(self.target_path)
            self.findings.extend(dependency_findings)
            print(f"   Dependency vulnerabilities: {len(dependency_findings)}")

        # 4. Deep CI/CD analysis
        if self.config["checks"]["cicd_configs"]:
            print("\n4. ⚙️ Deep CI/CD config analysis...")
            cicd_findings = self.cicd_analyzer.scan(self.target_path)
            self.findings.extend(cicd_findings)
            print(f"   CI/CD issues: {len(cicd_findings)}")

        # 5. Container analysis
        if self.config["checks"]["containers"]:
            print("\n5. 🐳 Container analysis...")
            container_findings = self.container_auditor.scan(self.target_path)
            self.findings.extend(container_findings)
            print(f"   Container issues: {len(container_findings)}")

        # 6. .env files check
        print("\n6. 🔐 .env files check...")
        env_findings = self._analyze_env_files()
        self.findings.extend(env_findings)
        print(f"   .env files found: {len(env_findings)}")

        # 7. Risk assessment
        print("\n7. ⚠️ Risk assessment...")
        self.risk_score, prioritized_findings = self.risk_assessor.assess(self.findings)

        # 8. Report generation
        print("\n8. 📊 Report generation...")
        reports = self.report_gen.generate(
            findings=prioritized_findings,
            risk_score=self.risk_score,
            target_path=str(self.target_path),
        )

        # 9. Final statistics
        print(f"\n{'='*60}")
        print("✅ AUDIT COMPLETE!")
        print(f"{'='*60}")
        print(f"📊 Statistics:")
        print(f"   Total issues: {len(self.findings)}")

        critical = len([f for f in self.findings if f.get("risk") == "critical"])
        high = len([f for f in self.findings if f.get("risk") == "high"])
        medium = len([f for f in self.findings if f.get("risk") == "medium"])
        low = len([f for f in self.findings if f.get("risk") == "low"])

        if critical > 0:
            print(f"   Critical: {critical} 🔴")
        if high > 0:
            print(f"   High: {high} 🟠")
        if medium > 0:
            print(f"   Medium: {medium} 🔵")
        if low > 0:
            print(f"   Low: {low} 🟢")

        print(f"   Overall risk: {self.risk_score}/100")
        print(f"   Reports saved to: {reports['output_dir']}")

        if critical > 0:
            print(f"\n🚨 CRITICAL ISSUES REQUIRE IMMEDIATE ATTENTION!")
            for finding in [f for f in self.findings if f.get("risk") == "critical"][
                :3
            ]:
                print(f"   • {finding.get('title', '')}")

        return {
            "findings": prioritized_findings,
            "risk_score": self.risk_score,
            "reports": reports,
            "stats": {
                "total": len(self.findings),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
        }


# ==================== HELPER FUNCTIONS ====================


def check_required_tools():
    """Check availability of required tools"""
    tools = ["git", "gitleaks", "detect-secrets"]
    missing = []

    print("🔧 Checking required tools...")

    for tool in tools:
        try:
            if tool == "detect-secrets":
                subprocess.run(
                    ["detect-secrets", "--version"], capture_output=True, check=True
                )
            else:
                subprocess.run([tool, "--version"], capture_output=True, check=True)
            print(f"   ✓ {tool}")
        except:
            print(f"   ✗ {tool} NOT FOUND")
            missing.append(tool)

    if missing:
        print(f"\n⚠️  Missing tools: {', '.join(missing)}")
        print("Install them for full functionality:")
        print("  - gitleaks: https://github.com/gitleaks/gitleaks")
        print("  - detect-secrets: pip install detect-secrets")
        print("  - safety: pip install safety (for dependency checking)")

    return len(missing) == 0


def show_help():
    print(
        """
🔐 CI/CD Security Auditor v3.0 - Enhanced
==========================================

Automated security scanning for CI/CD pipelines, secrets, and dependencies.

Usage:
  python main.py <path> [options]

Examples:
  python main.py /path/to/repo
  python main.py . --mode quick
  python main.py ../project --output ./my-reports

Options:
  -o, --output DIR    Report directory (default: ./reports)
  -m, --mode MODE     Audit mode (full/quick/secrets/deps/cicd/git)
  -c, --config FILE   Configuration file (JSON)
  --skip-tool-check   Skip tool availability check
  --list-tools        List all supported security tools

Modes:
  full     - Complete audit (default)
  quick    - Fast scan (secrets + .env only)
  secrets  - Secret scanning only
  deps     - Dependency analysis only
  cicd     - CI/CD config analysis only
  git      - Git history scanning only

Supported tools:
  • Gitleaks - Secret detection
  • TruffleHog - Deep secret verification
  • detect-secrets - Entropy-based detection
  • npm audit - JavaScript dependencies
  • safety - Python dependencies
  • govulncheck - Go dependencies
  • Docker scan - Container analysis
    """
    )


def main():
    parser = argparse.ArgumentParser(description="CI/CD Security Auditor")
    parser.add_argument("target", help="Path to repository or project")
    parser.add_argument("-o", "--output", help="Report directory", default="./reports")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["full", "quick", "secrets", "deps", "cicd", "git"],
        default="full",
        help="Audit mode",
    )
    parser.add_argument("-c", "--config", help="Configuration file")
    parser.add_argument(
        "--skip-tool-check", action="store_true", help="Skip tool availability check"
    )
    parser.add_argument(
        "--list-tools", action="store_true", help="List all supported security tools"
    )

    args = parser.parse_args()

    if args.list_tools:
        print("Supported security tools:")
        print("  • Gitleaks - Secret detection")
        print("  • TruffleHog - Deep secret verification")
        print("  • detect-secrets - Entropy-based detection")
        print("  • npm audit - JavaScript dependencies")
        print("  • safety - Python dependencies")
        print("  • govulncheck - Go dependencies")
        print("  • Docker scan - Container analysis")
        sys.exit(0)

    # If GitHub URL - suggest using audit_github.py
    if "github.com" in args.target or "git@" in args.target:
        print("🌐 GitHub URL detected")
        print("💡 For direct GitHub scanning use:")
        print(f"   python audit_github.py {args.target}")
        print(f"   or")
        print(f"   ./audit_github.py {args.target} --mode {args.mode}")
        sys.exit(0)

    target_path = Path(args.target).absolute()

    if not target_path.exists():
        print(f"❌ Path does not exist: {target_path}")
        sys.exit(1)

    # Check tools
    if not args.skip_tool_check:
        check_required_tools()

    print(f"\n🎯 Audit target: {target_path}")
    print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🔧 Mode: {args.mode}")
    print(f"{'='*60}\n")

    try:
        # Configure based on mode
        config_updates = {}

        if args.mode == "quick":
            config_updates["checks"] = {
                "secrets": True,
                "iac": False,
                "containers": False,
                "cicd_configs": False,
                "dependencies": False,
                "git_history": False,
            }
        elif args.mode == "secrets":
            config_updates["checks"] = {
                "secrets": True,
                "iac": False,
                "containers": False,
                "cicd_configs": False,
                "dependencies": False,
                "git_history": True,
            }
        elif args.mode == "deps":
            config_updates["checks"] = {
                "secrets": False,
                "iac": True,
                "containers": True,
                "cicd_configs": False,
                "dependencies": True,
                "git_history": False,
            }
        elif args.mode == "cicd":
            config_updates["checks"] = {
                "secrets": False,
                "iac": False,
                "containers": False,
                "cicd_configs": True,
                "dependencies": False,
                "git_history": False,
            }
        elif args.mode == "git":
            config_updates["checks"] = {
                "secrets": False,
                "iac": False,
                "containers": False,
                "cicd_configs": False,
                "dependencies": False,
                "git_history": True,
            }

        # Create and configure auditor
        auditor = CICDSecurityAuditor(args.target, args.config)

        if config_updates:
            auditor.config.update(config_updates)

        # Run audit
        results = auditor.run_full_audit()

        # Exit code based on risk
        exit_code = 0
        if results["risk_score"] >= 80:
            exit_code = 2  # Critical risk
        elif results["risk_score"] >= 50:
            exit_code = 1  # High risk
        else:
            exit_code = 0  # Low/medium risk

        sys.exit(exit_code)

    except KeyboardInterrupt:
        print("\n\n⏹️  Audit interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        show_help()
        sys.exit(1)

    main()
