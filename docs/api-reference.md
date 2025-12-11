# 🔌 API Reference

Programmatic usage of CI/CD Security Auditor.

## Python API

### Import
```python
from cicd_security_auditor import CICDSecurityAuditor
```
## Basic Usage
```bash
# Initialize auditor
auditor = CICDSecurityAuditor(
    target_path="/path/to/repo",
    config_path="./config.json"  # optional
)

# Run full audit
results = auditor.run_full_audit()

# Access results
print(f"Risk score: {results['risk_score']}/100")
print(f"Total issues: {results['stats']['total']}")
print(f"Critical: {results['stats']['critical']}")

# Access individual findings
for finding in results['findings']:
    print(f"{finding['risk']}: {finding['title']}")
```
## Scanner Classes

### AdvancedSecretScanner
```bash
from cicd_security_auditor import AdvancedSecretScanner

scanner = AdvancedSecretScanner(config={"checks": {"secrets": True}})
findings = scanner.scan("/path/to/repo")
```
### DependencyAuditor
```bash
from cicd_security_auditor import DependencyAuditor

auditor = DependencyAuditor(config={"checks": {"iac": True}})
findings = auditor.scan("/path/to/repo")
```
### CICDConfigDeepAnalyzer
```bash
from cicd_security_auditor import CICDConfigDeepAnalyzer

analyzer = CICDConfigDeepAnalyzer(config={"checks": {"cicd_configs": True}})
findings = analyzer.scan("/path/to/repo")
```
### GitHistoryScanner
```bash
from cicd_security_auditor import GitHistoryScanner

scanner = GitHistoryScanner(config={"checks": {"git_history": True}})
findings = scanner.scan("/path/to/repo")
```
## Configuration Object
```bash
config = {
    # Scan options
    "scan_depth": "deep",  # or "shallow"
    
    # What to check
    "checks": {
        "secrets": True,        # Secret scanning
        "iac": True,            # Infrastructure as Code
        "containers": True,     # Docker/container analysis
        "cicd_configs": True,   # CI/CD config analysis
        "dependencies": True,   # Dependency vulnerabilities
        "git_history": True,    # Git history scanning
    },
    
    # Risk assessment
    "risk_threshold": "medium",  # or "low", "high", "critical"
    
    # Output
    "report_format": ["html", "txt"],  # or ["json", "txt"]
}
```
## Results Structure
```bash
results = {
    "findings": [
        {
            "type": "secret_leak",
            "risk": "critical",        # critical/high/medium/low
            "title": "AWS Key in code",
            "description": "Found in config file",
            "file": "config/aws.yml",
            "line": 42,
            "remediation": "Rotate key immediately",
            "tool": "gitleaks",        # which tool found it
            "secret": "AKIA...",       # truncated secret
        }
    ],
    "risk_score": 78,  # 0-100
    "reports": {
        "output_dir": "./reports/audit_20240101_120000"
    },
    "stats": {
        "total": 23,
        "critical": 5,
        "high": 8,
        "medium": 7,
        "low": 3
    }
}
```
## Command Line API

### main.py
```bash
python main.py <path> [options]

Arguments:
  path                    Path to repository or project

Options:
  -h, --help            Show help
  -m, --mode MODE       Audit mode (full/quick/secrets/deps/cicd/git)
  -o, --output DIR      Output directory for reports
  -c, --config FILE     Configuration file
  --skip-tool-check     Skip tool availability check
  --list-tools          List all supported tools

Exit Codes:
  0 - Success, low risk (< 50)
  1 - Success, high risk (50-79)
  2 - Success, critical risk (80-100)
  3 - Error occurred
```
### audit_github.py
```bash
python audit_github.py <github-url> [component]

Arguments:
  github-url            GitHub repository URL
  component             Component to check (all/secrets/deps/cicd/git)

Examples:
  python audit_github.py https://github.com/user/repo
  python audit_github.py https://github.com/user/repo.git secrets
```
### audit_api.py (Pro version)
```bash
python audit_api.py

Starts REST API server on http://localhost:5000

Endpoints:
  GET  /                 - API information
  GET  /health          - Health check
  POST /audit           - Start new audit
  GET  /status/<id>     - Get job status
  GET  /result/<id>     - Get audit results
  GET  /queue           - View audit queue
```
## Webhook Integration

### Receive scan results via webhook
```bash
# webhook_receiver.py
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/webhook/security', methods=['POST'])
def security_webhook():
    data = request.json
    
    # Example payload
    # {
    #   "repo": "https://github.com/user/repo",
    #   "risk_score": 65,
    #   "critical_issues": 3,
    #   "report_url": "https://..."
    # }
    
    if data["risk_score"] > 70:
        # Send alert
        send_slack_alert(data)
    
    return jsonify({"status": "received"})

def send_slack_alert(data):
    webhook_url = "https://hooks.slack.com/services/..."
    message = {
        "text": f"🚨 Security Alert!\nRepo: {data['repo']}\nRisk: {data['risk_score']}/100"
    }
    requests.post(webhook_url, json=message)
```
## Extending the Auditor

### Custom Scanner
```bash
from cicd_security_auditor import CICDSecurityAuditor

class CustomScanner:
    def __init__(self, config):
        self.config = config
    
    def scan(self, repo_path):
        # Your custom scanning logic
        return [{
            "type": "custom",
            "risk": "medium",
            "title": "Custom finding",
            "remediation": "Fix it"
        }]

# Use with main auditor
auditor = CICDSecurityAuditor("/path/to/repo")
auditor.custom_scanner = CustomScanner(auditor.config)

# Add findings
custom_findings = auditor.custom_scanner.scan(auditor.target_path)
auditor.findings.extend(custom_findings)
```
### Custom Risk Assessment
```bash
from cicd_security_auditor import SimpleRiskAssessor

class CustomRiskAssessor(SimpleRiskAssessor):
    def assess(self, findings):
        # Custom risk calculation
        risk_score = 0
        for finding in findings:
            if finding.get('type') == 'secret_leak':
                risk_score += 40  # Higher weight for secrets
            elif finding.get('risk') == 'critical':
                risk_score += 30
            # ... more rules
        
        risk_score = min(risk_score, 100)
        return risk_score, findings
```
### Environment Variables
```bash
Variable                    Purpose                 Default
---
CICD_AUDITOR_CONFIG         Path to config file     None
---
CICD_AUDITOR_OUTPUT         Output directory        ./reports
---
CICD_AUDITOR_MODE           Audit mode              full
---
CICD_AUDITOR_SKIP_TOOLS     Skip tool check         0 (false)
---
GITHUB_TOKEN                GitHub API token        None
```
Example:
```bash
export CICD_AUDITOR_MODE=quick
export CICD_AUDITOR_OUTPUT=/var/reports
python main.py /path/to/repo
```