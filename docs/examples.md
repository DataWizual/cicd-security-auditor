# 📚 Examples

Real-world examples of using CI/CD Security Auditor.

## Example 1: GitHub Repository Scan

```bash
# Scan any public GitHub repository
python audit_github.py https://github.com/facebook/react

# Scan with specific component
python audit_github.py https://github.com/vuejs/vue secrets

# Output will show:
# - Cloned repository
# - Security issues found
# - Risk score
# - Report files
```
## Example 2: Local Project Security Audit
```bash
# Full audit of current directory
python main.py .

# Audit specific directory
python main.py ~/projects/my-app

# Save reports to custom location
python main.py . --output ./security-reports
```
## Example 3: CI/CD Integration

### GitHub Actions
```bash
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
          
      - name: Install auditor
        run: |
          git clone https://github.com/yourusername/cicd-security-auditor
          cd cicd-security-auditor
          pip install -r requirements.txt
          
      - name: Run security audit
        run: |
          cd cicd-security-auditor
          python main.py ${{ github.workspace }} --mode quick
          
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: cicd-security-auditor/reports/
```
### GitLab CI
```bash
# .gitlab-ci.yml
security_audit:
  stage: test
  image: python:3.10
  script:
    - git clone https://github.com/yourusername/cicd-security-auditor
    - cd cicd-security-auditor
    - pip install -r requirements.txt
    - python main.py . --mode quick
  artifacts:
    paths:
      - cicd-security-auditor/reports/
```
### Example 4: Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "🔐 Running security audit..."
cd $(git rev-parse --show-toplevel)

# Run quick audit on staged files
python /path/to/cicd-security-auditor/main.py . --mode quick

# Get risk score from output
RISK_SCORE=$?

if [ $RISK_SCORE -ge 50 ]; then
  echo "❌ Security audit failed! Risk too high."
  echo "   Run 'python main.py .' for details."
  exit 1
else
  echo "✅ Security audit passed!"
  exit 0
fi
```
### Example 5: Scheduled Daily Scan
```bash
#!/bin/bash
# daily-security-scan.sh

PROJECT_DIR="/home/user/projects"
AUDITOR_DIR="/opt/cicd-security-auditor"
REPORT_DIR="/var/www/security-reports"

cd $AUDITOR_DIR

# Scan all projects
for project in $PROJECT_DIR/*/; do
  if [ -d "$project" ]; then
    project_name=$(basename $project)
    echo "Scanning $project_name..."
    
    python main.py "$project" --output "$REPORT_DIR/$project_name"
    
    # Send alert if high risk
    # (add your notification logic here)
  fi
done
```
### Example 6: Custom Configuration
```bash
// config-custom.json
{
  "scan_depth": "deep",
  "checks": {
    "secrets": true,
    "iac": false,
    "containers": true,
    "cicd_configs": true,
    "dependencies": true,
    "git_history": false
  },
  "risk_threshold": "high",
  "report_format": ["html", "json"]
}
```
```bash
python main.py . --config config-custom.json
```
### Example 7: API Usage
```bash
# api_example.py
import subprocess
import json

def run_security_audit(repo_path):
    """Run security audit and parse results"""
    result = subprocess.run(
        ["python", "main.py", repo_path, "--mode", "full"],
        capture_output=True,
        text=True
    )
    
    # Parse output
    if "AUDIT COMPLETE" in result.stdout:
        # Extract risk score
        for line in result.stdout.split('\n'):
            if "Overall risk:" in line:
                risk_score = int(line.split(":")[1].split("/")[0])
                return risk_score
    
    return None

# Usage
score = run_security_audit("/path/to/project")
print(f"Risk score: {score}/100")
```
# Common Issues & Solutions

## Issue: "Tool not found" errors

**Solution**: Install missing tools or use `--skip-tool-check`:
```bash
python main.py . --skip-tool-check
```
## Issue: Large repositories timeout

**Solution**: Use shallow scan:
```bash
{"scan_depth": "shallow"}
```
## Issue: Too many false positives

**Solution**: Adjust configuration:
```bash
{
  "checks": {
    "git_history": false,  // Disable Git history scan
    "dependencies": true   // Keep dependency check
  }
}
```
