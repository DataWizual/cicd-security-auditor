# 🚀 Getting Started

Quick guide to start using CI/CD Security Auditor.

## Installation

### Option 1: Clone from GitHub
```bash
git clone https://github.com/yourusername/cicd-security-auditor.git
cd cicd-security-auditor
pip install -r requirements.txt
```
### Option 2: Install tools
```bash
# Install Python dependencies
pip install pyyaml detect-secrets safety

# Install Gitleaks (required for secret scanning)
# Linux/Mac:
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Install Docker (for TruffleHog)
# https://docs.docker.com/get-docker/
```
## Quick Start
### Scan a GitHub repository
```bash
python audit_github.py https://github.com/facebook/react
```
### Scan a local project
```bash
python main.py /path/to/your/project
```
### Quick scan (secrets only)
```bash
python main.py . --mode quick
```
### Scan Modes
```bash
Mode        Description                     Speed
---
full        Complete audit (default)        Slow
---
quick       Secrets and .env only           Fast
---
secrets     Secret scanning only            Medium
---
deps        Dependency analysis only        Medium
---
cicd        CI/CD config analysis only      Fast
---
git         Git history scanning only       Slow
```
## Configuration
Create `config.json`:
```bash
{
  "scan_depth": "deep",
  "checks": {
    "secrets": true,
    "iac": true,
    "containers": true,
    "cicd_configs": true,
    "dependencies": true,
    "git_history": true
  }
}
```
Use it:
```bash
python main.py /path/to/project --config config.json
```
## Output

After each scan, you'll get:

   - ✅ Text report (report.txt)
   - ✅ HTML report (report.html)
   - ✅ Risk score (0-100)
   - ✅ Statistics (critical/high/medium/low issues)

Reports are saved to: `./reports/audit_YYYYMMDD_HHMMSS/`

## Next Steps

   - **Examples** - Real-world use cases
   - **API Reference** - Advanced usage
   - Integrate into your CI/CD pipeline
   