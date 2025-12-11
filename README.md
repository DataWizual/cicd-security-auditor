# CI/CD Security Auditor 🔐

Automated security scanning tool for CI/CD pipelines, secrets, and dependencies.

## Features

- 🔍 **Multi-tool secret scanning** (Gitleaks, TruffleHog, detect-secrets)
- 📜 **Git history analysis** for leaked secrets
- 📦 **Dependency vulnerability scanning** (npm, Python, Go)
- ⚙️ **Deep CI/CD config analysis** (GitHub Actions, GitLab CI, etc.)
- 🐳 **Container security checks** (Dockerfile analysis)
- 📊 **HTML & text reports** with risk scoring
- 🌐 **Direct GitHub URL support**

## Quick Start

### Installation

### 1. Clone the repository:
```bash
git clone https://github.com/yourusername/cicd-security-auditor.git
cd cicd-security-auditor
```
### 2. Install Python dependencies:
```
pip install -r requirements.txt
```
### 3. Install required security tools:
```
# Gitleaks (secret detection)
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# detect-secrets
pip install detect-secrets

# Safety (Python dependencies)
pip install safety
```
### Usage

**Scan local repository**:
```bash
python main.py /path/to/your/repo
```

**Scan GitHub repository directly**:
```bash
python audit_github.py https://github.com/user/repo
```

**Scan specific components**:
```bash
# Only secrets
python main.py /path/to/repo --mode secrets

# Only dependencies
python main.py /path/to/repo --mode deps

# Only CI/CD configs
python main.py /path/to/repo --mode cicd
```
## Supported Tools

|Tool|Purpose|Installation|
|---------------|------------|------------|
|Gitleaks|Secret detection|Download|
|TruffleHog|Deep secret verification|docker pull trufflesecurity/trufflehog|
|detect-secrets|Entropy-based detection|pip install detect-secrets|
|npm audit|JavaScript dependencies|Install Node.js|
|safety|Python dependencies|pip install safety|
|govulncheck|Go dependencies|go install|

## Output Example
```bash
🔍 Starting ENHANCED CI/CD security audit...
📁 Target: /path/to/repo

1. 🔐 Multi-scanner secret detection...
   gitleaks: found 2
   trufflehog: found 1

2. 📜 Git history scanning...
   Found 3 potential secrets (after filtering)

3. 📦 Dependency analysis...
   Dependency vulnerabilities: 5

📊 Statistics:
   Total issues: 11
   Critical: 2 🔴
   High: 3 🟠
   Overall risk: 65/100
   Reports saved to: ./reports/audit_20251211_142047
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
  },
  "risk_threshold": "medium"
}
```
Use with config:
```bash
python main.py /path/to/repo --config config.json
```
## Exit Codes

   - 0: Low risk (score < 50)
   - 1: High risk (score 50-79)
   - 2: Critical risk (score ≥ 80)

## License

MIT License - see LICENSE file for details.









































