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
