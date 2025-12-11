"""
CI/CD Security Auditor
======================

Automated security scanning for CI/CD pipelines, secrets, and dependencies.

Version: 1.0.0
Author: Your Name
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Your Name"
__license__ = "MIT"
__email__ = "your.email@example.com"

# Expose main classes for easy import
from .main import (
    CICDSecurityAuditor,
    AdvancedSecretScanner,
    DependencyAuditor,
    CICDConfigDeepAnalyzer,
    GitHistoryScanner,
    SimpleContainerAuditor,
    SimpleRiskAssessor,
    SimpleReportGenerator
)

# Short aliases
Auditor = CICDSecurityAuditor
SecretScanner = AdvancedSecretScanner
DependencyScanner = DependencyAuditor
CICDAnalyzer = CICDConfigDeepAnalyzer
GitScanner = GitHistoryScanner

# List of what's available
__all__ = [
    "CICDSecurityAuditor",
    "AdvancedSecretScanner", 
    "DependencyAuditor",
    "CICDConfigDeepAnalyzer",
    "GitHistoryScanner",
    "SimpleContainerAuditor",
    "SimpleRiskAssessor",
    "SimpleReportGenerator",
    "Auditor",
    "SecretScanner",
    "DependencyScanner", 
    "CICDAnalyzer",
    "GitScanner",
]

# Package metadata
PACKAGE_INFO = {
    "name": "cicd-security-auditor",
    "version": __version__,
    "description": "Automated security scanning for CI/CD pipelines",
    "author": __author__,
    "license": __license__,
    "email": __email__,
    "url": "https://github.com/yourusername/cicd-security-auditor",
    "keywords": ["security", "cicd", "devsecops", "secrets", "audit"],
}