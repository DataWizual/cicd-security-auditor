#!/usr/bin/env python3
"""
GitHub Repository Auditor - Security audit for GitHub repositories via URL
"""

import subprocess
import tempfile
import shutil
import sys
import os
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add path to main module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_git_installed():
    """Check if git is installed"""
    try:
        subprocess.run(["git", "--version"], 
                      capture_output=True, check=True)
        return True
    except:
        return False

def clone_repository(repo_url, temp_dir, depth=1):
    """Clone repository to temporary directory"""
    try:
        print(f"   📥 Cloning repository (depth={depth})...")
        
        cmd = ["git", "clone"]
        
        # Add parameters for fast cloning
        if depth:
            cmd.extend(["--depth", str(depth)])
        
        cmd.extend(["--quiet", repo_url, temp_dir])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes for cloning
        )
        
        if result.returncode != 0:
            # Try without depth if failed
            if depth:
                print("   ⚠️  Failed to clone with depth, trying full clone...")
                return clone_repository(repo_url, temp_dir, depth=None)
            else:
                print(f"   ❌ Cloning error: {result.stderr}")
                return False
        
        print(f"   ✅ Successfully cloned: {Path(temp_dir).name}")
        return True
        
    except subprocess.TimeoutExpired:
        print("   ⏱️  Cloning timeout, repository too large")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def get_repo_info(temp_dir):
    """Get repository information"""
    info = {
        "name": Path(temp_dir).name,
        "url": "",
        "last_commit": "",
        "branch": "",
        "size": ""
    }
    
    try:
        # Get origin URL
        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=temp_dir,
            capture_output=True,
            text=True
        )
        if result.stdout:
            info["url"] = result.stdout.strip()
        
        # Last commit
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H %ad", "--date=short"],
            cwd=temp_dir,
            capture_output=True,
            text=True
        )
        if result.stdout:
            info["last_commit"] = result.stdout.strip()
        
        # Current branch
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=temp_dir,
            capture_output=True,
            text=True
        )
        if result.stdout:
            info["branch"] = result.stdout.strip()
        
        # Repository size
        total_size = 0
        for file in Path(temp_dir).rglob('*'):
            if file.is_file():
                total_size += file.stat().st_size
        info["size"] = f"{total_size / (1024*1024):.2f} MB"
        
    except Exception as e:
        print(f"   ⚠️  Failed to get info: {e}")
    
    return info

def audit_github_repo(repo_url, component="all"):
    """
    Clone and audit GitHub repository
    
    Args:
        repo_url: Repository URL (https:// or git@)
        component: Component to check (all, secrets, deps, cicd, git)
    """
    
    print(f"\n{'='*60}")
    print(f"🔐 GITHUB REPOSITORY SECURITY AUDIT")
    print(f"{'='*60}")
    print(f"🎯 URL: {repo_url}")
    print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🔧 Component: {component}")
    
    # Check if git is installed
    if not check_git_installed():
        print("\n❌ Git is not installed!")
        print("Install git: https://git-scm.com/downloads")
        return False
    
    # Create temporary directory with meaningful name
    repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
    temp_dir = tempfile.mkdtemp(prefix=f"audit_{repo_name}_")
    
    print(f"\n📁 Temporary directory: {temp_dir}")
    
    try:
        # 1. Clone repository
        print("\n1. 📥 Cloning repository...")
        if not clone_repository(repo_url, temp_dir):
            return False
        
        # 2. Get repository information
        print("\n2. 📊 Repository information...")
        repo_info = get_repo_info(temp_dir)
        for key, value in repo_info.items():
            if value:
                print(f"   {key}: {value}")
        
        # 3. Import and run main auditor
        print("\n3. 🔍 Running security audit...")
        
        # Dynamic import of main module
        try:
            # Try to import enhanced auditor
            from main import CICDSecurityAuditor, AdvancedSecretScanner, DependencyAuditor, CICDConfigDeepAnalyzer, GitHistoryScanner
            
            # Configuration
            config = {
                "checks": {
                    "secrets": component in ["all", "secrets"],
                    "iac": component in ["all", "deps"],
                    "containers": True,
                    "cicd_configs": component in ["all", "cicd"]
                }
            }
            
            # Run selective checks or full audit
            if component == "all":
                # Full audit via main class
                print("   🚀 Running full audit...")
                auditor = CICDSecurityAuditor(temp_dir)
                results = auditor.run_full_audit()
            else:
                # Selective checks
                print(f"   🎯 Running check: {component}")
                findings = []
                
                if component == "secrets":
                    scanner = AdvancedSecretScanner(config)
                    findings = scanner.scan(temp_dir)
                elif component == "deps":
                    auditor = DependencyAuditor(config)
                    findings = auditor.scan(temp_dir)
                elif component == "cicd":
                    analyzer = CICDConfigDeepAnalyzer(config)
                    findings = analyzer.scan(temp_dir)
                elif component == "git":
                    scanner = GitHistoryScanner(config)
                    findings = scanner.scan(temp_dir)
                
                # Save results
                if findings:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    output_dir = Path(f"./reports/{repo_name}_{component}_{timestamp}")
                    output_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Save to JSON
                    with open(output_dir / f"findings_{component}.json", 'w') as f:
                        json.dump({
                            "repo_url": repo_url,
                            "component": component,
                            "timestamp": timestamp,
                            "findings": findings
                        }, f, indent=2, ensure_ascii=False)
                    
                    # Simple text report
                    with open(output_dir / f"report_{component}.txt", 'w', encoding='utf-8') as f:
                        f.write(f"GitHub Audit Report - {component.upper()}\n")
                        f.write(f"Repository: {repo_url}\n")
                        f.write(f"Date: {datetime.now()}\n")
                        f.write(f"Total issues: {len(findings)}\n\n")
                        
                        for finding in findings:
                            f.write(f"[{finding.get('risk', 'unknown').upper()}] {finding.get('title', '')}\n")
                            f.write(f"File: {finding.get('file', 'N/A')}\n")
                            if finding.get('line'):
                                f.write(f"Line: {finding.get('line')}\n")
                            f.write(f"Fix: {finding.get('remediation', '')}\n")
                            f.write("-" * 50 + "\n")
                    
                    print(f"   📄 Report saved to: {output_dir}")
            
            return True
            
        except ImportError as e:
            print(f"   ❌ Failed to import modules: {e}")
            print("   Make sure main.py is in the same directory")
            return False
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Audit interrupted by user")
        return False
    except Exception as e:
        print(f"\n❌ Critical error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Clean up temporary directory
        print(f"\n4. 🧹 Cleaning temporary files...")
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
            print(f"   ✅ Cleaned: {temp_dir}")
        except Exception as e:
            print(f"   ⚠️  Failed to clean: {e}")

def show_help():
    print("""
GitHub Repository Auditor
=========================

Security audit for GitHub repositories directly via URL.

Usage:
  python audit_github.py <github-url> [component]

Examples:
  python audit_github.py https://github.com/user/repo
  python audit_github.py https://github.com/user/repo.git secrets
  python audit_github.py git@github.com:user/repo.git all

Components:
  all      - Full audit (default)
  secrets  - Secret scanning only
  deps     - Dependency analysis only  
  cicd     - CI/CD config analysis only
  git      - Git history scanning only

Supported URLs:
  • https://github.com/user/repo
  • https://github.com/user/repo.git
  • git@github.com:user/repo.git
  • ssh://git@github.com/user/repo.git
    """)

def main():
    parser = argparse.ArgumentParser(description="GitHub Repository Auditor")
    parser.add_argument("repo_url", help="GitHub repository URL")
    parser.add_argument("component", 
                       nargs="?", 
                       default="all",
                       choices=["all", "secrets", "deps", "cicd", "git"],
                       help="Component to audit (default: all)")
    
    args = parser.parse_args()
    
    # Run audit
    success = audit_github_repo(args.repo_url, args.component)
    
    if success:
        print(f"\n{'='*60}")
        print("✅ AUDIT SUCCESSFULLY COMPLETED!")
        print(f"{'='*60}")
        sys.exit(0)
    else:
        print(f"\n{'='*60}")
        print("❌ AUDIT FAILED WITH ERRORS")
        print(f"{'='*60}")
        sys.exit(1)

if __name__ == "__main__":
    main()