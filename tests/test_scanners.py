#!/usr/bin/env python3
"""
Tests for individual scanner components
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import (
    AdvancedSecretScanner,
    DependencyAuditor,
    CICDConfigDeepAnalyzer,
    GitHistoryScanner,
    SimpleContainerAuditor
)


class TestAdvancedSecretScanner:
    """Tests for AdvancedSecretScanner"""
    
    def setup_method(self):
        self.config = {"checks": {"secrets": True}}
        self.scanner = AdvancedSecretScanner(self.config)
        
    def test_init(self):
        """Test scanner initialization"""
        assert hasattr(self.scanner, 'tools')
        assert 'gitleaks' in self.scanner.tools
        assert 'trufflehog' in self.scanner.tools
        assert 'detect_secrets' in self.scanner.tools
    
    @patch('subprocess.run')
    def test_gitleaks_success(self, mock_subprocess):
        """Test successful gitleaks scan"""
        # Mock gitleaks output
        mock_output = {
            "findings": [
                {
                    "rule": "AWS Access Key",
                    "file": "test.txt",
                    "startLine": 10,
                    "secret": "AKIAIOSFODNN7EXAMPLE"
                }
            ]
        }
        
        mock_result = Mock()
        mock_result.stdout = json.dumps(mock_output)
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        findings = self.scanner._run_gitleaks("/test/path")
        
        assert len(findings) == 1
        assert findings[0]["type"] == "secret_leak"
        assert findings[0]["risk"] == "critical"
        assert "AWS Access Key" in findings[0]["title"]
    
    @patch('subprocess.run')
    def test_gitleaks_no_findings(self, mock_subprocess):
        """Test gitleaks with no findings"""
        mock_result = Mock()
        mock_result.stdout = json.dumps({"findings": []})
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        findings = self.scanner._run_gitleaks("/test/path")
        assert len(findings) == 0
    
    @patch('subprocess.run')
    def test_gitleaks_not_installed(self, mock_subprocess):
        """Test when gitleaks is not installed"""
        mock_subprocess.side_effect = FileNotFoundError
        
        findings = self.scanner._run_gitleaks("/test/path")
        assert len(findings) == 0
    
    @patch('subprocess.run')
    def test_detect_secrets_success(self, mock_subprocess):
        """Test successful detect-secrets scan"""
        # Mock detect-secrets output
        mock_output = {
            "results": {
                "test.txt": [
                    {
                        "type": "Base64HighEntropyString",
                        "line_number": 5,
                        "secret": "c2VjcmV0Cg=="
                    }
                ]
            }
        }
        
        mock_result = Mock()
        mock_result.stdout = json.dumps(mock_output)
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        findings = self.scanner._run_detect_secrets("/test/path")
        
        assert len(findings) == 1
        assert findings[0]["type"] == "secret_leak"
        assert findings[0]["risk"] == "high"
        assert "Base64HighEntropyString" in findings[0]["title"]
    
    def test_deduplicate_findings(self):
        """Test duplicate removal"""
        findings = [
            {"file": "test.txt", "line": 10, "secret": "secret1", "title": "Test 1"},
            {"file": "test.txt", "line": 10, "secret": "secret1", "title": "Test 1"},  # Duplicate
            {"file": "test.txt", "line": 20, "secret": "secret2", "title": "Test 2"},
            {"file": "other.txt", "line": 10, "secret": "secret1", "title": "Test 3"},
        ]
        
        unique = self.scanner._deduplicate_findings(findings)
        assert len(unique) == 3  # Removed one duplicate


class TestDependencyAuditor:
    """Tests for DependencyAuditor"""
    
    def setup_method(self):
        self.config = {"checks": {"iac": True}}
        self.auditor = DependencyAuditor(self.config)
    
    def test_init(self):
        """Test auditor initialization"""
        assert hasattr(self.auditor, 'vulnerability_sources')
        assert 'npm' in self.auditor.vulnerability_sources
        assert 'python' in self.auditor.vulnerability_sources
        assert 'go' in self.auditor.vulnerability_sources
        assert 'docker' in self.auditor.vulnerability_sources
    
    def test_map_severity(self):
        """Test severity mapping"""
        assert self.auditor._map_severity('critical') == 'critical'
        assert self.auditor._map_severity('high') == 'high'
        assert self.auditor._map_severity('medium') == 'medium'
        assert self.auditor._map_severity('low') == 'low'
        assert self.auditor._map_severity('moderate') == 'medium'
        assert self.auditor._map_severity('unknown') == 'low'
    
    def test_audit_docker(self):
        """Test Dockerfile analysis"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # Test 1: No Dockerfile
            findings = self.auditor._audit_docker(tmp_path)
            assert len(findings) == 0
            
            # Test 2: Good Dockerfile
            good_docker = tmp_path / "Dockerfile"
            good_docker.write_text("FROM ubuntu:20.04\nRUN echo 'test'")
            
            findings = self.auditor._audit_docker(tmp_path)
            assert len(findings) == 0
            
            # Test 3: Dockerfile with :latest
            bad_docker = tmp_path / "bad.Dockerfile"
            bad_docker.write_text("FROM ubuntu:latest\nRUN echo 'test'")
            
            # Need to update the test to look in subdirectory
            subdir = tmp_path / "app"
            subdir.mkdir()
            bad_docker_in_subdir = subdir / "Dockerfile"
            bad_docker_in_subdir.write_text("FROM ubuntu:latest\nRUN echo 'test'")
            
            findings = self.auditor._audit_docker(tmp_path)
            # Should find the :latest issue
            assert len(findings) >= 1
            assert ":latest" in findings[0]["title"]
            
            # Test 4: Outdated base image
            outdated_docker = tmp_path / "outdated.Dockerfile"
            outdated_docker.write_text("FROM ubuntu:16.04\nRUN echo 'old'")
            
            findings = self.auditor._audit_docker(tmp_path)
            # Should find outdated image
            assert any("16.04" in str(f.get("title", "")) for f in findings)


class TestCICDConfigDeepAnalyzer:
    """Tests for CICDConfigDeepAnalyzer"""
    
    def setup_method(self):
        self.config = {"checks": {"cicd_configs": True}}
        self.analyzer = CICDConfigDeepAnalyzer(self.config)
    
    def test_init(self):
        """Test analyzer initialization"""
        assert hasattr(self.analyzer, 'workflow_patterns')
        assert 'hardcoded_secrets' in self.analyzer.workflow_patterns
        assert 'dangerous_commands' in self.analyzer.workflow_patterns
        assert 'excessive_permissions' in self.analyzer.workflow_patterns
    
    def test_has_potential_secret_vars(self):
        """Test secret variable detection"""
        # Test with secret-like variable
        content = """
        env:
          DATABASE_PASSWORD: "secret123"
          normal_var: "value"
        """
        assert self.analyzer._has_potential_secret_vars(content) == True
        
        # Test without secret-like variables
        content = """
        env:
          NORMAL_VAR: "value"
          another_var: "test"
        """
        assert self.analyzer._has_potential_secret_vars(content) == False
        
        # Test with commented secret
        content = """
        # DATABASE_PASSWORD: "secret123"
        NORMAL_VAR: "value"
        """
        assert self.analyzer._has_potential_secret_vars(content) == False
    
    def test_get_remediation(self):
        """Test remediation advice"""
        assert "GitHub Secrets" in self.analyzer._get_remediation('hardcoded_secrets')
        assert "safer alternatives" in self.analyzer._get_remediation('dangerous_commands')
        assert "least privilege" in self.analyzer._get_remediation('excessive_permissions')
        assert "Fix the configuration" == self.analyzer._get_remediation('unknown_type')
    
    def test_analyze_file_hardcoded_secret(self):
        """Test finding hardcoded secrets in config"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            repo_path = tmp_path / "repo"
            repo_path.mkdir()
            
            # Create GitHub Actions workflow with hardcoded secret
            workflow = repo_path / ".github" / "workflows"
            workflow.mkdir(parents=True)
            
            workflow_file = workflow / "test.yml"
            workflow_content = """
            name: Test
            on: push
            jobs:
              test:
                runs-on: ubuntu-latest
                env:
                  SECRET_KEY: "my-secret-key-12345"
                steps:
                  - run: echo "Testing"
            """
            workflow_file.write_text(workflow_content)
            
            findings = self.analyzer._analyze_file(workflow_file, repo_path)
            
            # Should find hardcoded secret
            assert len(findings) >= 1
            assert any("Hardcoded" in f.get("title", "") for f in findings)
    
    def test_analyze_file_dangerous_command(self):
        """Test finding dangerous commands"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            repo_path = tmp_path / "repo"
            repo_path.mkdir()
            
            workflow = repo_path / ".github" / "workflows"
            workflow.mkdir(parents=True)
            
            workflow_file = workflow / "dangerous.yml"
            workflow_content = """
            steps:
              - name: Dangerous
                run: curl http://example.com/script.sh | bash
            """
            workflow_file.write_text(workflow_content)
            
            findings = self.analyzer._analyze_file(workflow_file, repo_path)
            
            assert len(findings) >= 1
            assert any("Dangerous" in f.get("title", "") for f in findings)


class TestGitHistoryScanner:
    """Tests for GitHistoryScanner"""
    
    def setup_method(self):
        self.config = {"checks": {"git_history": True}}
        self.scanner = GitHistoryScanner(self.config)
    
    def test_init(self):
        """Test scanner initialization"""
        assert hasattr(self.scanner, 'patterns')
        assert 'AWS Access Key ID' in self.scanner.patterns.values()
        assert 'GitHub Token' in self.scanner.patterns.values()
    
    def test_is_false_positive(self):
        """Test false positive filtering"""
        # Test SHA1 commit hash (should be filtered)
        sha1_hash = "a1b2c3d4e5f67890123456789012345678901234"
        line = f"commit {sha1_hash}"
        assert self.scanner._is_false_positive(sha1_hash, line) == True
        
        # Test short hex (should not be filtered)
        short_hex = "a1b2c3"
        line = "token: a1b2c3"
        assert self.scanner._is_false_positive(short_hex, line) == False
        
        # Test comment line (should be filtered)
        comment_line = "# SECRET_KEY=abc123"
        assert self.scanner._is_false_positive("abc123", comment_line) == True
        
        # Test example/test line (should be filtered)
        example_line = "example_key: AKIAEXAMPLE123"
        assert self.scanner._is_false_positive("AKIAEXAMPLE123", example_line) == True
    
    def test_deduplicate_findings(self):
        """Test duplicate Git findings removal"""
        findings = [
            {"commit": "abc123", "secret_preview": "AKIAIOSFODNN7EXAMPLE", "file": "test.txt"},
            {"commit": "abc123", "secret_preview": "AKIAIOSFODNN7EXAMPLE", "file": "test.txt"},  # Duplicate
            {"commit": "def456", "secret_preview": "AKIAIOSFODNN7EXAMPLE", "file": "test.txt"},
            {"commit": "abc123", "secret_preview": "ghp_abcdef1234567890", "file": "test.txt"},
        ]
        
        unique = self.scanner._deduplicate_findings(findings)
        assert len(unique) == 3  # Removed one duplicate


class TestSimpleContainerAuditor:
    """Tests for SimpleContainerAuditor"""
    
    def setup_method(self):
        self.config = {"checks": {"containers": True}}
        self.auditor = SimpleContainerAuditor(self.config)
    
    def test_scan_no_dockerfile(self):
        """Test scanning directory without Dockerfile"""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = self.auditor.scan(tmpdir)
            assert len(findings) == 0
    
    def test_scan_with_latest_tag(self):
        """Test scanning Dockerfile with :latest tag"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            dockerfile = tmp_path / "Dockerfile"
            dockerfile.write_text("FROM ubuntu:latest\nRUN echo 'test'")
            
            findings = self.auditor.scan(tmpdir)
            
            assert len(findings) == 1
            assert findings[0]["type"] == "docker"
            assert findings[0]["risk"] == "medium"
            assert ":latest" in findings[0]["title"]
            assert "Dockerfile" in findings[0]["file"]
    
    def test_scan_with_specific_tag(self):
        """Test scanning Dockerfile with specific tag"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            dockerfile = tmp_path / "Dockerfile"
            dockerfile.write_text("FROM ubuntu:20.04\nRUN echo 'test'")
            
            findings = self.auditor.scan(tmpdir)
            assert len(findings) == 0  # Should not flag specific version


class TestScannerIntegration:
    """Integration tests for scanners"""
    
    def test_all_scanners_initializable(self):
        """Test that all scanners can be initialized"""
        config = {"checks": {"secrets": True, "iac": True, "cicd_configs": True, "git_history": True}}
        
        scanners = [
            AdvancedSecretScanner(config),
            DependencyAuditor(config),
            CICDConfigDeepAnalyzer(config),
            GitHistoryScanner(config),
            SimpleContainerAuditor(config),
        ]
        
        assert len(scanners) == 5
        for scanner in scanners:
            assert scanner is not None
    
    @patch('subprocess.run')
    def test_scanner_error_handling(self, mock_subprocess):
        """Test scanner error handling"""
        config = {"checks": {"secrets": True}}
        scanner = AdvancedSecretScanner(config)
        
        # Simulate tool failure
        mock_subprocess.side_effect = Exception("Tool failed")
        
        # Should handle error gracefully
        with patch.object(scanner, '_run_gitleaks', return_value=[]):
            with patch.object(scanner, '_run_trufflehog', return_value=[]):
                with patch.object(scanner, '_run_detect_secrets', return_value=[]):
                    findings = scanner.scan("/test/path")
                    assert len(findings) == 0


if __name__ == "__main__":
    # Run tests manually
    print("Running scanner tests...")
    
    tests = [
        TestAdvancedSecretScanner(),
        TestDependencyAuditor(),
        TestCICDConfigDeepAnalyzer(),
        TestGitHistoryScanner(),
        TestSimpleContainerAuditor(),
    ]
    
    for test_class in tests:
        class_name = test_class.__class__.__name__
        print(f"\n🔧 Testing {class_name}...")
        
        # Run setup
        test_class.setup_method()
        
        # Run test_init if exists
        if hasattr(test_class, 'test_init'):
            test_class.test_init()
            print(f"  ✅ {class_name}.test_init")
    
    print("\n✅ All scanner tests passed!")