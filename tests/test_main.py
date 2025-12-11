#!/usr/bin/env python3
"""
Tests for CI/CD Security Auditor
"""

import os
import sys
import tempfile
import json
from pathlib import Path
import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import (
    CICDSecurityAuditor,
    AdvancedSecretScanner,
    DependencyAuditor,
    SimpleContainerAuditor,
    SimpleRiskAssessor,
    SimpleReportGenerator
)


class TestBasicComponents:
    """Basic component tests"""
    
    def test_risk_assessor(self):
        """Test risk assessment"""
        assessor = SimpleRiskAssessor({})
        
        # Test with no findings
        score, findings = assessor.assess([])
        assert score == 0
        assert findings == []
        
        # Test with findings
        test_findings = [
            {"risk": "critical", "title": "Test 1"},
            {"risk": "high", "title": "Test 2"},
            {"risk": "medium", "title": "Test 3"},
            {"risk": "low", "title": "Test 4"},
        ]
        
        score, findings = assessor.assess(test_findings)
        assert score == 65  # 30 + 20 + 10 + 5
        assert len(findings) == 4
    
    def test_report_generator(self):
        """Test report generation"""
        generator = SimpleReportGenerator({})
        
        test_findings = [
            {
                "risk": "critical",
                "title": "Test Finding",
                "file": "test.txt",
                "remediation": "Fix it"
            }
        ]
        
        result = generator.generate(
            findings=test_findings,
            risk_score=75,
            target_path="/test/path"
        )
        
        assert "output_dir" in result
        assert isinstance(result["output_dir"], str)
        
        # Check if reports were created
        report_dir = Path(result["output_dir"])
        assert report_dir.exists()
        assert (report_dir / "report.txt").exists()
        assert (report_dir / "report.html").exists()
        
        # Clean up
        import shutil
        shutil.rmtree(report_dir, ignore_errors=True)
    
    def test_container_auditor(self):
        """Test Dockerfile analysis"""
        auditor = SimpleContainerAuditor({})
        
        # Create temp directory with Dockerfile
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # Test 1: No Dockerfile
            findings = auditor.scan(tmp_path)
            assert len(findings) == 0
            
            # Test 2: Dockerfile with :latest
            dockerfile = tmp_path / "Dockerfile"
            dockerfile.write_text("FROM ubuntu:latest\nRUN echo test")
            
            findings = auditor.scan(tmp_path)
            assert len(findings) == 1
            assert ":latest" in findings[0]["title"]
    
    def test_auditor_initialization(self):
        """Test main auditor initialization"""
        with tempfile.TemporaryDirectory() as tmpdir:
            auditor = CICDSecurityAuditor(tmpdir)
            
            assert auditor.target_path == Path(tmpdir).absolute()
            assert hasattr(auditor, "secret_scanner")
            assert hasattr(auditor, "dependency_auditor")
            assert hasattr(auditor, "cicd_analyzer")
            assert hasattr(auditor, "git_history_scanner")
            assert hasattr(auditor, "container_auditor")
            assert hasattr(auditor, "risk_assessor")
            assert hasattr(auditor, "report_gen")


class TestIntegration:
    """Integration tests"""
    
    def test_empty_directory_audit(self):
        """Test audit on empty directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            auditor = CICDSecurityAuditor(tmpdir)
            
            # Configure for quick scan
            auditor.config["checks"] = {
                "secrets": False,
                "iac": False,
                "containers": False,
                "cicd_configs": False,
                "dependencies": False,
                "git_history": False
            }
            
            result = auditor.run_full_audit()
            
            assert "findings" in result
            assert "risk_score" in result
            assert "reports" in result
            assert "stats" in result
            
            # Empty directory should have only .env check
            # (which finds nothing in empty dir)
            assert result["risk_score"] == 0
    
    def test_config_loading(self):
        """Test configuration loading"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create config file
            config_path = Path(tmpdir) / "config.json"
            config_data = {
                "scan_depth": "shallow",
                "checks": {
                    "secrets": False,
                    "dependencies": True
                }
            }
            
            config_path.write_text(json.dumps(config_data))
            
            # Create auditor with config
            auditor = CICDSecurityAuditor(tmpdir, str(config_path))
            
            assert auditor.config["scan_depth"] == "shallow"
            assert auditor.config["checks"]["secrets"] == False
            assert auditor.config["checks"]["dependencies"] == True
    
    def test_mode_configuration(self):
        """Test different audit modes"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test quick mode
            auditor = CICDSecurityAuditor(tmpdir)
            auditor.config["checks"] = {
                "secrets": True,
                "iac": False,
                "containers": False,
                "cicd_configs": False,
                "dependencies": False,
                "git_history": False
            }
            
            # Should only run secrets scanner
            # (Note: In real test, we would mock the scanners)
            assert auditor.config["checks"]["secrets"] == True
            assert auditor.config["checks"]["dependencies"] == False


@pytest.mark.skipif(not os.getenv("RUN_INTEGRATION_TESTS"), 
                   reason="Integration tests require external tools")
class TestWithTools:
    """Tests that require external tools (skipped by default)"""
    
    def test_git_history_scanner(self):
        """Test Git history scanner (requires git)"""
        # This would test actual git scanning
        pass
    
    def test_dependency_auditor(self):
        """Test dependency auditor (requires npm, pip)"""
        # This would test actual dependency scanning
        pass


def test_imports():
    """Test that all imports work"""
    # This test just ensures everything imports correctly
    from src.main import (
        CICDConfigDeepAnalyzer,
        GitHistoryScanner
    )
    
    assert True  # If we get here, imports work


if __name__ == "__main__":
    # Run tests manually
    print("Running tests...")
    
    tester = TestBasicComponents()
    
    print("1. Testing risk assessor...")
    tester.test_risk_assessor()
    print("   ✅ Passed")
    
    print("2. Testing report generator...")
    tester.test_report_generator()
    print("   ✅ Passed")
    
    print("3. Testing container auditor...")
    tester.test_container_auditor()
    print("   ✅ Passed")
    
    print("4. Testing auditor initialization...")
    tester.test_auditor_initialization()
    print("   ✅ Passed")
    
    print("\n✅ All basic tests passed!")