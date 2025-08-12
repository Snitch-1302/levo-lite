#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CI/CD Test Script for LevoLite
Runs all security tests and generates summary for GitHub Actions
"""

import os
import sys
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Set UTF-8 encoding for Windows compatibility
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)
                                  
def run_command(command, description):
    """Run a command and return success status"""
    print(f"🔍 {description}...")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {description} completed successfully")
            return True
        else:
            print(f"❌ {description} failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ {description} failed: {e}")
        return False

def analyze_results():
    """Analyze all test results and generate summary"""
    print("📊 Analyzing test results...")
    
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tests": {},
        "issues": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "policy_violations": 0,
        "pii_exposures": 0,
        "overall_status": "PASS"
    }
    
    # Check vulnerability report
    if os.path.exists("vulnerability_report.json"):
        try:
            with open("vulnerability_report.json", "r") as f:
                vuln_data = json.load(f)
            
            summary["tests"]["vulnerability"] = {
                "status": "COMPLETE",
                "vulnerabilities": len(vuln_data.get("vulnerabilities", [])),
                "critical": sum(1 for v in vuln_data.get("vulnerabilities", []) 
                              if v.get("severity") == "critical"),
                "high": sum(1 for v in vuln_data.get("vulnerabilities", []) 
                           if v.get("severity") == "high"),
                "medium": sum(1 for v in vuln_data.get("vulnerabilities", []) 
                            if v.get("severity") == "medium"),
                "low": sum(1 for v in vuln_data.get("vulnerabilities", []) 
                          if v.get("severity") == "low")
            }
            
            summary["issues"]["critical"] += summary["tests"]["vulnerability"]["critical"]
            summary["issues"]["high"] += summary["tests"]["vulnerability"]["high"]
            summary["issues"]["medium"] += summary["tests"]["vulnerability"]["medium"]
            summary["issues"]["low"] += summary["tests"]["vulnerability"]["low"]
            
        except Exception as e:
            summary["tests"]["vulnerability"] = {"status": "ERROR", "error": str(e)}
    else:
        summary["tests"]["vulnerability"] = {"status": "NOT_FOUND"}
    
    # Check sensitive data report
    if os.path.exists("sensitive_report.json"):
        try:
            with open("sensitive_report.json", "r") as f:
                sensitive_data = json.load(f)
            
            summary["tests"]["sensitive"] = {
                "status": "COMPLETE",
                "matches": len(sensitive_data.get("matches", [])),
                "critical": sum(1 for m in sensitive_data.get("matches", []) 
                              if m.get("exposure_risk") == "critical"),
                "high": sum(1 for m in sensitive_data.get("matches", []) 
                           if m.get("exposure_risk") == "high"),
                "medium": sum(1 for m in sensitive_data.get("matches", []) 
                            if m.get("exposure_risk") == "medium"),
                "low": sum(1 for m in sensitive_data.get("matches", []) 
                          if m.get("exposure_risk") == "low")
            }
            
            summary["issues"]["critical"] += summary["tests"]["sensitive"]["critical"]
            summary["issues"]["high"] += summary["tests"]["sensitive"]["high"]
            summary["issues"]["medium"] += summary["tests"]["sensitive"]["medium"]
            summary["issues"]["low"] += summary["tests"]["sensitive"]["low"]
            summary["pii_exposures"] = summary["tests"]["sensitive"]["matches"]
            
        except Exception as e:
            summary["tests"]["sensitive"] = {"status": "ERROR", "error": str(e)}
    else:
        summary["tests"]["sensitive"] = {"status": "NOT_FOUND"}
    
    # Check policy report
    if os.path.exists("policy_report.json"):
        try:
            with open("policy_report.json", "r") as f:
                policy_data = json.load(f)
            
            summary["tests"]["policy"] = {
                "status": "COMPLETE",
                "total_violations": policy_data.get("total_violations", 0),
                "critical": policy_data.get("violations_by_severity", {}).get("critical", 0),
                "high": policy_data.get("violations_by_severity", {}).get("high", 0),
                "medium": policy_data.get("violations_by_severity", {}).get("medium", 0),
                "low": policy_data.get("violations_by_severity", {}).get("low", 0)
            }
            
            summary["issues"]["critical"] += summary["tests"]["policy"]["critical"]
            summary["issues"]["high"] += summary["tests"]["policy"]["high"]
            summary["issues"]["medium"] += summary["tests"]["policy"]["medium"]
            summary["issues"]["low"] += summary["tests"]["policy"]["low"]
            summary["policy_violations"] = summary["tests"]["policy"]["total_violations"]
            
        except Exception as e:
            summary["tests"]["policy"] = {"status": "ERROR", "error": str(e)}
    else:
        summary["tests"]["policy"] = {"status": "NOT_FOUND"}
    
    # Check OpenAPI generation
    if os.path.exists("openapi.yaml"):
        summary["tests"]["openapi"] = {"status": "COMPLETE"}
    else:
        summary["tests"]["openapi"] = {"status": "NOT_FOUND"}
    
    # Determine overall status
    if summary["issues"]["critical"] > 0:
        summary["overall_status"] = "CRITICAL"
    elif summary["issues"]["high"] > 0:
        summary["overall_status"] = "HIGH"
    elif summary["policy_violations"] > 0:
        summary["overall_status"] = "WARNING"
    else:
        summary["overall_status"] = "PASS"
    
    return summary

def generate_markdown_report(summary):
    """Generate markdown report from summary"""
    md = f"""# 🔒 API Security Analysis Report

**Generated:** {summary['timestamp']}  
**Overall Status:** {summary['overall_status']}

## 📊 Summary

- **Critical Issues:** {summary['issues']['critical']}
- **High Issues:** {summary['issues']['high']}
- **Medium Issues:** {summary['issues']['medium']}
- **Low Issues:** {summary['issues']['low']}
- **Policy Violations:** {summary['policy_violations']}
- **PII Exposures:** {summary['pii_exposures']}

## 🔍 Test Results

### Vulnerability Scanner
- **Status:** {summary['tests']['vulnerability']['status']}
"""
    
    if summary['tests']['vulnerability']['status'] == 'COMPLETE':
        md += f"""
- **Total Vulnerabilities:** {summary['tests']['vulnerability']['vulnerabilities']}
- **Critical:** {summary['tests']['vulnerability']['critical']}
- **High:** {summary['tests']['vulnerability']['high']}
- **Medium:** {summary['tests']['vulnerability']['medium']}
- **Low:** {summary['tests']['vulnerability']['low']}
"""
    
    md += f"""
### Sensitive Data Analysis
- **Status:** {summary['tests']['sensitive']['status']}
"""
    
    if summary['tests']['sensitive']['status'] == 'COMPLETE':
        md += f"""
- **Total Matches:** {summary['tests']['sensitive']['matches']}
- **Critical:** {summary['tests']['sensitive']['critical']}
- **High:** {summary['tests']['sensitive']['high']}
- **Medium:** {summary['tests']['sensitive']['medium']}
- **Low:** {summary['tests']['sensitive']['low']}
"""
    
    md += f"""
### Policy Engine
- **Status:** {summary['tests']['policy']['status']}
"""
    
    if summary['tests']['policy']['status'] == 'COMPLETE':
        md += f"""
- **Total Violations:** {summary['tests']['policy']['total_violations']}
- **Critical:** {summary['tests']['policy']['critical']}
- **High:** {summary['tests']['policy']['high']}
- **Medium:** {summary['tests']['policy']['medium']}
- **Low:** {summary['tests']['policy']['low']}
"""
    
    md += f"""
### OpenAPI Generation
- **Status:** {summary['tests']['openapi']['status']}

## 🚨 Recommendations

"""
    
    if summary['issues']['critical'] > 0:
        md += "- 🚨 **CRITICAL**: Address all critical security issues immediately\n"
        md += "- 🔐 Review authentication and authorization mechanisms\n"
        md += "- 🛡️ Implement proper input validation and sanitization\n"
    
    if summary['policy_violations'] > 0:
        md += "- 📜 Review and update security policies\n"
        md += "- 🔍 Monitor API traffic for policy compliance\n"
    
    if summary['pii_exposures'] > 0:
        md += "- 🧬 Implement data masking for sensitive information\n"
        md += "- 🔒 Ensure proper encryption for PII data\n"
    
    if summary['overall_status'] == 'PASS':
        md += "- ✅ All security checks passed!\n"
    
    return md

def main():
    """Main CI/CD test function"""
    print("🚀 LevoLite CI/CD Security Test")
    print("=" * 50)
    
    # Run all security tests
    tests = [
        ("python discovery/cli.py list", "API Discovery"),
        ("python openapi/cli.py generate --output openapi.yaml", "OpenAPI Generation"),
        ("python vulnerability/cli.py scan --output vulnerability_report.json", "Vulnerability Scanner"),
        ("python sensitive/cli.py test --output sensitive_report.json", "Sensitive Data Analysis"),
        ("python policy/cli.py test --output policy_report.json", "Policy Engine")
    ]
    
    results = {}
    for command, description in tests:
        results[description] = run_command(command, description)
    
    # Analyze results
    summary = analyze_results()
    
    # Generate reports
    with open("ci_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    with open("ci_report.md", "w") as f:
        f.write(generate_markdown_report(summary))
    
    # Print summary
    print(f"\n📊 CI/CD Test Summary")
    print(f"{'='*50}")
    print(f"Overall Status: {summary['overall_status']}")
    print(f"Critical Issues: {summary['issues']['critical']}")
    print(f"High Issues: {summary['issues']['high']}")
    print(f"Policy Violations: {summary['policy_violations']}")
    print(f"PII Exposures: {summary['pii_exposures']}")
    
    # Set exit code based on issues
    if summary['issues']['critical'] > 0 or summary['issues']['high'] > 0:
        print(f"\n❌ Build will fail due to security issues")
        sys.exit(1)
    elif summary['policy_violations'] > 0:
        print(f"\n⚠️ Build will fail due to policy violations")
        sys.exit(1)
    else:
        print(f"\n✅ All security checks passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()