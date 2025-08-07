#!/usr/bin/env python3
"""
Test script for LevoLite Policy Engine
This script demonstrates the policy evaluation functionality
"""

import os
import sys
import json
from policy.engine import PolicyEngine
from policy.models import PolicyConfig

def create_sample_traffic_data():
    """Create sample API traffic data for testing"""
    return [
        {
            "endpoint": "/login",
            "method": "POST",
            "request": {
                "headers": {
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
                "body": {
                    "username": "user@example.com",
                    "password": "plaintextpassword123",
                    "remember_me": True
                }
            },
            "response": {
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                },
                "body": {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "user_id": 123,
                    "email": "user@example.com",
                    "expires_in": 3600
                },
                "status": 200
            }
        },
        {
            "endpoint": "/admin/users",
            "method": "GET",
            "request": {
                "headers": {},  # No authentication header
                "body": None
            },
            "response": {
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": {
                    "users": [
                        {
                            "user_id": 123,
                            "full_name": "John Doe",
                            "email": "john.doe@example.com",
                            "ssn": "123-45-6789"
                        }
                    ]
                },
                "status": 200
            }
        },
        {
            "endpoint": "/profile",
            "method": "GET",
            "request": {
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "Content-Type": "application/json"
                },
                "body": None
            },
            "response": {
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": {
                    "user_id": 123,
                    "full_name": "John Doe",
                    "email": "john.doe@example.com",
                    "phone": "555-123-4567",
                    "address": "123 Main Street, Anytown, USA 12345",
                    "ssn": "123-45-6789",
                    "date_of_birth": "1990-01-15"
                },
                "status": 200
            }
        },
        {
            "endpoint": "/api/data",
            "method": "GET",
            "request": {
                "headers": {
                    "X-Forwarded-Proto": "http",  # Non-HTTPS request
                    "Content-Type": "application/json"
                },
                "body": None
            },
            "response": {
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": {
                    "data": "sensitive_information",
                    "timestamp": "2024-01-01T00:00:00Z"
                },
                "status": 200
            }
        },
        {
            "endpoint": "/health",
            "method": "GET",
            "request": {
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": None
            },
            "response": {
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": {
                    "status": "healthy",
                    "timestamp": "2024-01-01T00:00:00Z"
                },
                "status": 200
            }
        }
    ]

def run_policy_evaluation():
    """Run policy evaluation on sample traffic"""
    print("🔍 Running policy evaluation...")
    
    # Create policy config
    config = PolicyConfig(
        enable_realtime_evaluation=True,
        enable_blocking=False,
        enable_logging=True,
        evaluate_requests=True,
        evaluate_responses=True,
        max_evaluation_time=1.0,
        generate_reports=True,
        report_format="json",
        include_evidence=True,
        policy_directory="policies"
    )
    
    # Create policy engine
    engine = PolicyEngine(config)
    
    # Get sample traffic data
    traffic_data = create_sample_traffic_data()
    
    # Evaluate each request/response
    for item in traffic_data:
        print(f"  🔍 Evaluating {item['method']} {item['endpoint']}...")
        
        evaluation = engine.evaluate_request_response(
            endpoint=item['endpoint'],
            method=item['method'],
            request_headers=item['request']['headers'],
            request_body=item['request']['body'],
            response_status=item['response']['status'],
            response_headers=item['response']['headers'],
            response_body=item['response']['body']
        )
        
        # Print immediate results
        if evaluation.violations_found > 0:
            print(f"    🚨 Found {evaluation.violations_found} policy violations")
            for violation in evaluation.violations:
                print(f"      - {violation.rule_name} ({violation.severity.value})")
        else:
            print(f"    ✅ No policy violations found")
    
    # Generate comprehensive report
    report = engine.generate_report("http://localhost:8000")
    
    return report

def show_detailed_evaluations(report):
    """Show detailed evaluation results"""
    print(f"\n📋 DETAILED EVALUATIONS")
    print(f"{'='*60}")
    
    for i, evaluation in enumerate(report.evaluations, 1):
        print(f"\n{i}. {evaluation.method} {evaluation.endpoint}")
        print(f"   Status: {evaluation.response_status}")
        print(f"   Rules Evaluated: {evaluation.rules_evaluated}")
        print(f"   Violations Found: {evaluation.violations_found}")
        print(f"   Overall Severity: {evaluation.overall_severity.value}")
        
        if evaluation.violations:
            print(f"   🚨 POLICY VIOLATIONS:")
            for violation in evaluation.violations:
                print(f"     - Rule: {violation.rule_name}")
                print(f"       Severity: {violation.severity.value}")
                print(f"       Description: {violation.description}")
                print(f"       Actions: {', '.join(violation.actions_taken)}")
                print()
        else:
            print(f"   ✅ No violations found")
        
        if evaluation.blocked:
            print(f"   🚫 REQUEST BLOCKED")

def show_violation_breakdown(report):
    """Show violation breakdown by category"""
    print(f"\n📊 VIOLATION BREAKDOWN")
    print(f"{'='*60}")
    
    # By severity
    print(f"\nBy Severity:")
    for severity, count in report.violations_by_severity.items():
        print(f"  {severity.value}: {count}")
    
    # By rule
    print(f"\nBy Rule:")
    for rule_name, count in report.violations_by_rule.items():
        print(f"  {rule_name}: {count}")
    
    # By endpoint
    print(f"\nBy Endpoint:")
    for endpoint, count in report.violations_by_endpoint.items():
        print(f"  {endpoint}: {count}")
    
    # Compliance issues
    if report.compliance_issues:
        print(f"\nCompliance Issues:")
        for issue in report.compliance_issues:
            print(f"  - {issue}")

def save_report_files(report):
    """Save report in multiple formats"""
    print(f"\n💾 Saving report files...")
    
    # Save JSON report
    with open("policy_report.json", "w") as f:
        json.dump(report.dict(), f, indent=2, default=str)
    print("✅ policy_report.json")
    
    # Save HTML report
    from policy.cli import generate_html_report
    html_content = generate_html_report(report)
    with open("policy_report.html", "w") as f:
        f.write(html_content)
    print("✅ policy_report.html")
    
    # Save Markdown report
    from policy.cli import generate_markdown_report
    md_content = generate_markdown_report(report)
    with open("policy_report.md", "w") as f:
        f.write(md_content)
    print("✅ policy_report.md")

def main():
    """Main test function"""
    print("🧪 LevoLite Policy Engine Test")
    print("=" * 60)
    
    # Run policy evaluation
    try:
        report = run_policy_evaluation()
        
        # Show results
        show_detailed_evaluations(report)
        show_violation_breakdown(report)
        
        # Save reports
        save_report_files(report)
        
        print(f"\n🎉 Policy evaluation completed!")
        print(f"\n📁 Generated reports:")
        print(f"  - policy_report.json (JSON format)")
        print(f"  - policy_report.html (HTML format)")
        print(f"  - policy_report.md (Markdown format)")
        
        print(f"\n💡 To run evaluation on your own data:")
        print(f"  python policy/cli.py evaluate --input your_traffic.json")
        print(f"  python policy/cli.py test --sample security")
        print(f"  python policy/cli.py rules --list")
        
    except Exception as e:
        print(f"❌ Policy evaluation failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 