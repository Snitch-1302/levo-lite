#!/usr/bin/env python3
"""
Test script for LevoLite Sensitive Data Classifier
This script demonstrates the sensitive data detection functionality
"""

import os
import sys
import json
import requests
from sensitive.classifier import SensitiveDataClassifier
from sensitive.models import ClassifierConfig, SensitiveDataAnalysis

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
                    "password": "secretpassword123",
                    "remember_me": True
                },
                "params": {}
            },
            "response": {
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                },
                "body": {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "user_id": 123,
                    "email": "user@example.com",
                    "expires_in": 3600
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
                "body": None,
                "params": {}
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
                    "date_of_birth": "1990-01-15",
                    "credit_score": 750
                },
                "status": 200
            }
        },
        {
            "endpoint": "/payment/process",
            "method": "POST",
            "request": {
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "Content-Type": "application/json",
                    "X-API-Key": "sk_live_1234567890abcdef"
                },
                "body": {
                    "card_number": "4111-1111-1111-1111",
                    "expiry_date": "12/25",
                    "cvv": "123",
                    "cardholder_name": "John Doe",
                    "amount": 99.99,
                    "currency": "USD",
                    "billing_address": {
                        "street": "123 Main Street",
                        "city": "Anytown",
                        "state": "CA",
                        "zip": "12345",
                        "country": "USA"
                    }
                },
                "params": {}
            },
            "response": {
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": {
                    "transaction_id": "txn_1234567890abcdef",
                    "status": "success",
                    "amount": 99.99,
                    "currency": "USD",
                    "card_last4": "1111",
                    "receipt_url": "https://receipt.example.com/txn_1234567890abcdef"
                },
                "status": 200
            }
        },
        {
            "endpoint": "/users/search",
            "method": "GET",
            "request": {
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "Content-Type": "application/json"
                },
                "body": None,
                "params": {
                    "q": "john",
                    "email": "john@example.com",
                    "phone": "555-123-4567"
                }
            },
            "response": {
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": {
                    "results": [
                        {
                            "user_id": 123,
                            "full_name": "John Doe",
                            "email": "john.doe@example.com",
                            "phone": "555-123-4567"
                        },
                        {
                            "user_id": 456,
                            "full_name": "John Smith",
                            "email": "john.smith@example.com",
                            "phone": "555-987-6543"
                        }
                    ],
                    "total": 2
                },
                "status": 200
            }
        },
        {
            "endpoint": "/admin/users",
            "method": "GET",
            "request": {
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "Content-Type": "application/json"
                },
                "body": None,
                "params": {}
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
                            "ssn": "123-45-6789",
                            "date_of_birth": "1990-01-15",
                            "credit_card": "4111-1111-1111-1111"
                        },
                        {
                            "user_id": 456,
                            "full_name": "Jane Smith",
                            "email": "jane.smith@example.com",
                            "ssn": "987-65-4321",
                            "date_of_birth": "1985-05-20",
                            "credit_card": "5555-5555-5555-5555"
                        }
                    ]
                },
                "status": 200
            }
        }
    ]

def run_sensitive_data_analysis():
    """Run sensitive data analysis on sample traffic"""
    print("🔍 Running sensitive data analysis...")
    
    # Create classifier config
    config = ClassifierConfig(
        enable_regex_detection=True,
        enable_ml_detection=False,
        enable_custom_patterns=True,
        min_confidence=0.6,
        max_value_length=1000,
        analyze_headers=True,
        analyze_body=True,
        analyze_params=True,
        mask_detected_data=True,
        log_sensitive_data=False
    )
    
    # Create classifier
    classifier = SensitiveDataClassifier(config)
    
    # Get sample traffic data
    traffic_data = create_sample_traffic_data()
    
    # Analyze each request/response
    analyses = []
    for item in traffic_data:
        print(f"  🔍 Analyzing {item['method']} {item['endpoint']}...")
        
        analysis = classifier.analyze_request_response(
            endpoint=item['endpoint'],
            method=item['method'],
            request_headers=item['request']['headers'],
            request_body=item['request']['body'],
            request_params=item['request']['params'],
            response_headers=item['response']['headers'],
            response_body=item['response']['body'],
            response_status=item['response']['status']
        )
        
        analyses.append(analysis)
        
        # Print immediate findings
        if analysis.total_matches > 0:
            print(f"    🚨 Found {analysis.total_matches} sensitive data matches")
            for match in analysis.sensitive_data_found:
                print(f"      - {match.data_type.value}: {match.field_name} ({match.exposure_risk.value})")
        else:
            print(f"    ✅ No sensitive data found")
    
    # Generate comprehensive report
    report = classifier.generate_report(analyses, "http://localhost:8000")
    
    return report

def show_detailed_findings(report):
    """Show detailed findings from the analysis"""
    print(f"\n📋 DETAILED FINDINGS")
    print(f"{'='*60}")
    
    for i, analysis in enumerate(report.analyses, 1):
        print(f"\n{i}. {analysis.method} {analysis.endpoint}")
        print(f"   Status: {analysis.response_status}")
        print(f"   Risk Level: {analysis.overall_risk.value}")
        print(f"   Sensitive Data Matches: {analysis.total_matches}")
        
        if analysis.sensitive_data_found:
            print(f"   🚨 SENSITIVE DATA FOUND:")
            for match in analysis.sensitive_data_found:
                print(f"     - Type: {match.data_type.value}")
                print(f"       Location: {match.location.value}")
                print(f"       Field: {match.field_name}")
                print(f"       Value: {match.value}")
                print(f"       Risk: {match.exposure_risk.value}")
                print(f"       Confidence: {match.confidence}")
                print()
        
        if analysis.recommendations:
            print(f"   💡 Recommendations:")
            for rec in analysis.recommendations:
                print(f"     - {rec}")
            print()

def show_statistics(report):
    """Show statistical breakdown"""
    print(f"\n📊 STATISTICAL BREAKDOWN")
    print(f"{'='*60}")
    
    print(f"\nBy Data Type:")
    for data_type, count in report.data_type_breakdown.items():
        print(f"  {data_type.value}: {count}")
    
    print(f"\nBy Location:")
    for location, count in report.location_breakdown.items():
        print(f"  {location.value}: {count}")
    
    print(f"\nBy Risk Level:")
    for risk, count in report.risk_breakdown.items():
        print(f"  {risk.value}: {count}")
    
    print(f"\nCompliance Issues:")
    for issue in report.compliance_issues:
        print(f"  - {issue}")

def save_report_files(report):
    """Save report in multiple formats"""
    print(f"\n💾 Saving report files...")
    
    # Save JSON report
    with open("sensitive_data_report.json", "w") as f:
        json.dump(report.dict(), f, indent=2, default=str)
    print("✅ sensitive_data_report.json")
    
    # Save HTML report
    from sensitive.cli import generate_html_report
    html_content = generate_html_report(report)
    with open("sensitive_data_report.html", "w") as f:
        f.write(html_content)
    print("✅ sensitive_data_report.html")
    
    # Save Markdown report
    from sensitive.cli import generate_markdown_report
    md_content = generate_markdown_report(report)
    with open("sensitive_data_report.md", "w") as f:
        f.write(md_content)
    print("✅ sensitive_data_report.md")

def main():
    """Main test function"""
    print("🧪 LevoLite Sensitive Data Classifier Test")
    print("=" * 60)
    
    # Run sensitive data analysis
    try:
        report = run_sensitive_data_analysis()
        
        # Show results
        show_detailed_findings(report)
        show_statistics(report)
        
        # Save reports
        save_report_files(report)
        
        print(f"\n🎉 Sensitive data analysis completed!")
        print(f"\n📁 Generated reports:")
        print(f"  - sensitive_data_report.json (JSON format)")
        print(f"  - sensitive_data_report.html (HTML format)")
        print(f"  - sensitive_data_report.md (Markdown format)")
        
        print(f"\n💡 To run analysis on your own data:")
        print(f"  python sensitive/cli.py analyze --input your_traffic.json")
        print(f"  python sensitive/cli.py test --sample payment")
        print(f"  python sensitive/cli.py patterns --list")
        
    except Exception as e:
        print(f"❌ Sensitive data analysis failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 