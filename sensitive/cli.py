#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI interface for LevoLite Sensitive Data Classifier
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from models import ClassifierConfig, DetectionPattern, SensitiveDataType, SeverityLevel
from classifier import SensitiveDataClassifier

# Set UTF-8 encoding for Windows compatibility
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)
                                  
def create_default_config() -> ClassifierConfig:
    """Create default classifier configuration"""
    return ClassifierConfig(
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

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description="LevoLite Sensitive Data Classifier")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze API traffic for sensitive data')
    analyze_parser.add_argument('--input', required=True,
                              help='Input file with API traffic data (JSON)')
    analyze_parser.add_argument('--output', default='sensitive_data_report.json',
                              help='Output report file (default: sensitive_data_report.json)')
    analyze_parser.add_argument('--format', choices=['json', 'html', 'markdown'],
                              default='json',
                              help='Report format (default: json)')
    analyze_parser.add_argument('--target-api', default='http://localhost:8000',
                              help='Target API URL (default: http://localhost:8000)')
    analyze_parser.add_argument('--mask-data', action='store_true', default=True,
                              help='Mask sensitive data in output (default: true)')
    analyze_parser.add_argument('--log-sensitive', action='store_true',
                              help='Log sensitive data values (use with caution)')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test sensitive data detection on sample data')
    test_parser.add_argument('--sample', choices=['login', 'profile', 'payment', 'all'],
                           default='all',
                           help='Sample data to test (default: all)')
    test_parser.add_argument('--output', default='test_sensitive_data.json',
                           help='Output file (default: test_sensitive_data.json)')
    
    # Patterns command
    patterns_parser = subparsers.add_parser('patterns', help='List or manage detection patterns')
    patterns_parser.add_argument('--list', action='store_true',
                               help='List all detection patterns')
    patterns_parser.add_argument('--add', nargs=3,
                               metavar=('NAME', 'TYPE', 'PATTERN'),
                               help='Add custom pattern (name type regex_pattern)')
    patterns_parser.add_argument('--remove', metavar='NAME',
                               help='Remove custom pattern by name')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report from analysis results')
    report_parser.add_argument('--input', required=True,
                             help='Input analysis results file')
    report_parser.add_argument('--output', default='sensitive_data_report.html',
                             help='Output report file')
    report_parser.add_argument('--format', choices=['html', 'markdown', 'json'],
                             default='html',
                             help='Report format (default: html)')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show classifier information')
    info_parser.add_argument('--detailed', action='store_true',
                           help='Show detailed pattern information')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'analyze':
        run_analysis(args)
    elif args.command == 'test':
        run_test(args)
    elif args.command == 'patterns':
        manage_patterns(args)
    elif args.command == 'report':
        generate_report(args)
    elif args.command == 'info':
        show_info(args)

def run_analysis(args):
    """Run sensitive data analysis"""
    print(f"🔍 Analyzing sensitive data in {args.input}")
    
    if not os.path.exists(args.input):
        print(f"❌ Input file not found: {args.input}")
        sys.exit(1)
    
    try:
        # Load traffic data
        with open(args.input, 'r') as f:
            traffic_data = json.load(f)
        
        # Create classifier config
        config = create_default_config()
        config.mask_detected_data = args.mask_data
        config.log_sensitive_data = args.log_sensitive
        
        # Create classifier
        classifier = SensitiveDataClassifier(config)
        
        # Analyze each request/response
        analyses = []
        for item in traffic_data:
            if 'request' in item and 'response' in item:
                analysis = classifier.analyze_request_response(
                    endpoint=item.get('endpoint', ''),
                    method=item.get('method', 'GET'),
                    request_headers=item['request'].get('headers', {}),
                    request_body=item['request'].get('body'),
                    request_params=item['request'].get('params', {}),
                    response_headers=item['response'].get('headers', {}),
                    response_body=item['response'].get('body'),
                    response_status=item['response'].get('status', 200)
                )
                analyses.append(analysis)
        
        # Generate report
        report = classifier.generate_report(analyses, args.target_api)
        
        # Save report
        save_report(report, args.output, args.format)
        
        # Print summary
        print_summary(report)
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        sys.exit(1)

def run_test(args):
    """Run test with sample data"""
    print(f"🧪 Testing sensitive data detection with sample data")
    
    # Create sample data
    sample_data = create_sample_data(args.sample)
    
    # Create classifier
    config = create_default_config()
    classifier = SensitiveDataClassifier(config)
    
    # Analyze sample data
    analyses = []
    for item in sample_data:
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
    
    # Generate report
    report = classifier.generate_report(analyses, "http://localhost:8000")
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(report.dict(), f, indent=2, default=str)
    
    print(f"✅ Test completed. Results saved to {args.output}")
    print_summary(report)

def create_sample_data(sample_type: str) -> list:
    """Create sample data for testing"""
    samples = []
    
    if sample_type in ['login', 'all']:
        samples.append({
            'endpoint': '/login',
            'method': 'POST',
            'request': {
                'headers': {'Content-Type': 'application/json'},
                'body': {
                    'username': 'user@example.com',
                    'password': 'secretpassword123',
                    'remember_me': True
                },
                'params': {}
            },
            'response': {
                'headers': {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'},
                'body': {
                    'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                    'user_id': 123,
                    'email': 'user@example.com'
                },
                'status': 200
            }
        })
    
    if sample_type in ['profile', 'all']:
        samples.append({
            'endpoint': '/profile',
            'method': 'GET',
            'request': {
                'headers': {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'},
                'body': None,
                'params': {}
            },
            'response': {
                'headers': {'Content-Type': 'application/json'},
                'body': {
                    'user_id': 123,
                    'full_name': 'John Doe',
                    'email': 'john.doe@example.com',
                    'phone': '555-123-4567',
                    'address': '123 Main St, Anytown, USA',
                    'ssn': '123-45-6789',
                    'date_of_birth': '1990-01-15'
                },
                'status': 200
            }
        })
    
    if sample_type in ['payment', 'all']:
        samples.append({
            'endpoint': '/payment',
            'method': 'POST',
            'request': {
                'headers': {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                },
                'body': {
                    'card_number': '4111-1111-1111-1111',
                    'expiry_date': '12/25',
                    'cvv': '123',
                    'amount': 99.99,
                    'currency': 'USD'
                },
                'params': {}
            },
            'response': {
                'headers': {'Content-Type': 'application/json'},
                'body': {
                    'transaction_id': 'txn_123456789',
                    'status': 'success',
                    'amount': 99.99,
                    'currency': 'USD'
                },
                'status': 200
            }
        })
    
    return samples

def manage_patterns(args):
    """Manage detection patterns"""
    if args.list:
        show_patterns()
    elif args.add:
        add_pattern(args.add[0], args.add[1], args.add[2])
    elif args.remove:
        remove_pattern(args.remove)
    else:
        print("Use --list, --add, or --remove")

def show_patterns():
    """Show all detection patterns"""
    config = create_default_config()
    classifier = SensitiveDataClassifier(config)
    
    print("📋 Detection Patterns")
    print("=" * 60)
    
    for pattern in classifier.patterns:
        print(f"\n🔍 {pattern.name}")
        print(f"   Type: {pattern.data_type.value}")
        print(f"   Risk Level: {pattern.risk_level.value}")
        print(f"   Confidence: {pattern.confidence}")
        print(f"   Description: {pattern.description}")
        print(f"   Pattern: {pattern.regex_pattern}")

def add_pattern(name: str, data_type: str, regex_pattern: str):
    """Add custom detection pattern"""
    try:
        # Validate data type
        data_type_enum = SensitiveDataType(data_type)
        
        # Create pattern
        pattern = DetectionPattern(
            name=name,
            data_type=data_type_enum,
            regex_pattern=regex_pattern,
            confidence=0.7,
            risk_level=SeverityLevel.MEDIUM,
            description=f"Custom pattern: {name}"
        )
        
        # Save to custom patterns file
        custom_patterns_file = "custom_patterns.json"
        patterns = []
        
        if os.path.exists(custom_patterns_file):
            with open(custom_patterns_file, 'r') as f:
                patterns = json.load(f)
        
        patterns.append(pattern.dict())
        
        with open(custom_patterns_file, 'w') as f:
            json.dump(patterns, f, indent=2)
        
        print(f"✅ Added custom pattern: {name}")
        
    except Exception as e:
        print(f"❌ Error adding pattern: {e}")

def remove_pattern(name: str):
    """Remove custom detection pattern"""
    custom_patterns_file = "custom_patterns.json"
    
    if not os.path.exists(custom_patterns_file):
        print("❌ No custom patterns file found")
        return
    
    try:
        with open(custom_patterns_file, 'r') as f:
            patterns = json.load(f)
        
        # Find and remove pattern
        patterns = [p for p in patterns if p['name'] != name]
        
        with open(custom_patterns_file, 'w') as f:
            json.dump(patterns, f, indent=2)
        
        print(f"✅ Removed custom pattern: {name}")
        
    except Exception as e:
        print(f"❌ Error removing pattern: {e}")

def generate_report(args):
    """Generate report from analysis results"""
    print(f"📊 Generating report from {args.input}")
    
    if not os.path.exists(args.input):
        print(f"❌ Input file not found: {args.input}")
        sys.exit(1)
    
    try:
        with open(args.input, 'r') as f:
            data = json.load(f)
        
        # Convert back to report object
        from models import SensitiveDataReport
        report = SensitiveDataReport(**data)
        
        # Save report
        save_report(report, args.output, args.format)
        
        print(f"✅ Report generated: {args.output}")
        
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        sys.exit(1)

def show_info(args):
    """Show classifier information"""
    print("📋 Sensitive Data Classifier Information")
    print("=" * 60)
    
    config = create_default_config()
    classifier = SensitiveDataClassifier(config)
    
    print(f"Detection Patterns: {len(classifier.patterns)}")
    print(f"Data Types Supported: {len(SensitiveDataType)}")
    print(f"Risk Levels: {len(SeverityLevel)}")
    
    if args.detailed:
        print(f"\n📊 Data Types:")
        for data_type in SensitiveDataType:
            print(f"  - {data_type.value}")
        
        print(f"\n⚠️  Risk Levels:")
        for risk in SeverityLevel:
            print(f"  - {risk.value}")
        
        print(f"\n🔍 Detection Locations:")
        from models import DataLocation
        for location in DataLocation:
            print(f"  - {location.value}")

def save_report(report, output_file: str, format_type: str):
    """Save report in specified format"""
    if format_type == 'json':
        with open(output_file, 'w') as f:
            json.dump(report.dict(), f, indent=2, default=str)
    
    elif format_type == 'html':
        html_content = generate_html_report(report)
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    elif format_type == 'markdown':
        md_content = generate_markdown_report(report)
        with open(output_file, 'w') as f:
            f.write(md_content)

def generate_html_report(report) -> str:
    """Generate HTML report"""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Sensitive Data Report - {report.report_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .sensitive-data {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ff4444; background-color: #fff5f5; }}
        .critical {{ border-left-color: #ff0000; }}
        .high {{ border-left-color: #ff6600; }}
        .medium {{ border-left-color: #ffaa00; }}
        .low {{ border-left-color: #ffdd00; }}
        .risk-score {{ font-size: 24px; font-weight: bold; }}
        .risk-critical {{ color: #ff0000; }}
        .risk-high {{ color: #ff6600; }}
        .risk-medium {{ color: #ffaa00; }}
        .risk-low {{ color: #ffdd00; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Sensitive Data Report</h1>
        <p><strong>Report:</strong> {report.report_name}</p>
        <p><strong>Target:</strong> {report.target_api}</p>
        <p><strong>Generated:</strong> {report.generated_at}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Requests Analyzed:</strong> {report.total_requests_analyzed}</p>
        <p><strong>Requests with Sensitive Data:</strong> {report.requests_with_sensitive_data}</p>
        <p><strong>Total Sensitive Matches:</strong> {report.total_sensitive_matches}</p>
        
        <div class="risk-score risk-{report.overall_risk_level.value}">
            Risk Score: {report.overall_risk_score:.1f}/10 ({report.overall_risk_level.value})
        </div>
    </div>
    
    <div class="breakdown">
        <h2>📈 Breakdown</h2>
        <h3>By Data Type:</h3>
        <ul>
"""
    
    for data_type, count in report.data_type_breakdown.items():
        html += f"            <li>{data_type.value}: {count}</li>\n"
    
    html += """        </ul>
        
        <h3>By Risk Level:</h3>
        <ul>
"""
    
    for risk, count in report.risk_breakdown.items():
        html += f"            <li>{risk.value}: {count}</li>\n"
    
    html += """        </ul>
    </div>
    
    <div class="compliance">
        <h2>⚠️ Compliance Issues</h2>
        <ul>
"""
    
    for issue in report.compliance_issues:
        html += f"            <li>{issue}</li>\n"
    
    html += """        </ul>
    </div>
</body>
</html>
    """
    
    return html

def generate_markdown_report(report) -> str:
    """Generate Markdown report"""
    md = f"""# 🔍 Sensitive Data Report

**Report:** {report.report_name}  
**Target:** {report.target_api}  
**Generated:** {report.generated_at}

## 📊 Summary

- **Total Requests Analyzed:** {report.total_requests_analyzed}
- **Requests with Sensitive Data:** {report.requests_with_sensitive_data}
- **Total Sensitive Matches:** {report.total_sensitive_matches}
- **Risk Score:** {report.overall_risk_score:.1f}/10 ({report.overall_risk_level.value})

## 📈 Breakdown

### By Data Type:
"""
    
    for data_type, count in report.data_type_breakdown.items():
        md += f"- {data_type.value}: {count}\n"
    
    md += "\n### By Risk Level:\n"
    
    for risk, count in report.risk_breakdown.items():
        md += f"- {risk.value}: {count}\n"
    
    md += "\n## ⚠️ Compliance Issues\n"
    
    for issue in report.compliance_issues:
        md += f"- {issue}\n"
    
    return md

def print_summary(report):
    """Print analysis summary"""
    print(f"\n{'='*60}")
    print(f"📊 SENSITIVE DATA ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Total Requests Analyzed: {report.total_requests_analyzed}")
    print(f"Requests with Sensitive Data: {report.requests_with_sensitive_data}")
    print(f"Total Sensitive Matches: {report.total_sensitive_matches}")
    print(f"Risk Score: {report.overall_risk_score:.1f}/10 ({report.overall_risk_level.value})")
    
    if report.total_sensitive_matches > 0:
        print(f"\n🚨 SENSITIVE DATA FOUND:")
        print(f"By Data Type:")
        for data_type, count in report.data_type_breakdown.items():
            print(f"  - {data_type.value}: {count}")
        
        print(f"By Risk Level:")
        for risk, count in report.risk_breakdown.items():
            print(f"  - {risk.value}: {count}")
        
        if report.compliance_issues:
            print(f"\n⚠️ Compliance Issues:")
            for issue in report.compliance_issues:
                print(f"  - {issue}")
    else:
        print(f"\n✅ No sensitive data found!")

if __name__ == "__main__":
    main()