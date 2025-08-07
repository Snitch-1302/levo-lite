#!/usr/bin/env python3
"""
CLI interface for LevoLite Policy Engine
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from models import PolicyConfig, PolicyRule, PolicyCondition, PolicyAction
from engine import PolicyEngine

def create_default_config() -> PolicyConfig:
    """Create default policy engine configuration"""
    return PolicyConfig(
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

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description="LevoLite Policy Engine")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Evaluate command
    evaluate_parser = subparsers.add_parser('evaluate', help='Evaluate API traffic against policies')
    evaluate_parser.add_argument('--input', required=True,
                               help='Input file with API traffic data (JSON)')
    evaluate_parser.add_argument('--output', default='policy_report.json',
                               help='Output report file (default: policy_report.json)')
    evaluate_parser.add_argument('--format', choices=['json', 'html', 'markdown'],
                               default='json',
                               help='Report format (default: json)')
    evaluate_parser.add_argument('--target-api', default='http://localhost:8000',
                               help='Target API URL (default: http://localhost:8000)')
    evaluate_parser.add_argument('--policy-dir', default='policies',
                               help='Policy directory (default: policies)')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test policy evaluation with sample data')
    test_parser.add_argument('--sample', choices=['security', 'compliance', 'all'],
                           default='all',
                           help='Sample data to test (default: all)')
    test_parser.add_argument('--output', default='test_policy_report.json',
                           help='Output file (default: test_policy_report.json)')
    
    # Rules command
    rules_parser = subparsers.add_parser('rules', help='Manage policy rules')
    rules_parser.add_argument('--list', action='store_true',
                            help='List all policy rules')
    rules_parser.add_argument('--add', metavar='FILE',
                            help='Add policy rule from YAML file')
    rules_parser.add_argument('--remove', metavar='RULE_NAME',
                            help='Remove policy rule by name')
    rules_parser.add_argument('--enable', metavar='RULE_NAME',
                            help='Enable policy rule')
    rules_parser.add_argument('--disable', metavar='RULE_NAME',
                            help='Disable policy rule')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report from evaluation results')
    report_parser.add_argument('--input', required=True,
                             help='Input evaluation results file')
    report_parser.add_argument('--output', default='policy_report.html',
                             help='Output report file')
    report_parser.add_argument('--format', choices=['html', 'markdown', 'json'],
                             default='html',
                             help='Report format (default: html)')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show policy engine information')
    info_parser.add_argument('--detailed', action='store_true',
                           help='Show detailed policy information')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'evaluate':
        run_evaluation(args)
    elif args.command == 'test':
        run_test(args)
    elif args.command == 'rules':
        manage_rules(args)
    elif args.command == 'report':
        generate_report(args)
    elif args.command == 'info':
        show_info(args)

def run_evaluation(args):
    """Run policy evaluation on API traffic"""
    print(f"🔍 Evaluating policies against {args.input}")
    
    if not os.path.exists(args.input):
        print(f"❌ Input file not found: {args.input}")
        sys.exit(1)
    
    try:
        # Load traffic data
        with open(args.input, 'r') as f:
            traffic_data = json.load(f)
        
        # Create policy config
        config = create_default_config()
        config.policy_directory = args.policy_dir
        
        # Create policy engine
        engine = PolicyEngine(config)
        
        # Evaluate each request/response
        for item in traffic_data:
            if 'request' in item and 'response' in item:
                evaluation = engine.evaluate_request_response(
                    endpoint=item.get('endpoint', ''),
                    method=item.get('method', 'GET'),
                    request_headers=item['request'].get('headers', {}),
                    request_body=item['request'].get('body'),
                    response_status=item['response'].get('status', 200),
                    response_headers=item['response'].get('headers', {}),
                    response_body=item['response'].get('body')
                )
        
        # Generate report
        report = engine.generate_report(args.target_api)
        
        # Save report
        save_report(report, args.output, args.format)
        
        # Print summary
        print_summary(report)
        
    except Exception as e:
        print(f"❌ Evaluation failed: {e}")
        sys.exit(1)

def run_test(args):
    """Run test with sample data"""
    print(f"🧪 Testing policy evaluation with sample data")
    
    # Create sample traffic data
    sample_data = create_sample_traffic_data(args.sample)
    
    # Create policy engine
    config = create_default_config()
    engine = PolicyEngine(config)
    
    # Evaluate sample data
    for item in sample_data:
        evaluation = engine.evaluate_request_response(
            endpoint=item['endpoint'],
            method=item['method'],
            request_headers=item['request']['headers'],
            request_body=item['request']['body'],
            response_status=item['response']['status'],
            response_headers=item['response']['headers'],
            response_body=item['response']['body']
        )
    
    # Generate report
    report = engine.generate_report("http://localhost:8000")
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(report.dict(), f, indent=2, default=str)
    
    print(f"✅ Test completed. Results saved to {args.output}")
    print_summary(report)

def create_sample_traffic_data(sample_type: str) -> list:
    """Create sample traffic data for testing"""
    samples = []
    
    if sample_type in ['security', 'all']:
        # Security violation samples
        samples.extend([
            {
                "endpoint": "/login",
                "method": "POST",
                "request": {
                    "headers": {"Content-Type": "application/json"},
                    "body": {"username": "user", "password": "plaintext123"}
                },
                "response": {
                    "headers": {"Content-Type": "application/json"},
                    "body": {"status": "success"},
                    "status": 200
                }
            },
            {
                "endpoint": "/admin/users",
                "method": "GET",
                "request": {
                    "headers": {},  # No auth header
                    "body": None
                },
                "response": {
                    "headers": {"Content-Type": "application/json"},
                    "body": {"users": []},
                    "status": 200
                }
            }
        ])
    
    if sample_type in ['compliance', 'all']:
        # Compliance violation samples
        samples.extend([
            {
                "endpoint": "/profile",
                "method": "GET",
                "request": {
                    "headers": {"Authorization": "Bearer token"},
                    "body": None
                },
                "response": {
                    "headers": {"Content-Type": "application/json"},
                    "body": {
                        "ssn": "123-45-6789",
                        "email": "user@example.com"
                    },
                    "status": 200
                }
            },
            {
                "endpoint": "/api/data",
                "method": "GET",
                "request": {
                    "headers": {"X-Forwarded-Proto": "http"},  # Non-HTTPS
                    "body": None
                },
                "response": {
                    "headers": {"Content-Type": "application/json"},
                    "body": {"data": "sensitive"},
                    "status": 200
                }
            }
        ])
    
    return samples

def manage_rules(args):
    """Manage policy rules"""
    if args.list:
        list_rules()
    elif args.add:
        add_rule(args.add)
    elif args.remove:
        remove_rule(args.remove)
    elif args.enable:
        enable_rule(args.enable)
    elif args.disable:
        disable_rule(args.disable)
    else:
        print("Use --list, --add, --remove, --enable, or --disable")

def list_rules():
    """List all policy rules"""
    config = create_default_config()
    engine = PolicyEngine(config)
    
    print("📋 Policy Rules")
    print("=" * 60)
    
    for rule in engine.rules:
        print(f"\n🔍 {rule.name}")
        print(f"   Type: {rule.rule_type.value}")
        print(f"   Severity: {rule.severity.value}")
        print(f"   Enabled: {rule.enabled}")
        print(f"   Description: {rule.description}")
        print(f"   Conditions: {len(rule.conditions)}")
        print(f"   Actions: {len(rule.actions)}")

def add_rule(yaml_file: str):
    """Add policy rule from YAML file"""
    if not os.path.exists(yaml_file):
        print(f"❌ Rule file not found: {yaml_file}")
        return
    
    try:
        import yaml
        with open(yaml_file, 'r') as f:
            rule_data = yaml.safe_load(f)
        
        # Copy to policies directory
        config = create_default_config()
        policy_dir = Path(config.policy_directory)
        policy_dir.mkdir(exist_ok=True)
        
        target_file = policy_dir / f"{rule_data.get('name', 'custom')}.yaml"
        with open(target_file, 'w') as f:
            yaml.dump(rule_data, f, default_flow_style=False, indent=2)
        
        print(f"✅ Added rule: {rule_data.get('name', 'custom')}")
        
    except Exception as e:
        print(f"❌ Error adding rule: {e}")

def remove_rule(rule_name: str):
    """Remove policy rule by name"""
    config = create_default_config()
    policy_dir = Path(config.policy_directory)
    
    # Find and remove rule file
    for yaml_file in policy_dir.glob("*.yaml"):
        try:
            import yaml
            with open(yaml_file, 'r') as f:
                rule_data = yaml.safe_load(f)
            
            if rule_data.get('name') == rule_name:
                yaml_file.unlink()
                print(f"✅ Removed rule: {rule_name}")
                return
                
        except Exception as e:
            print(f"❌ Error checking rule file {yaml_file}: {e}")
    
    print(f"❌ Rule not found: {rule_name}")

def enable_rule(rule_name: str):
    """Enable policy rule"""
    config = create_default_config()
    policy_dir = Path(config.policy_directory)
    
    for yaml_file in policy_dir.glob("*.yaml"):
        try:
            import yaml
            with open(yaml_file, 'r') as f:
                rule_data = yaml.safe_load(f)
            
            if rule_data.get('name') == rule_name:
                rule_data['enabled'] = True
                with open(yaml_file, 'w') as f:
                    yaml.dump(rule_data, f, default_flow_style=False, indent=2)
                print(f"✅ Enabled rule: {rule_name}")
                return
                
        except Exception as e:
            print(f"❌ Error updating rule file {yaml_file}: {e}")
    
    print(f"❌ Rule not found: {rule_name}")

def disable_rule(rule_name: str):
    """Disable policy rule"""
    config = create_default_config()
    policy_dir = Path(config.policy_directory)
    
    for yaml_file in policy_dir.glob("*.yaml"):
        try:
            import yaml
            with open(yaml_file, 'r') as f:
                rule_data = yaml.safe_load(f)
            
            if rule_data.get('name') == rule_name:
                rule_data['enabled'] = False
                with open(yaml_file, 'w') as f:
                    yaml.dump(rule_data, f, default_flow_style=False, indent=2)
                print(f"✅ Disabled rule: {rule_name}")
                return
                
        except Exception as e:
            print(f"❌ Error updating rule file {yaml_file}: {e}")
    
    print(f"❌ Rule not found: {rule_name}")

def generate_report(args):
    """Generate report from evaluation results"""
    print(f"📊 Generating report from {args.input}")
    
    if not os.path.exists(args.input):
        print(f"❌ Input file not found: {args.input}")
        sys.exit(1)
    
    try:
        with open(args.input, 'r') as f:
            data = json.load(f)
        
        # Convert back to report object
        from models import PolicyReport
        report = PolicyReport(**data)
        
        # Save report
        save_report(report, args.output, args.format)
        
        print(f"✅ Report generated: {args.output}")
        
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        sys.exit(1)

def show_info(args):
    """Show policy engine information"""
    print("📋 Policy Engine Information")
    print("=" * 60)
    
    config = create_default_config()
    engine = PolicyEngine(config)
    
    print(f"Policy Directory: {config.policy_directory}")
    print(f"Total Rules Loaded: {len(engine.rules)}")
    print(f"Enabled Rules: {len([r for r in engine.rules if r.enabled])}")
    
    print(f"\nRule Types:")
    rule_types = {}
    for rule in engine.rules:
        rule_types[rule.rule_type.value] = rule_types.get(rule.rule_type.value, 0) + 1
    
    for rule_type, count in rule_types.items():
        print(f"  - {rule_type}: {count}")
    
    print(f"\nSeverity Levels:")
    severity_levels = {}
    for rule in engine.rules:
        severity_levels[rule.severity.value] = severity_levels.get(rule.severity.value, 0) + 1
    
    for severity, count in severity_levels.items():
        print(f"  - {severity}: {count}")
    
    if args.detailed:
        print(f"\n📋 Detailed Rule Information:")
        for rule in engine.rules:
            print(f"\n🔍 {rule.name}")
            print(f"   Type: {rule.rule_type.value}")
            print(f"   Severity: {rule.severity.value}")
            print(f"   Enabled: {rule.enabled}")
            print(f"   Description: {rule.description}")
            print(f"   Conditions: {len(rule.conditions)}")
            for condition in rule.conditions:
                print(f"     - {condition.type.value}: {condition.description}")
            print(f"   Actions: {len(rule.actions)}")
            for action in rule.actions:
                print(f"     - {action.type.value}: {action.description}")

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
    <title>Policy Report - {report.report_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .violation {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ff4444; background-color: #fff5f5; }}
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
        <h1>🔍 Policy Report</h1>
        <p><strong>Report:</strong> {report.report_name}</p>
        <p><strong>Target:</strong> {report.target_api}</p>
        <p><strong>Generated:</strong> {report.generated_at}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Requests Evaluated:</strong> {report.total_requests_evaluated}</p>
        <p><strong>Requests with Violations:</strong> {report.requests_with_violations}</p>
        <p><strong>Total Violations:</strong> {report.total_violations}</p>
        
        <div class="risk-score risk-{report.overall_risk_level.value}">
            Risk Score: {report.overall_risk_score:.1f}/10 ({report.overall_risk_level.value})
        </div>
    </div>
    
    <div class="violations">
        <h2>🚨 Policy Violations</h2>
    """
    
    for evaluation in report.evaluations:
        if evaluation.violations:
            for violation in evaluation.violations:
                severity_class = violation.severity.value
                html += f"""
        <div class="violation {severity_class}">
            <h3>❌ {violation.rule_name}</h3>
            <p><strong>Endpoint:</strong> {violation.method} {violation.endpoint}</p>
            <p><strong>Severity:</strong> {violation.severity.value}</p>
            <p><strong>Description:</strong> {violation.description}</p>
            <p><strong>Actions:</strong> {', '.join(violation.actions_taken)}</p>
        </div>
                """
    
    html += """
    </div>
</body>
</html>
    """
    
    return html

def generate_markdown_report(report) -> str:
    """Generate Markdown report"""
    md = f"""# 🔍 Policy Report

**Report:** {report.report_name}  
**Target:** {report.target_api}  
**Generated:** {report.generated_at}

## 📊 Summary

- **Total Requests Evaluated:** {report.total_requests_evaluated}
- **Requests with Violations:** {report.requests_with_violations}
- **Total Violations:** {report.total_violations}
- **Risk Score:** {report.overall_risk_score:.1f}/10 ({report.overall_risk_level.value})

## 🚨 Policy Violations

"""
    
    for evaluation in report.evaluations:
        if evaluation.violations:
            for violation in evaluation.violations:
                md += f"""### ❌ {violation.rule_name}

- **Endpoint:** {violation.method} {violation.endpoint}
- **Severity:** {violation.severity.value}
- **Description:** {violation.description}
- **Actions:** {', '.join(violation.actions_taken)}

"""
    
    return md

def print_summary(report):
    """Print evaluation summary"""
    print(f"\n{'='*60}")
    print(f"📊 POLICY EVALUATION SUMMARY")
    print(f"{'='*60}")
    print(f"Total Requests Evaluated: {report.total_requests_evaluated}")
    print(f"Requests with Violations: {report.requests_with_violations}")
    print(f"Total Violations: {report.total_violations}")
    print(f"Risk Score: {report.overall_risk_score:.1f}/10 ({report.overall_risk_level.value})")
    
    if report.total_violations > 0:
        print(f"\n🚨 POLICY VIOLATIONS FOUND:")
        for evaluation in report.evaluations:
            for violation in evaluation.violations:
                print(f"  ❌ {violation.rule_name}")
                print(f"     Severity: {violation.severity.value}")
                print(f"     Endpoint: {violation.method} {violation.endpoint}")
                print(f"     Description: {violation.description}")
                print()
    else:
        print(f"\n✅ No policy violations found!")

if __name__ == "__main__":
    main() 