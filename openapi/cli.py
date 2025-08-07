#!/usr/bin/env python3
"""
CLI interface for LevoLite OpenAPI Generator
"""

import argparse
import os
import sys
from pathlib import Path

from generator import OpenAPIGenerator

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description="LevoLite OpenAPI Generator")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate OpenAPI specification')
    generate_parser.add_argument('--format', choices=['yaml', 'json', 'both'], default='yaml',
                               help='Output format (default: yaml)')
    generate_parser.add_argument('--title', default='Discovered API',
                               help='API title (default: Discovered API)')
    generate_parser.add_argument('--version', default='1.0.0',
                               help='API version (default: 1.0.0)')
    generate_parser.add_argument('--output-dir', default='.',
                               help='Output directory (default: current directory)')
    generate_parser.add_argument('--db-path', default='discovery.db',
                               help='Path to discovery database (default: discovery.db)')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate OpenAPI specification')
    validate_parser.add_argument('--file', required=True,
                               help='OpenAPI specification file to validate')
    
    # Convert command
    convert_parser = subparsers.add_parser('convert', help='Convert between formats')
    convert_parser.add_argument('--input', required=True,
                              help='Input OpenAPI specification file')
    convert_parser.add_argument('--output', required=True,
                              help='Output file path')
    convert_parser.add_argument('--format', choices=['yaml', 'json'],
                              help='Output format (auto-detected from output file extension)')
    
    # Postman command
    postman_parser = subparsers.add_parser('postman', help='Export to Postman collection')
    postman_parser.add_argument('--output', default='postman_collection.json',
                               help='Output file path (default: postman_collection.json)')
    postman_parser.add_argument('--db-path', default='discovery.db',
                               help='Path to discovery database (default: discovery.db)')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show generator information')
    info_parser.add_argument('--db-path', default='discovery.db',
                           help='Path to discovery database (default: discovery.db)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'generate':
        generate_openapi(args)
    elif args.command == 'validate':
        validate_openapi(args)
    elif args.command == 'convert':
        convert_openapi(args)
    elif args.command == 'postman':
        export_postman(args)
    elif args.command == 'info':
        show_info(args)

def generate_openapi(args):
    """Generate OpenAPI specification"""
    print("🔧 Generating OpenAPI specification...")
    
    # Check if database exists
    if not os.path.exists(args.db_path):
        print(f"❌ Discovery database not found: {args.db_path}")
        print("Please run the API discovery tool first:")
        print("  python discovery/interceptor.py")
        return
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize generator
    generator = OpenAPIGenerator(args.db_path)
    
    try:
        # Generate spec
        spec = generator.generate_openapi_spec(args.title, args.version)
        
        # Export based on format
        if args.format in ['yaml', 'both']:
            yaml_path = os.path.join(args.output_dir, 'openapi.yaml')
            result = generator.export_yaml(yaml_path)
            print(f"✅ {result}")
        
        if args.format in ['json', 'both']:
            json_path = os.path.join(args.output_dir, 'openapi.json')
            result = generator.export_json(json_path)
            print(f"✅ {result}")
        
        # Show summary
        endpoints = generator.load_discovered_endpoints()
        print(f"\n📊 Generated OpenAPI spec with {len(endpoints)} endpoints")
        print(f"📁 Output directory: {os.path.abspath(args.output_dir)}")
        
        # Show validation info
        print("\n💡 To validate the generated spec:")
        print("  - Upload to https://editor.swagger.io/")
        print("  - Use the validate command: python openapi/cli.py validate --file openapi.yaml")
        
    except Exception as e:
        print(f"❌ Error generating OpenAPI spec: {e}")
        sys.exit(1)

def validate_openapi(args):
    """Validate OpenAPI specification"""
    print(f"🔍 Validating OpenAPI specification: {args.file}")
    
    if not os.path.exists(args.file):
        print(f"❌ File not found: {args.file}")
        sys.exit(1)
    
    try:
        # Try to parse the file
        with open(args.file, 'r') as f:
            content = f.read()
        
        # Basic validation
        if args.file.endswith('.yaml') or args.file.endswith('.yml'):
            import yaml
            try:
                yaml.safe_load(content)
                print("✅ YAML syntax is valid")
            except yaml.YAMLError as e:
                print(f"❌ YAML syntax error: {e}")
                sys.exit(1)
        elif args.file.endswith('.json'):
            import json
            try:
                json.loads(content)
                print("✅ JSON syntax is valid")
            except json.JSONDecodeError as e:
                print(f"❌ JSON syntax error: {e}")
                sys.exit(1)
        
        # Check for required OpenAPI fields
        if 'openapi' in content and 'paths' in content:
            print("✅ Contains required OpenAPI fields")
        else:
            print("⚠️  Missing required OpenAPI fields (openapi, paths)")
        
        print("✅ Basic validation passed")
        print("\n💡 For full validation, upload to https://editor.swagger.io/")
        
    except Exception as e:
        print(f"❌ Validation error: {e}")
        sys.exit(1)

def convert_openapi(args):
    """Convert between OpenAPI formats"""
    print(f"🔄 Converting {args.input} to {args.output}")
    
    if not os.path.exists(args.input):
        print(f"❌ Input file not found: {args.input}")
        sys.exit(1)
    
    try:
        # Read input file
        with open(args.input, 'r') as f:
            content = f.read()
        
        # Parse based on input format
        if args.input.endswith('.yaml') or args.input.endswith('.yml'):
            import yaml
            data = yaml.safe_load(content)
        elif args.input.endswith('.json'):
            import json
            data = json.loads(content)
        else:
            print("❌ Unsupported input format")
            sys.exit(1)
        
        # Determine output format
        output_format = args.format
        if not output_format:
            if args.output.endswith('.yaml') or args.output.endswith('.yml'):
                output_format = 'yaml'
            elif args.output.endswith('.json'):
                output_format = 'json'
            else:
                output_format = 'yaml'  # default
        
        # Write output
        with open(args.output, 'w') as f:
            if output_format == 'yaml':
                import yaml
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            else:
                import json
                json.dump(data, f, indent=2)
        
        print(f"✅ Converted to {args.output}")
        
    except Exception as e:
        print(f"❌ Conversion error: {e}")
        sys.exit(1)

def export_postman(args):
    """Export to Postman collection"""
    print("📦 Exporting to Postman collection...")
    
    # Check if database exists
    if not os.path.exists(args.db_path):
        print(f"❌ Discovery database not found: {args.db_path}")
        print("Please run the API discovery tool first:")
        print("  python discovery/interceptor.py")
        return
    
    try:
        # Initialize generator
        generator = OpenAPIGenerator(args.db_path)
        
        # Export Postman collection
        result = generator.export_postman(args.output)
        print(f"✅ {result}")
        
        # Show summary
        endpoints = generator.load_discovered_endpoints()
        print(f"\n📊 Exported {len(endpoints)} endpoints to Postman collection")
        print(f"📁 Output file: {os.path.abspath(args.output)}")
        
        print("\n💡 To import into Postman:")
        print("  1. Open Postman")
        print("  2. Click 'Import'")
        print("  3. Select the generated JSON file")
        
    except Exception as e:
        print(f"❌ Error exporting to Postman: {e}")
        sys.exit(1)

def show_info(args):
    """Show generator information"""
    print("📋 OpenAPI Generator Information")
    print("=" * 40)
    
    # Check if database exists
    if not os.path.exists(args.db_path):
        print(f"❌ Discovery database not found: {args.db_path}")
        print("Please run the API discovery tool first:")
        print("  python discovery/interceptor.py")
        return
    
    try:
        # Initialize generator
        generator = OpenAPIGenerator(args.db_path)
        
        # Load endpoints
        endpoints = generator.load_discovered_endpoints()
        
        print(f"📊 Total endpoints discovered: {len(endpoints)}")
        
        # Count by method
        methods = {}
        for endpoint in endpoints:
            method = endpoint.method.value
            methods[method] = methods.get(method, 0) + 1
        
        print("\n📈 Endpoints by method:")
        for method, count in sorted(methods.items()):
            print(f"  {method}: {count}")
        
        # Count by security level
        security_levels = {}
        for endpoint in endpoints:
            level = endpoint.security_level.value
            security_levels[level] = security_levels.get(level, 0) + 1
        
        print("\n🔒 Endpoints by security level:")
        for level, count in sorted(security_levels.items()):
            print(f"  {level}: {count}")
        
        # Show unique paths
        unique_paths = set(endpoint.path for endpoint in endpoints)
        print(f"\n🛣️  Unique paths: {len(unique_paths)}")
        
        # Show auth endpoints
        auth_endpoints = [e for e in endpoints if e.has_auth]
        print(f"🔐 Authenticated endpoints: {len(auth_endpoints)}")
        
        # Show sensitive endpoints
        sensitive_endpoints = [e for e in endpoints if e.contains_sensitive_data]
        print(f"🔴 Sensitive data endpoints: {len(sensitive_endpoints)}")
        
        print(f"\n💾 Database: {os.path.abspath(args.db_path)}")
        
    except Exception as e:
        print(f"❌ Error loading information: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 