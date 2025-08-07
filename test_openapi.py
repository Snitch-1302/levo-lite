#!/usr/bin/env python3
"""
Test script for LevoLite OpenAPI Generator
This script demonstrates the OpenAPI generation functionality
"""

import os
import sys
import requests
import time
from openapi.generator import OpenAPIGenerator

def check_discovery_data():
    """Check if we have discovery data to work with"""
    if not os.path.exists("discovery.db"):
        print("❌ No discovery database found!")
        print("Please run the API discovery tool first:")
        print("  python discovery/interceptor.py")
        return False
    
    # Check if we have endpoints
    generator = OpenAPIGenerator()
    endpoints = generator.load_discovered_endpoints()
    
    if not endpoints:
        print("❌ No endpoints found in discovery database!")
        print("Please make some API requests first:")
        print("  curl http://localhost:8000/health")
        print("  curl http://localhost:8000/users")
        return False
    
    print(f"✅ Found {len(endpoints)} endpoints in discovery database")
    return True

def make_sample_requests():
    """Make sample requests to generate discovery data"""
    print("📡 Making sample API requests...")
    
    base_url = "http://localhost:8000"
    
    sample_requests = [
        ("GET", "/health", None),
        ("POST", "/login", {"username": "admin", "password": "admin123"}),
        ("GET", "/users/1", None),
        ("GET", "/users/2", None),
        ("GET", "/profiles/1", None),
        ("GET", "/admin/users", None),
        ("GET", "/search?q=admin", None),
        ("GET", "/internal/users", None),
    ]
    
    for method, endpoint, data in sample_requests:
        try:
            print(f"  {method} {endpoint}")
            
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}")
            elif method == "POST":
                response = requests.post(f"{base_url}{endpoint}", json=data)
            
            print(f"    Status: {response.status_code}")
            
        except Exception as e:
            print(f"    Error: {e}")
        
        time.sleep(0.5)

def test_openapi_generation():
    """Test OpenAPI generation"""
    print("\n🔧 Testing OpenAPI generation...")
    
    generator = OpenAPIGenerator()
    
    # Generate spec
    spec = generator.generate_openapi_spec("LevoLite Sample API", "1.0.0")
    
    print("✅ OpenAPI specification generated successfully")
    print(f"📊 Spec contains {len(spec.paths)} paths")
    
    # Export to YAML
    yaml_result = generator.export_yaml("test_openapi.yaml")
    print(f"✅ {yaml_result}")
    
    # Export to JSON
    json_result = generator.export_json("test_openapi.json")
    print(f"✅ {json_result}")
    
    # Export to Postman
    postman_result = generator.export_postman("test_postman_collection.json")
    print(f"✅ {postman_result}")
    
    return True

def show_generated_spec():
    """Show information about the generated spec"""
    print("\n📋 Generated OpenAPI Specification Details")
    print("=" * 50)
    
    generator = OpenAPIGenerator()
    endpoints = generator.load_discovered_endpoints()
    
    print(f"Total endpoints: {len(endpoints)}")
    
    # Group by path
    paths = {}
    for endpoint in endpoints:
        if endpoint.path not in paths:
            paths[endpoint.path] = []
        paths[endpoint.path].append(endpoint)
    
    print(f"Unique paths: {len(paths)}")
    
    print("\n📄 Paths and methods:")
    for path, path_endpoints in sorted(paths.items()):
        methods = [e.method.value for e in path_endpoints]
        print(f"  {path}: {', '.join(methods)}")
    
    print("\n🔐 Authentication:")
    auth_endpoints = [e for e in endpoints if e.has_auth]
    print(f"  Authenticated endpoints: {len(auth_endpoints)}")
    for endpoint in auth_endpoints:
        print(f"    {endpoint.method.value} {endpoint.path} ({endpoint.auth_type.value})")
    
    print("\n🔴 Sensitive data:")
    sensitive_endpoints = [e for e in endpoints if e.contains_sensitive_data]
    print(f"  Sensitive endpoints: {len(sensitive_endpoints)}")
    for endpoint in sensitive_endpoints:
        print(f"    {endpoint.method.value} {endpoint.path}")
    
    print("\n🚨 Security issues:")
    vulnerable_endpoints = [e for e in endpoints if e.potential_idor or e.missing_auth]
    print(f"  Vulnerable endpoints: {len(vulnerable_endpoints)}")
    for endpoint in vulnerable_endpoints:
        issues = []
        if endpoint.potential_idor:
            issues.append("IDOR")
        if endpoint.missing_auth:
            issues.append("Missing Auth")
        print(f"    {endpoint.method.value} {endpoint.path} ({', '.join(issues)})")

def validate_generated_files():
    """Validate the generated files"""
    print("\n🔍 Validating generated files...")
    
    files_to_check = [
        "test_openapi.yaml",
        "test_openapi.json",
        "test_postman_collection.json"
    ]
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"✅ {file_path} ({size} bytes)")
        else:
            print(f"❌ {file_path} not found")

def main():
    """Main test function"""
    print("🧪 LevoLite OpenAPI Generator Test")
    print("=" * 50)
    
    # Check if we have discovery data
    if not check_discovery_data():
        print("\n💡 To generate discovery data:")
        print("1. Start the API server:")
        print("   cd app && uvicorn main:app --reload --port 8000")
        print("2. Start the discovery interceptor:")
        print("   python discovery/interceptor.py")
        print("3. Make some API requests")
        print("4. Run this test again")
        return
    
    # Test OpenAPI generation
    if test_openapi_generation():
        show_generated_spec()
        validate_generated_files()
        
        print("\n🎉 OpenAPI generation test completed!")
        print("\n💡 Generated files:")
        print("  - test_openapi.yaml (OpenAPI spec in YAML)")
        print("  - test_openapi.json (OpenAPI spec in JSON)")
        print("  - test_postman_collection.json (Postman collection)")
        
        print("\n🔍 To validate the generated spec:")
        print("  - Upload test_openapi.yaml to https://editor.swagger.io/")
        print("  - Use the CLI: python openapi/cli.py validate --file test_openapi.yaml")
        
        print("\n📦 To import into Postman:")
        print("  - Open Postman")
        print("  - Click 'Import'")
        print("  - Select test_postman_collection.json")
    else:
        print("❌ OpenAPI generation test failed")

if __name__ == "__main__":
    main() 