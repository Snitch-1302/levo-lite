#!/usr/bin/env python3
"""
Test script for LevoLite API Discovery
This script demonstrates the API discovery functionality by:
1. Starting the sample FastAPI server
2. Making various API requests
3. Showing the discovery results
"""

import requests
import time
import subprocess
import sys
import os
from discovery.cli import DiscoveryCLI

def start_api_server():
    """Start the sample FastAPI server"""
    print("🚀 Starting sample API server...")
    
    # Change to app directory
    os.chdir('app')
    
    # Start server in background
    process = subprocess.Popen([
        sys.executable, '-m', 'uvicorn', 'main:app', 
        '--host', '0.0.0.0', '--port', '8000', '--reload'
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for server to start
    time.sleep(3)
    
    # Change back to root directory
    os.chdir('..')
    
    return process

def make_test_requests():
    """Make various test requests to the API"""
    print("📡 Making test API requests...")
    
    base_url = "http://localhost:8000"
    
    # Test requests that demonstrate different security scenarios
    test_requests = [
        # Health check (safe)
        ("GET", "/health", None, "Health check"),
        
        # Login (authentication)
        ("POST", "/login", {"username": "admin", "password": "admin123"}, "Login as admin"),
        
        # User endpoints (potential IDOR)
        ("GET", "/users/1", None, "Get user 1"),
        ("GET", "/users/2", None, "Get user 2"),
        ("GET", "/users", None, "Get all users"),
        
        # Profile endpoints (sensitive data)
        ("GET", "/profiles/1", None, "Get profile 1"),
        ("GET", "/profiles/2", None, "Get profile 2"),
        
        # Admin endpoints (should require auth)
        ("GET", "/admin/users", None, "Admin users (should fail)"),
        
        # Search endpoint
        ("GET", "/search?q=admin", None, "Search users"),
        
        # Internal endpoint (security issue)
        ("GET", "/internal/users", None, "Internal users (security issue)"),
        
        # Debug endpoint (security issue)
        ("GET", "/debug/users", None, "Debug users (security issue)"),
        
        # API info
        ("GET", "/api/info", None, "API info"),
    ]
    
    results = []
    
    for method, endpoint, data, description in test_requests:
        try:
            print(f"  {method} {endpoint} - {description}")
            
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}")
            elif method == "POST":
                response = requests.post(f"{base_url}{endpoint}", json=data)
            
            print(f"    Status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    if isinstance(json_data, list):
                        print(f"    Response: {len(json_data)} items")
                    else:
                        print(f"    Response: {type(json_data).__name__}")
                except:
                    print(f"    Response: {len(response.text)} chars")
            else:
                print(f"    Error: {response.text[:100]}...")
            
            results.append({
                'method': method,
                'endpoint': endpoint,
                'status': response.status_code,
                'description': description
            })
            
        except Exception as e:
            print(f"    Error: {e}")
            results.append({
                'method': method,
                'endpoint': endpoint,
                'status': 'ERROR',
                'description': description
            })
        
        time.sleep(0.5)  # Small delay between requests
    
    return results

def show_discovery_results():
    """Show the discovery results using the CLI"""
    print("\n📊 API Discovery Results")
    print("=" * 50)
    
    cli = DiscoveryCLI()
    
    # Show summary
    cli.print_summary()
    
    print("\n🔍 Discovered Endpoints:")
    print("-" * 50)
    
    # List all endpoints
    endpoints = cli.list_endpoints()
    cli.print_endpoints_table(endpoints)
    
    print("\n🚨 Security Issues Found:")
    print("-" * 50)
    
    # Show vulnerable endpoints
    vulnerable = cli.list_endpoints({'vulnerable': True})
    if vulnerable:
        cli.print_endpoints_table(vulnerable, show_details=True)
    else:
        print("No security issues detected!")
    
    print("\n🔴 Sensitive Data Endpoints:")
    print("-" * 50)
    
    # Show sensitive endpoints
    sensitive = cli.list_endpoints({'sensitive_data': True})
    if sensitive:
        cli.print_endpoints_table(sensitive)
    else:
        print("No sensitive data endpoints detected!")

def main():
    """Main test function"""
    print("🧪 LevoLite API Discovery Test")
    print("=" * 50)
    
    # Check if discovery database exists
    if not os.path.exists("discovery.db"):
        print("❌ No discovery database found!")
        print("Please run the discovery interceptor first:")
        print("  python discovery/interceptor.py")
        return
    
    # Make test requests
    results = make_test_requests()
    
    print(f"\n✅ Made {len(results)} test requests")
    
    # Wait a bit for discovery to process
    print("⏳ Waiting for discovery processing...")
    time.sleep(2)
    
    # Show results
    show_discovery_results()
    
    print("\n💡 To run the discovery interceptor:")
    print("  1. Set proxy environment variables:")
    print("     export HTTP_PROXY=http://localhost:8080")
    print("     export HTTPS_PROXY=http://localhost:8080")
    print("  2. Run the interceptor:")
    print("     python discovery/interceptor.py")
    print("  3. Make requests to the API")
    print("  4. View results with:")
    print("     python discovery/cli.py list")
    print("     python discovery/cli.py summary")

if __name__ == "__main__":
    main() 