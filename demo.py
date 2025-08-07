#!/usr/bin/env python3
"""
Demo script for LevoLite API Discovery
This script demonstrates the complete workflow of API discovery
"""

import os
import sys
import time
import subprocess
import requests
from discovery.cli import DiscoveryCLI

def print_step(step_num, title, description=""):
    """Print a formatted step"""
    print(f"\n{'='*60}")
    print(f"STEP {step_num}: {title}")
    print(f"{'='*60}")
    if description:
        print(description)
    print()

def check_server_running():
    """Check if the API server is running"""
    try:
        response = requests.get("http://localhost:8000/health", timeout=2)
        return response.status_code == 200
    except:
        return False

def start_api_server():
    """Start the API server"""
    print_step(1, "Starting Sample API Server", 
               "We'll start a FastAPI server with various endpoints that demonstrate different security scenarios.")
    
    if check_server_running():
        print("✅ API server is already running on http://localhost:8000")
        return None
    
    print("🚀 Starting API server...")
    print("This will start a FastAPI server with endpoints that demonstrate:")
    print("  - Authentication (login)")
    print("  - Potential IDOR vulnerabilities (/users/{id})")
    print("  - Sensitive data exposure (/profiles/{id})")
    print("  - Missing authentication (/internal/users)")
    print("  - Admin endpoints (/admin/users)")
    
    # Start server in background
    process = subprocess.Popen([
        sys.executable, '-m', 'uvicorn', 'main:app', 
        '--host', '0.0.0.0', '--port', '8000', '--reload'
    ], cwd='app', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for server to start
    for i in range(10):
        if check_server_running():
            print("✅ API server started successfully!")
            return process
        time.sleep(1)
        print(f"⏳ Waiting for server... ({i+1}/10)")
    
    print("❌ Failed to start API server")
    return None

def start_discovery_interceptor():
    """Start the discovery interceptor"""
    print_step(2, "Starting API Discovery Interceptor",
               "We'll start a proxy that captures and analyzes API traffic.")
    
    print("🔍 Starting discovery interceptor...")
    print("This proxy will:")
    print("  - Capture all HTTP/HTTPS traffic")
    print("  - Extract API endpoint information")
    print("  - Analyze security patterns")
    print("  - Store results in SQLite database")
    
    # Check if interceptor is already running
    try:
        response = requests.get("http://localhost:8080", timeout=1)
        print("✅ Discovery interceptor is already running on port 8080")
        return None
    except:
        pass
    
    # Start interceptor in background
    process = subprocess.Popen([
        sys.executable, 'discovery/interceptor.py',
        '--host', 'localhost',
        '--port', '8000',
        '--proxy-port', '8080',
        '--session', 'demo'
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for interceptor to start
    time.sleep(3)
    print("✅ Discovery interceptor started on port 8080")
    return process

def make_demo_requests():
    """Make demo requests to the API"""
    print_step(3, "Making API Requests",
               "We'll make various API requests that will be captured and analyzed by the discovery tool.")
    
    base_url = "http://localhost:8000"
    
    demo_requests = [
        ("GET", "/health", None, "Health check - safe endpoint"),
        ("POST", "/login", {"username": "admin", "password": "admin123"}, "Login - authentication endpoint"),
        ("GET", "/users/1", None, "Get user 1 - potential IDOR vulnerability"),
        ("GET", "/users/2", None, "Get user 2 - potential IDOR vulnerability"),
        ("GET", "/profiles/1", None, "Get profile 1 - sensitive data exposure"),
        ("GET", "/profiles/2", None, "Get profile 2 - sensitive data exposure"),
        ("GET", "/admin/users", None, "Admin endpoint - should require auth"),
        ("GET", "/internal/users", None, "Internal endpoint - security issue"),
        ("GET", "/debug/users", None, "Debug endpoint - security issue"),
        ("GET", "/search?q=admin", None, "Search endpoint - with query parameters"),
    ]
    
    print("📡 Making demo API requests...")
    print("These requests demonstrate different security scenarios:")
    print()
    
    for i, (method, endpoint, data, description) in enumerate(demo_requests, 1):
        print(f"{i:2d}. {method} {endpoint}")
        print(f"    {description}")
        
        try:
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}")
            elif method == "POST":
                response = requests.post(f"{base_url}{endpoint}", json=data)
            
            status_emoji = "✅" if response.status_code == 200 else "❌"
            print(f"    {status_emoji} Status: {response.status_code}")
            
        except Exception as e:
            print(f"    ❌ Error: {e}")
        
        time.sleep(0.5)  # Small delay between requests
    
    print(f"\n✅ Made {len(demo_requests)} demo requests")

def show_discovery_results():
    """Show the discovery results"""
    print_step(4, "Analyzing Discovery Results",
               "We'll analyze the captured API traffic and show security findings.")
    
    cli = DiscoveryCLI()
    
    print("📊 Discovery Summary:")
    print("-" * 40)
    cli.print_summary()
    
    print("\n🔍 Discovered Endpoints:")
    print("-" * 40)
    endpoints = cli.list_endpoints()
    cli.print_endpoints_table(endpoints)
    
    print("\n🚨 Security Issues Detected:")
    print("-" * 40)
    vulnerable = cli.list_endpoints({'vulnerable': True})
    if vulnerable:
        cli.print_endpoints_table(vulnerable, show_details=True)
    else:
        print("No security issues detected!")
    
    print("\n🔴 Sensitive Data Endpoints:")
    print("-" * 40)
    sensitive = cli.list_endpoints({'sensitive_data': True})
    if sensitive:
        cli.print_endpoints_table(sensitive)
    else:
        print("No sensitive data endpoints detected!")

def show_cli_usage():
    """Show CLI usage examples"""
    print_step(5, "CLI Usage Examples",
               "Here are some useful commands for exploring the discovery results:")
    
    print("📋 Available CLI Commands:")
    print()
    print("List all endpoints:")
    print("  python discovery/cli.py list")
    print()
    print("Show summary statistics:")
    print("  python discovery/cli.py summary")
    print()
    print("Show only vulnerable endpoints:")
    print("  python discovery/cli.py list --vulnerable")
    print()
    print("Show only endpoints with sensitive data:")
    print("  python discovery/cli.py list --sensitive")
    print()
    print("Show only GET endpoints:")
    print("  python discovery/cli.py list --method GET")
    print()
    print("Show detailed information:")
    print("  python discovery/cli.py list --details")
    print()
    print("Export results to JSON:")
    print("  python discovery/cli.py export --output results.json")

def main():
    """Main demo function"""
    print("🎯 LevoLite API Discovery Demo")
    print("=" * 60)
    print("This demo will show you how to:")
    print("1. Start a sample API server")
    print("2. Capture API traffic with a proxy")
    print("3. Analyze security patterns")
    print("4. View discovery results")
    print("5. Use the CLI for exploration")
    print()
    
    # Check if we're in the right directory
    if not os.path.exists("app/main.py"):
        print("❌ Please run this script from the project root directory")
        sys.exit(1)
    
    # Step 1: Start API server
    api_process = start_api_server()
    
    # Step 2: Start discovery interceptor
    interceptor_process = start_discovery_interceptor()
    
    # Step 3: Make demo requests
    make_demo_requests()
    
    # Wait a bit for processing
    print("\n⏳ Processing captured traffic...")
    time.sleep(3)
    
    # Step 4: Show results
    show_discovery_results()
    
    # Step 5: Show CLI usage
    show_cli_usage()
    
    print("\n🎉 Demo completed!")
    print("\n💡 To continue exploring:")
    print("  - Use the CLI commands shown above")
    print("  - Make more requests to the API")
    print("  - Check the discovery.db file for raw data")
    print("\n🛑 To stop the demo:")
    print("  - Press Ctrl+C in the terminal running the API server")
    print("  - Press Ctrl+C in the terminal running the interceptor")
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Demo stopped by user")
        if api_process:
            api_process.terminate()
        if interceptor_process:
            interceptor_process.terminate()

if __name__ == "__main__":
    main() 