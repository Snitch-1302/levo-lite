#!/usr/bin/env python3
"""
Setup script for LevoLite API Security Analyzer
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def main():
    """Main setup function"""
    print("🚀 LevoLite API Security Analyzer Setup")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Install dependencies
    print("\n📦 Installing dependencies...")
    if not run_command("pip install -r requirements.txt", "Installing Python dependencies"):
        print("❌ Failed to install dependencies")
        sys.exit(1)
    
    # Initialize the sample app database
    print("\n🗄️ Initializing sample app database...")
    os.chdir('app')
    if not run_command(f"{sys.executable} -c \"from database import init_db; init_db(); print('Database initialized')\"", "Initializing database"):
        print("❌ Failed to initialize database")
        sys.exit(1)
    os.chdir('..')
    
    print("\n✅ Setup completed successfully!")
    print("\n🎯 Next steps:")
    print("1. Start the sample API server:")
    print("   cd app && uvicorn main:app --reload --port 8000")
    print("\n2. In another terminal, start the API discovery interceptor:")
    print("   python discovery/interceptor.py")
    print("\n3. Set proxy environment variables:")
    print("   export HTTP_PROXY=http://localhost:8080")
    print("   export HTTPS_PROXY=http://localhost:8080")
    print("\n4. Make requests to the API (they will be captured)")
    print("\n5. View discovery results:")
    print("   python discovery/cli.py list")
    print("   python discovery/cli.py summary")
    print("\n📚 For more information, see README.md")

if __name__ == "__main__":
    main() 