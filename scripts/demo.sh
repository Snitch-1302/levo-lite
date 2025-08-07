#!/bin/bash

# LevoLite Demo Script
# This script demonstrates all features of the API Security Analyzer

set -e

echo "🚀 LevoLite API Security Analyzer Demo"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

print_status "Starting LevoLite demo..."

# Create necessary directories
mkdir -p data reports logs

print_status "Building and starting LevoLite with Docker Compose..."

# Start the application
docker-compose up --build -d

print_status "Waiting for services to start..."
sleep 30

# Check if services are running
if curl -f http://localhost:8000/health &> /dev/null; then
    print_success "Backend API is running at http://localhost:8000"
else
    print_error "Backend API is not responding"
    exit 1
fi

print_status "Running security analysis..."

# Run API discovery
print_status "🔍 Running API Discovery..."
docker-compose exec levolite python discovery/cli.py list-endpoints

# Generate OpenAPI spec
print_status "📄 Generating OpenAPI Specification..."
docker-compose exec levolite python openapi/cli.py generate --output openapi.yaml

# Run vulnerability scan
print_status "🔐 Running Vulnerability Scanner..."
docker-compose exec levolite python vulnerability/cli.py scan --output vulnerability_report.json

# Run sensitive data analysis
print_status "🧬 Running Sensitive Data Analysis..."
docker-compose exec levolite python sensitive/cli.py test --output sensitive_report.json

# Run policy evaluation
print_status "📜 Running Policy Evaluation..."
docker-compose exec levolite python policy/cli.py test --output policy_report.json

print_success "Security analysis complete!"

# Display results
echo ""
echo "📊 Demo Results:"
echo "================"

# Show discovered endpoints
echo ""
print_status "Discovered API Endpoints:"
docker-compose exec levolite python discovery/cli.py list-endpoints --limit 5

# Show vulnerability summary
echo ""
print_status "Vulnerability Summary:"
if [ -f "vulnerability_report.json" ]; then
    echo "Found $(jq '.vulnerabilities | length' vulnerability_report.json) vulnerabilities"
    echo "Critical: $(jq '[.vulnerabilities[] | select(.severity == "critical")] | length' vulnerability_report.json)"
    echo "High: $(jq '[.vulnerabilities[] | select(.severity == "high")] | length' vulnerability_report.json)"
else
    echo "No vulnerability report found"
fi

# Show sensitive data summary
echo ""
print_status "Sensitive Data Summary:"
if [ -f "sensitive_report.json" ]; then
    echo "Found $(jq '.matches | length' sensitive_report.json) sensitive data matches"
    echo "Critical: $(jq '[.matches[] | select(.exposure_risk == "critical")] | length' sensitive_report.json)"
    echo "High: $(jq '[.matches[] | select(.exposure_risk == "high")] | length' sensitive_report.json)"
else
    echo "No sensitive data report found"
fi

# Show policy violations
echo ""
print_status "Policy Violations:"
if [ -f "policy_report.json" ]; then
    echo "Total violations: $(jq '.total_violations' policy_report.json)"
    echo "Critical: $(jq '.violations_by_severity.critical // 0' policy_report.json)"
    echo "High: $(jq '.violations_by_severity.high // 0' policy_report.json)"
else
    echo "No policy report found"
fi

echo ""
print_success "🎉 Demo completed successfully!"
echo ""
echo "🌐 Access Points:"
echo "  - Dashboard: http://localhost:3000"
echo "  - API Documentation: http://localhost:8000/docs"
echo "  - Health Check: http://localhost:8000/health"
echo ""
echo "📁 Generated Reports:"
echo "  - Vulnerability Report: vulnerability_report.json"
echo "  - Sensitive Data Report: sensitive_report.json"
echo "  - Policy Report: policy_report.json"
echo "  - OpenAPI Spec: openapi.yaml"
echo ""
echo "🔧 To stop the demo:"
echo "  docker-compose down"
echo ""
echo "📖 For more information, see README.md" 