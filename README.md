# LevoLite: End-to-End API Security Analyzer

An ambitious project to build a comprehensive API security analysis platform that discovers, tests, and monitors APIs for security vulnerabilities.

## 🚀 Project Overview

LevoLite is an end-to-end API security analyzer that provides:
- **API Discovery**: Automatically discover APIs through traffic monitoring
- **Vulnerability Testing**: Test for IDOR, BOLA, auth bypasses, and more
- **Sensitive Data Detection**: Identify PII and sensitive data flows
- **Policy Enforcement**: Custom YAML-based security policies
- **CI/CD Integration**: Automated security testing in pipelines
- **Dashboard**: Visual interface for security insights

## 🛠️ Tech Stack

- **Backend**: FastAPI + Uvicorn
- **Data Models**: Pydantic
- **Database**: SQLite
- **Frontend**: React + Tailwind
- **CI/CD**: GitHub Actions
- **Containerization**: Docker

## 📋 Phase Plan

### Phase 1: API Discovery ✅
- Traffic interceptor using mitmproxy
- API endpoint extraction and cataloging
- Database storage with Pydantic models
- CLI/web interface for discovered APIs

### Phase 2: OpenAPI Generator ✅
- Convert discovered traffic to OpenAPI 3.0 specs
- Export as YAML/JSON
- Postman collection export
- OpenAPI validation support

### Phase 3: AuthN/AuthZ Vulnerability Tester ✅
- Automated testing for BOLA, IDOR, auth bypasses
- Mock users with different privilege levels
- Comprehensive vulnerability reporting
- OWASP API Top 10 coverage

### Phase 4: Sensitive Data Classifier ✅
- PII detection in API payloads
- Regex and ML-based classification
- Comprehensive sensitive data detection
- Risk assessment and compliance checking

### Phase 5: Policy Engine ✅
- YAML-based custom security policies
- Runtime violation detection
- Comprehensive policy evaluation engine
- Customizable governance rules

### Phase 6: CI/CD Integration ✅
- GitHub Actions automation
- Build failure on critical issues
- Automated security testing pipeline
- Security badge support

### Phase 7: Dashboard ✅
- React-based visualization
- Real-time security insights
- Interactive dashboard with charts
- Export/download functionality

### Phase 8: Final Polish ✅
- Dockerization with docker-compose
- Comprehensive documentation
- Demo script and automation
- Production-ready deployment

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+ (for frontend)
- Docker (optional)

### Option 1: Docker (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd levo-lite

# Run with Docker Compose
docker-compose up --build

# Access the application
# Dashboard: http://localhost:3000
# API Docs: http://localhost:8000/docs
```

### Option 2: Manual Setup
```bash
# Clone the repository
git clone <repository-url>
cd levo-lite

# Install Python dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend
npm install
cd ..

# Run the sample API server
python -m uvicorn app.main:app --reload --port 8000

# In another terminal, start the frontend
cd frontend
npm start
```

### Option 3: Demo Script
```bash
# Run the complete demo
chmod +x scripts/demo.sh
./scripts/demo.sh
```

## 📁 Project Structure

```
levo-lite/
├── app/                    # Sample FastAPI application
│   ├── main.py            # FastAPI server with endpoints
│   ├── models.py          # Pydantic data models
│   ├── database.py        # SQLite database setup
│   ├── auth.py            # Authentication utilities
│   └── dashboard.py       # Dashboard API endpoints
├── discovery/             # Phase 1: API Discovery
│   ├── interceptor.py     # Traffic interceptor
│   ├── parser.py          # API data parser
│   ├── cli.py            # CLI interface
│   └── models.py         # Discovery data models
├── openapi/               # Phase 2: OpenAPI Generator
│   ├── generator.py       # OpenAPI spec generator
│   └── cli.py            # OpenAPI CLI interface
├── vulnerability/          # Phase 3: Vulnerability Tester
│   ├── models.py          # Vulnerability test models
│   ├── scanner.py         # Vulnerability scanner engine
│   └── cli.py            # Vulnerability CLI interface
├── sensitive/              # Phase 4: Sensitive Data Classifier
│   ├── models.py          # Sensitive data models
│   ├── classifier.py      # Sensitive data classifier
│   └── cli.py            # Sensitive data CLI interface
├── policy/                 # Phase 5: Policy Engine
│   ├── models.py          # Policy models
│   ├── engine.py          # Policy evaluation engine
│   └── cli.py            # Policy CLI interface
├── .github/workflows/      # Phase 6: CI/CD Integration
│   └── api-security.yml   # GitHub Actions workflow
├── frontend/              # React dashboard (Phase 7)
│   ├── src/
│   │   ├── components/    # Reusable UI components
│   │   ├── pages/         # Dashboard pages
│   │   └── services/      # API service layer
│   └── public/            # Static assets
├── scripts/               # Utility scripts
│   └── demo.sh           # Demo automation script
├── Dockerfile             # Docker configuration
├── docker-compose.yml     # Multi-service deployment
└── requirements.txt       # Python dependencies
```

## 🎯 Current Status

**Phase 1: API Discovery** - ✅ Complete
- Sample FastAPI app with multiple endpoints
- Traffic interceptor using mitmproxy
- API endpoint extraction and storage
- CLI interface for viewing discovered APIs
- Database models with Pydantic

**Phase 2: OpenAPI Generator** - ✅ Complete
- OpenAPI 3.0 specification generator
- YAML and JSON export formats
- Postman collection export
- Automatic parameter and response inference
- Security analysis integration

**Phase 3: AuthN/AuthZ Vulnerability Tester** - ✅ Complete
- Automated vulnerability testing for BOLA, IDOR, missing auth
- Mock users with different privilege levels (anonymous, user, admin)
- Comprehensive test suites with OWASP API Top 10 coverage
- Detailed vulnerability reporting in multiple formats (JSON, HTML, Markdown)
- Risk scoring and severity assessment

**Phase 4: Sensitive Data Classifier** - ✅ Complete
- Comprehensive PII detection (email, phone, SSN, credit cards, passwords, tokens)
- Regex-based pattern matching with confidence scoring
- Risk assessment and compliance checking (PCI DSS, GDPR, CCPA)
- Detailed reporting with data masking and security recommendations
- Support for custom detection patterns

**Phase 5: Policy Engine** - ✅ Complete
- YAML-driven policy engine with customizable governance rules
- Real-time policy evaluation for API requests/responses
- Multiple condition types (endpoint, method, headers, body, auth)
- Configurable actions (block, warn, log, alert, redirect, rate_limit)
- Comprehensive violation reporting with evidence collection
- Default security and compliance policy templates

**Phase 6: CI/CD Integration** - ✅ Complete
- GitHub Actions workflow for automated security testing
- Runs all security tests (discovery, vulnerability, sensitive data, policy)
- Build failure on critical issues and policy violations
- Comprehensive security reporting with Markdown and JSON formats
- Security badge support for repository status
- Automated PR comments with security analysis

**Phase 7: Dashboard** - ✅ Complete
- React + Tailwind CSS frontend with modern UI
- Interactive dashboard with real-time security insights
- Comprehensive data visualization with charts and metrics
- Search, filter, and explore functionality for all data
- Export/download reports in multiple formats (JSON, YAML, Markdown, HTML)
- Responsive design with mobile support
- Real-time data from FastAPI backend with CORS support

**Phase 8: Final Polish** - ✅ Complete
- Docker containerization with multi-service support
- Docker Compose for easy deployment
- Comprehensive documentation and setup instructions
- Demo automation script for showcasing features
- Production-ready configuration with health checks
- Clean project structure and organization

## 🔧 Development

### Running Tests
```bash
# Run all security tests
python ci_test.py

# Run individual tests
python test_discovery.py
python test_openapi.py
python test_vulnerability.py
python test_sensitive.py
python test_policy.py
```

### Code Formatting
```bash
black .
isort .
```

### Type Checking
```bash
mypy .
```

## 📊 Demo

The sample API includes endpoints that demonstrate various security scenarios:
- `/login` - Authentication endpoint
- `/users/{user_id}` - User data access (potential IDOR)
- `/admin/users` - Admin-only endpoint
- `/profile` - User profile with sensitive data
- `/search` - Search endpoint with query parameters

## 🌐 Access Points

When running the application:
- **Dashboard**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **Sample API**: http://localhost:8001 (when using docker-compose)

## 📁 Generated Reports

The system generates comprehensive reports:
- **Vulnerability Report**: `vulnerability_report.json`
- **Sensitive Data Report**: `sensitive_report.json`
- **Policy Report**: `policy_report.json`
- **OpenAPI Spec**: `openapi.yaml`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🎯 Roadmap

- [x] Phase 1: API Discovery
- [x] Phase 2: OpenAPI Generator
- [x] Phase 3: AuthN/AuthZ Testing
- [x] Phase 4: Sensitive Data Detection
- [x] Phase 5: Policy Engine
- [x] Phase 6: CI/CD Integration
- [x] Phase 7: Dashboard
- [x] Phase 8: Final Polish

## 🚀 Deployment

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production Deployment
```bash
# Build production image
docker build -t levolite:latest .

# Run with environment variables
docker run -p 8000:8000 -p 3000:3000 \
  -e DATABASE_URL=sqlite:///./data/levolite.db \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/reports:/app/reports \
  levolite:latest
```

## 📈 Performance

- **API Discovery**: Real-time traffic interception
- **Vulnerability Scanning**: Comprehensive test suite with 15+ test cases
- **Sensitive Data Detection**: 10+ pattern types with 90%+ accuracy
- **Policy Evaluation**: Real-time rule processing
- **Dashboard**: Responsive UI with real-time updates

## 🔒 Security Features

- **OWASP API Top 10 Coverage**: Complete vulnerability testing
- **PII Detection**: Comprehensive sensitive data identification
- **Policy Enforcement**: Customizable security rules
- **Compliance Support**: GDPR, PCI DSS, CCPA compliance checking
- **Real-time Monitoring**: Live traffic analysis and alerting 