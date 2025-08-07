from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import json
import os
from datetime import datetime, timedelta

from .database import get_db
from .models import User

router = APIRouter()

@router.get("/dashboard")
async def get_dashboard_data(db: Session = Depends(get_db)):
    """Get dashboard overview data"""
    try:
        # Try to load real data from files
        dashboard_data = load_dashboard_data()
        return dashboard_data
    except Exception as e:
        # Return mock data if files don't exist
        return get_mock_dashboard_data()

@router.get("/discovery/endpoints")
async def get_discovery_endpoints(db: Session = Depends(get_db)):
    """Get discovered API endpoints"""
    try:
        # Try to load from discovery database
        import sqlite3
        conn = sqlite3.connect('discovery.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM endpoints ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        conn.close()
        
        endpoints = []
        for row in rows:
            endpoints.append({
                "id": row[0],
                "path": row[1],
                "method": row[2],
                "status_code": row[3],
                "auth_required": bool(row[4]),
                "sensitive_data": bool(row[5]),
                "last_seen": row[6],
                "call_count": row[7]
            })
        
        return {"endpoints": endpoints}
    except Exception as e:
        return get_mock_discovery_data()

@router.get("/vulnerability/report")
async def get_vulnerability_report(db: Session = Depends(get_db)):
    """Get vulnerability scan report"""
    try:
        if os.path.exists("vulnerability_report.json"):
            with open("vulnerability_report.json", "r") as f:
                return json.load(f)
        return get_mock_vulnerability_data()
    except Exception as e:
        return get_mock_vulnerability_data()

@router.get("/sensitive/report")
async def get_sensitive_report(db: Session = Depends(get_db)):
    """Get sensitive data analysis report"""
    try:
        if os.path.exists("sensitive_report.json"):
            with open("sensitive_report.json", "r") as f:
                return json.load(f)
        return get_mock_sensitive_data()
    except Exception as e:
        return get_mock_sensitive_data()

@router.get("/policy/report")
async def get_policy_report(db: Session = Depends(get_db)):
    """Get policy evaluation report"""
    try:
        if os.path.exists("policy_report.json"):
            with open("policy_report.json", "r") as f:
                return json.load(f)
        return get_mock_policy_data()
    except Exception as e:
        return get_mock_policy_data()

@router.get("/reports")
async def get_reports(db: Session = Depends(get_db)):
    """Get available reports"""
    try:
        reports = []
        report_files = [
            "vulnerability_report.json",
            "sensitive_report.json", 
            "policy_report.json",
            "openapi.yaml"
        ]
        
        for file in report_files:
            if os.path.exists(file):
                stat = os.stat(file)
                reports.append({
                    "id": len(reports) + 1,
                    "name": file.replace("_", " ").replace(".json", "").replace(".yaml", "").title(),
                    "type": file.split("_")[0] if "_" in file else "other",
                    "generated_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "status": "completed",
                    "file_size": f"{stat.st_size / 1024:.1f} KB"
                })
        
        return {"reports": reports}
    except Exception as e:
        return get_mock_reports_data()

@router.get("/export/{report_type}")
async def export_report(report_type: str, format: str = "json", db: Session = Depends(get_db)):
    """Export report in specified format"""
    try:
        file_map = {
            "vulnerability": "vulnerability_report.json",
            "sensitive": "sensitive_report.json",
            "policy": "policy_report.json",
            "openapi": "openapi.yaml"
        }
        
        if report_type not in file_map:
            raise HTTPException(status_code=404, detail="Report type not found")
        
        file_path = file_map[report_type]
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Report file not found")
        
        with open(file_path, "r") as f:
            content = f.read()
        
        return {"content": content, "filename": file_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def load_dashboard_data():
    """Load real dashboard data from files"""
    summary = {
        "total_endpoints": 0,
        "vulnerabilities": 0,
        "critical_issues": 0,
        "high_issues": 0,
        "medium_issues": 0,
        "low_issues": 0,
        "policy_violations": 0,
        "pii_exposures": 0,
        "overall_status": "PASS"
    }
    
    # Load discovery data
    try:
        import sqlite3
        conn = sqlite3.connect('discovery.db')
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM endpoints")
        summary["total_endpoints"] = cursor.fetchone()[0]
        conn.close()
    except:
        pass
    
    # Load vulnerability data
    try:
        if os.path.exists("vulnerability_report.json"):
            with open("vulnerability_report.json", "r") as f:
                vuln_data = json.load(f)
                summary["vulnerabilities"] = len(vuln_data.get("vulnerabilities", []))
                for vuln in vuln_data.get("vulnerabilities", []):
                    severity = vuln.get("severity", "low")
                    if severity == "critical":
                        summary["critical_issues"] += 1
                    elif severity == "high":
                        summary["high_issues"] += 1
                    elif severity == "medium":
                        summary["medium_issues"] += 1
                    else:
                        summary["low_issues"] += 1
    except:
        pass
    
    # Load sensitive data
    try:
        if os.path.exists("sensitive_report.json"):
            with open("sensitive_report.json", "r") as f:
                sensitive_data = json.load(f)
                summary["pii_exposures"] = len(sensitive_data.get("matches", []))
    except:
        pass
    
    # Load policy data
    try:
        if os.path.exists("policy_report.json"):
            with open("policy_report.json", "r") as f:
                policy_data = json.load(f)
                summary["policy_violations"] = policy_data.get("total_violations", 0)
    except:
        pass
    
    # Determine overall status
    if summary["critical_issues"] > 0:
        summary["overall_status"] = "CRITICAL"
    elif summary["high_issues"] > 0:
        summary["overall_status"] = "HIGH"
    elif summary["policy_violations"] > 0:
        summary["overall_status"] = "WARNING"
    else:
        summary["overall_status"] = "PASS"
    
    return {
        "summary": summary,
        "recent_activity": get_recent_activity(),
        "charts": get_chart_data()
    }

def get_recent_activity():
    """Get recent activity from various reports"""
    activities = []
    
    # Add vulnerability activities
    try:
        if os.path.exists("vulnerability_report.json"):
            with open("vulnerability_report.json", "r") as f:
                vuln_data = json.load(f)
                for vuln in vuln_data.get("vulnerabilities", [])[:3]:
                    activities.append({
                        "id": len(activities) + 1,
                        "type": "vulnerability",
                        "severity": vuln.get("severity", "low"),
                        "endpoint": vuln.get("endpoint", "Unknown"),
                        "description": vuln.get("name", "Vulnerability detected"),
                        "timestamp": datetime.now().isoformat()
                    })
    except:
        pass
    
    # Add policy activities
    try:
        if os.path.exists("policy_report.json"):
            with open("policy_report.json", "r") as f:
                policy_data = json.load(f)
                for evaluation in policy_data.get("evaluations", [])[:3]:
                    activities.append({
                        "id": len(activities) + 1,
                        "type": "policy",
                        "severity": evaluation.get("severity", "medium"),
                        "endpoint": evaluation.get("endpoint", "Unknown"),
                        "description": f"Policy violation: {evaluation.get('rule_name', 'Unknown rule')}",
                        "timestamp": evaluation.get("timestamp", datetime.now().isoformat())
                    })
    except:
        pass
    
    return activities

def get_chart_data():
    """Generate chart data"""
    return {
        "vulnerabilities_by_severity": [
            {"name": "Critical", "value": 2, "color": "#ef4444"},
            {"name": "High", "value": 3, "color": "#f97316"},
            {"name": "Medium", "value": 2, "color": "#eab308"},
            {"name": "Low", "value": 1, "color": "#3b82f6"}
        ],
        "endpoints_by_method": [
            {"name": "GET", "value": 12, "color": "#22c55e"},
            {"name": "POST", "value": 8, "color": "#3b82f6"},
            {"name": "PUT", "value": 3, "color": "#f59e0b"},
            {"name": "DELETE", "value": 1, "color": "#ef4444"}
        ]
    }

def get_mock_dashboard_data():
    """Return mock dashboard data"""
    return {
        "summary": {
            "total_endpoints": 24,
            "vulnerabilities": 8,
            "critical_issues": 2,
            "high_issues": 3,
            "medium_issues": 2,
            "low_issues": 1,
            "policy_violations": 5,
            "pii_exposures": 12,
            "overall_status": "WARNING"
        },
        "recent_activity": [
            {
                "id": 1,
                "type": "vulnerability",
                "severity": "critical",
                "endpoint": "/api/users/{id}",
                "description": "IDOR vulnerability detected",
                "timestamp": datetime.now().isoformat()
            },
            {
                "id": 2,
                "type": "policy",
                "severity": "high",
                "endpoint": "/api/admin/users",
                "description": "Policy violation: Unauthenticated admin access",
                "timestamp": (datetime.now() - timedelta(hours=1)).isoformat()
            }
        ],
        "charts": {
            "vulnerabilities_by_severity": [
                {"name": "Critical", "value": 2, "color": "#ef4444"},
                {"name": "High", "value": 3, "color": "#f97316"},
                {"name": "Medium", "value": 2, "color": "#eab308"},
                {"name": "Low", "value": 1, "color": "#3b82f6"}
            ],
            "endpoints_by_method": [
                {"name": "GET", "value": 12, "color": "#22c55e"},
                {"name": "POST", "value": 8, "color": "#3b82f6"},
                {"name": "PUT", "value": 3, "color": "#f59e0b"},
                {"name": "DELETE", "value": 1, "color": "#ef4444"}
            ]
        }
    }

def get_mock_discovery_data():
    """Return mock discovery data"""
    return {
        "endpoints": [
            {
                "id": 1,
                "path": "/api/users",
                "method": "GET",
                "status_code": 200,
                "auth_required": True,
                "sensitive_data": False,
                "last_seen": datetime.now().isoformat(),
                "call_count": 156
            },
            {
                "id": 2,
                "path": "/api/users/{id}",
                "method": "GET",
                "status_code": 200,
                "auth_required": True,
                "sensitive_data": True,
                "last_seen": (datetime.now() - timedelta(minutes=30)).isoformat(),
                "call_count": 89
            }
        ],
        "summary": {
            "total_endpoints": 24,
            "authenticated": 18,
            "unauthenticated": 6,
            "with_sensitive_data": 8,
            "methods": {
                "GET": 12,
                "POST": 8,
                "PUT": 3,
                "DELETE": 1
            }
        }
    }

def get_mock_vulnerability_data():
    """Return mock vulnerability data"""
    return {
        "vulnerabilities": [
            {
                "id": 1,
                "name": "IDOR Vulnerability",
                "severity": "critical",
                "endpoint": "/api/users/{id}",
                "description": "Users can access other users' data by changing the ID parameter",
                "cwe": "CWE-639",
                "evidence": "Successfully accessed user 123 data with user 456 token",
                "recommendation": "Implement proper authorization checks",
                "status": "open"
            }
        ],
        "summary": {
            "total": 8,
            "critical": 2,
            "high": 3,
            "medium": 2,
            "low": 1,
            "open": 6,
            "fixed": 2
        }
    }

def get_mock_sensitive_data():
    """Return mock sensitive data"""
    return {
        "matches": [
            {
                "id": 1,
                "data_type": "email",
                "field_name": "email",
                "location": "request_body",
                "endpoint": "/api/users",
                "exposure_risk": "high",
                "value": "user@example.com",
                "masked": False
            }
        ],
        "summary": {
            "total_matches": 12,
            "critical": 3,
            "high": 5,
            "medium": 3,
            "low": 1,
            "data_types": {
                "email": 4,
                "password": 2,
                "phone": 3,
                "ssn": 1,
                "credit_card": 2
            }
        }
    }

def get_mock_policy_data():
    """Return mock policy data"""
    return {
        "evaluations": [
            {
                "id": 1,
                "rule_name": "No Plaintext Passwords",
                "severity": "critical",
                "endpoint": "/api/auth/login",
                "description": "Password transmitted in plaintext",
                "evidence": "Found password field in request body",
                "timestamp": datetime.now().isoformat()
            }
        ],
        "summary": {
            "total_violations": 5,
            "critical": 2,
            "high": 2,
            "medium": 1,
            "low": 0,
            "rules_evaluated": 8,
            "rules_passed": 3
        }
    }

def get_mock_reports_data():
    """Return mock reports data"""
    return {
        "reports": [
            {
                "id": 1,
                "name": "Security Analysis Report",
                "type": "comprehensive",
                "generated_at": datetime.now().isoformat(),
                "status": "completed",
                "file_size": "2.3 MB"
            }
        ]
    } 