import json
import re
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, parse_qs
from datetime import datetime

from models import APIEndpoint, HTTPMethod, AuthType, SecurityLevel

class APIParser:
    """Parser for extracting API endpoint information from captured traffic"""
    
    def __init__(self):
        # Patterns for sensitive data detection
        self.sensitive_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'password': r'"password"\s*:\s*"[^"]*"',
            'token': r'"token"\s*:\s*"[^"]*"',
            'api_key': r'"api_key"\s*:\s*"[^"]*"',
            'authorization': r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
        }
        
        # Patterns for IDOR detection
        self.idor_patterns = [
            r'/users/\d+',
            r'/profiles/\d+',
            r'/accounts/\d+',
            r'/orders/\d+',
            r'/data/\d+',
            r'/api/\w+/\d+',
        ]
        
        # Sensitive endpoint patterns
        self.sensitive_endpoints = [
            '/admin',
            '/internal',
            '/debug',
            '/config',
            '/settings',
            '/users',
            '/profiles',
            '/accounts',
            '/payment',
            '/billing',
        ]
        
        # Authentication header patterns
        self.auth_patterns = {
            'bearer': r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
            'api_key': r'[Xx]-[Aa][Pp][Ii]-[Kk][Ee][Yy]\s*:\s*[^\s]+',
            'basic': r'Basic\s+[A-Za-z0-9+/]+=*',
            'cookie': r'Cookie\s*:\s*[^;]+',
        }
    
    def parse_request(self, flow_data: Dict[str, Any]) -> APIEndpoint:
        """Parse a captured request/response flow into an APIEndpoint"""
        
        # Extract basic request information
        request = flow_data.get('request', {})
        response = flow_data.get('response', {})
        
        # Parse URL
        url = request.get('url', '')
        parsed_url = urlparse(url)
        
        # Extract path and query parameters
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query) if parsed_url.query else {}
        
        # Convert query params from list to single values
        query_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
        
        # Extract method
        method = HTTPMethod(request.get('method', 'GET').upper())
        
        # Extract headers
        headers = request.get('headers', {})
        
        # Parse request body
        body = None
        if request.get('body'):
            try:
                body = json.loads(request.get('body'))
            except (json.JSONDecodeError, TypeError):
                body = request.get('body')
        
        # Parse response
        status_code = response.get('status_code')
        response_headers = response.get('headers', {})
        response_body = None
        if response.get('body'):
            try:
                response_body = json.loads(response.get('body'))
            except (json.JSONDecodeError, TypeError):
                response_body = response.get('body')
        
        # Analyze authentication
        auth_type, has_auth = self._analyze_authentication(headers)
        
        # Analyze security level
        security_level = self._analyze_security_level(path, headers, body, response_body)
        
        # Check for sensitive data
        contains_sensitive_data = self._detect_sensitive_data(body, response_body, headers)
        
        # Check for potential IDOR
        potential_idor = self._detect_idor_vulnerability(path, method)
        
        # Check for missing authentication on sensitive endpoints
        missing_auth = self._detect_missing_auth(path, has_auth, security_level)
        
        return APIEndpoint(
            path=path,
            method=method,
            host=parsed_url.hostname or 'localhost',
            port=parsed_url.port or 80,
            scheme=parsed_url.scheme or 'http',
            query_params=query_params,
            headers=headers,
            body=body,
            status_code=status_code,
            response_headers=response_headers,
            response_body=response_body,
            auth_type=auth_type,
            has_auth=has_auth,
            security_level=security_level,
            contains_sensitive_data=contains_sensitive_data,
            potential_idor=potential_idor,
            missing_auth=missing_auth,
            discovered_at=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
    
    def _analyze_authentication(self, headers: Dict[str, str]) -> tuple[AuthType, bool]:
        """Analyze headers to detect authentication type"""
        headers_str = json.dumps(headers).lower()
        
        if re.search(self.auth_patterns['bearer'], headers_str, re.IGNORECASE):
            return AuthType.BEARER, True
        elif re.search(self.auth_patterns['api_key'], headers_str, re.IGNORECASE):
            return AuthType.API_KEY, True
        elif re.search(self.auth_patterns['basic'], headers_str, re.IGNORECASE):
            return AuthType.BASIC, True
        elif re.search(self.auth_patterns['cookie'], headers_str, re.IGNORECASE):
            return AuthType.COOKIE, True
        else:
            return AuthType.NONE, False
    
    def _analyze_security_level(self, path: str, headers: Dict[str, str], 
                               body: Any, response_body: Any) -> SecurityLevel:
        """Analyze the security level of an endpoint"""
        
        # Check for sensitive endpoints
        path_lower = path.lower()
        if any(sensitive in path_lower for sensitive in self.sensitive_endpoints):
            return SecurityLevel.HIGH
        
        # Check for admin endpoints
        if '/admin' in path_lower:
            return SecurityLevel.CRITICAL
        
        # Check for debug endpoints
        if '/debug' in path_lower or '/internal' in path_lower:
            return SecurityLevel.CRITICAL
        
        # Check for user data endpoints
        if '/users' in path_lower or '/profiles' in path_lower:
            return SecurityLevel.MEDIUM
        
        # Check for authentication
        if self._analyze_authentication(headers)[1]:
            return SecurityLevel.MEDIUM
        
        # Check for sensitive data in request/response
        if self._detect_sensitive_data(body, response_body, headers):
            return SecurityLevel.HIGH
        
        return SecurityLevel.LOW
    
    def _detect_sensitive_data(self, body: Any, response_body: Any, 
                              headers: Dict[str, str]) -> bool:
        """Detect sensitive data in request/response"""
        
        # Convert to string for pattern matching
        data_str = ""
        if body:
            data_str += json.dumps(body) if isinstance(body, (dict, list)) else str(body)
        if response_body:
            data_str += json.dumps(response_body) if isinstance(response_body, (dict, list)) else str(response_body)
        if headers:
            data_str += json.dumps(headers)
        
        # Check for sensitive patterns
        for pattern_name, pattern in self.sensitive_patterns.items():
            if re.search(pattern, data_str, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_idor_vulnerability(self, path: str, method: HTTPMethod) -> bool:
        """Detect potential IDOR vulnerabilities"""
        
        # Check for IDOR patterns in path
        for pattern in self.idor_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        # Check for numeric IDs in path
        if re.search(r'/\d+', path):
            # If it's a GET request to a resource with ID, potential IDOR
            if method == HTTPMethod.GET:
                return True
        
        return False
    
    def _detect_missing_auth(self, path: str, has_auth: bool, 
                            security_level: SecurityLevel) -> bool:
        """Detect missing authentication on sensitive endpoints"""
        
        if not has_auth and security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            return True
        
        # Check specific sensitive endpoints
        path_lower = path.lower()
        sensitive_endpoints = ['/admin', '/internal', '/debug', '/users', '/profiles']
        
        if any(endpoint in path_lower for endpoint in sensitive_endpoints) and not has_auth:
            return True
        
        return False
    
    def analyze_endpoint_security(self, endpoint: APIEndpoint) -> Dict[str, Any]:
        """Perform comprehensive security analysis of an endpoint"""
        
        findings = []
        
        # Check for missing authentication
        if endpoint.missing_auth:
            findings.append({
                'type': 'missing_auth',
                'severity': 'high',
                'description': f'Endpoint {endpoint.path} lacks authentication but handles sensitive data'
            })
        
        # Check for potential IDOR
        if endpoint.potential_idor:
            findings.append({
                'type': 'potential_idor',
                'severity': 'medium',
                'description': f'Endpoint {endpoint.path} may be vulnerable to IDOR attacks'
            })
        
        # Check for sensitive data exposure
        if endpoint.contains_sensitive_data:
            findings.append({
                'type': 'sensitive_data',
                'severity': 'high',
                'description': f'Endpoint {endpoint.path} contains sensitive data'
            })
        
        # Check for HTTP usage (if we have scheme info)
        if hasattr(endpoint, 'scheme') and endpoint.scheme == 'http':
            findings.append({
                'type': 'http_usage',
                'severity': 'medium',
                'description': f'Endpoint {endpoint.path} uses HTTP instead of HTTPS'
            })
        
        return {
            'endpoint': endpoint.path,
            'method': endpoint.method,
            'security_level': endpoint.security_level,
            'findings': findings,
            'total_findings': len(findings)
        } 