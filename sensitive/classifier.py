import re
import json
import sqlite3
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import hashlib
from urllib.parse import urlparse, parse_qs

from models import (
    SensitiveDataType, DataLocation, SeverityLevel, SensitiveDataMatch,
    SensitiveDataAnalysis, SensitiveDataReport, DetectionPattern,
    ClassifierConfig, DataFlowAnalysis
)

class SensitiveDataClassifier:
    """Classifier for detecting sensitive data in API payloads"""
    
    def __init__(self, config: ClassifierConfig):
        self.config = config
        self.patterns = self._initialize_patterns()
        self.analyses: List[SensitiveDataAnalysis] = []
        
    def _initialize_patterns(self) -> List[DetectionPattern]:
        """Initialize detection patterns for sensitive data"""
        patterns = []
        
        # Email patterns
        patterns.append(DetectionPattern(
            name="Email Address",
            data_type=SensitiveDataType.EMAIL,
            regex_pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            confidence=0.9,
            risk_level=SeverityLevel.MEDIUM,
            description="Email address detection"
        ))
        
        # Phone number patterns
        patterns.append(DetectionPattern(
            name="Phone Number",
            data_type=SensitiveDataType.PHONE,
            regex_pattern=r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            confidence=0.8,
            risk_level=SeverityLevel.MEDIUM,
            description="US phone number detection"
        ))
        
        # SSN patterns
        patterns.append(DetectionPattern(
            name="Social Security Number",
            data_type=SensitiveDataType.SSN,
            regex_pattern=r'\b\d{3}-\d{2}-\d{4}\b',
            confidence=0.95,
            risk_level=SeverityLevel.CRITICAL,
            description="US Social Security Number"
        ))
        
        # Credit card patterns
        patterns.append(DetectionPattern(
            name="Credit Card Number",
            data_type=SensitiveDataType.CREDIT_CARD,
            regex_pattern=r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            confidence=0.85,
            risk_level=SeverityLevel.CRITICAL,
            description="Credit card number detection"
        ))
        
        # Password patterns
        patterns.append(DetectionPattern(
            name="Password Field",
            data_type=SensitiveDataType.PASSWORD,
            regex_pattern=r'"password"\s*:\s*"[^"]*"',
            confidence=0.9,
            risk_level=SeverityLevel.HIGH,
            description="Password field in JSON"
        ))
        
        # Token patterns
        patterns.append(DetectionPattern(
            name="Bearer Token",
            data_type=SensitiveDataType.TOKEN,
            regex_pattern=r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
            confidence=0.8,
            risk_level=SeverityLevel.HIGH,
            description="Bearer token in headers"
        ))
        
        patterns.append(DetectionPattern(
            name="JWT Token",
            data_type=SensitiveDataType.TOKEN,
            regex_pattern=r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            confidence=0.9,
            risk_level=SeverityLevel.HIGH,
            description="JWT token detection"
        ))
        
        # API Key patterns
        patterns.append(DetectionPattern(
            name="API Key",
            data_type=SensitiveDataType.API_KEY,
            regex_pattern=r'[Xx]-[Aa][Pp][Ii]-[Kk][Ee][Yy]\s*:\s*[^\s]+',
            confidence=0.8,
            risk_level=SeverityLevel.HIGH,
            description="API key in headers"
        ))
        
        # Name patterns
        patterns.append(DetectionPattern(
            name="Full Name",
            data_type=SensitiveDataType.NAME,
            regex_pattern=r'"name"\s*:\s*"[^"]*"|"full_name"\s*:\s*"[^"]*"',
            confidence=0.7,
            risk_level=SeverityLevel.MEDIUM,
            description="Name field in JSON"
        ))
        
        # Address patterns
        patterns.append(DetectionPattern(
            name="Address",
            data_type=SensitiveDataType.ADDRESS,
            regex_pattern=r'"address"\s*:\s*"[^"]*"',
            confidence=0.6,
            risk_level=SeverityLevel.MEDIUM,
            description="Address field in JSON"
        ))
        
        # Date of birth patterns
        patterns.append(DetectionPattern(
            name="Date of Birth",
            data_type=SensitiveDataType.DATE_OF_BIRTH,
            regex_pattern=r'"dob"\s*:\s*"[^"]*"|"date_of_birth"\s*:\s*"[^"]*"',
            confidence=0.8,
            risk_level=SeverityLevel.HIGH,
            description="Date of birth field"
        ))
        
        # IP Address patterns
        patterns.append(DetectionPattern(
            name="IP Address",
            data_type=SensitiveDataType.IP_ADDRESS,
            regex_pattern=r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            confidence=0.7,
            risk_level=SeverityLevel.LOW,
            description="IP address detection"
        ))
        
        # UUID patterns
        patterns.append(DetectionPattern(
            name="UUID",
            data_type=SensitiveDataType.UUID,
            regex_pattern=r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
            confidence=0.9,
            risk_level=SeverityLevel.LOW,
            description="UUID detection"
        ))
        
        # Session ID patterns
        patterns.append(DetectionPattern(
            name="Session ID",
            data_type=SensitiveDataType.SESSION_ID,
            regex_pattern=r'"session_id"\s*:\s*"[^"]*"|"sessionId"\s*:\s*"[^"]*"',
            confidence=0.8,
            risk_level=SeverityLevel.MEDIUM,
            description="Session ID field"
        ))
        
        # Add custom patterns
        if self.config.enable_custom_patterns:
            patterns.extend(self.config.custom_patterns)
        
        return patterns
    
    def analyze_request_response(self, endpoint: str, method: str, 
                               request_headers: Dict[str, str], 
                               request_body: Optional[Dict[str, Any]],
                               request_params: Dict[str, Any],
                               response_headers: Dict[str, str],
                               response_body: Optional[Dict[str, Any]],
                               response_status: int) -> SensitiveDataAnalysis:
        """Analyze a single request/response for sensitive data"""
        
        analysis = SensitiveDataAnalysis(
            endpoint=endpoint,
            method=method,
            request_headers=request_headers,
            request_body=request_body,
            request_params=request_params,
            response_headers=response_headers,
            response_body=response_body,
            response_status=response_status
        )
        
        # Analyze request headers
        if self.config.analyze_headers:
            header_matches = self._analyze_headers(request_headers, DataLocation.REQUEST_HEADER)
            analysis.sensitive_data_found.extend(header_matches)
        
        # Analyze request body
        if self.config.analyze_body and request_body:
            body_matches = self._analyze_json_data(request_body, DataLocation.REQUEST_BODY)
            analysis.sensitive_data_found.extend(body_matches)
        
        # Analyze request parameters
        if self.config.analyze_params and request_params:
            param_matches = self._analyze_params(request_params, DataLocation.REQUEST_PARAMS)
            analysis.sensitive_data_found.extend(param_matches)
        
        # Analyze response headers
        if self.config.analyze_headers:
            response_header_matches = self._analyze_headers(response_headers, DataLocation.RESPONSE_HEADER)
            analysis.sensitive_data_found.extend(response_header_matches)
        
        # Analyze response body
        if self.config.analyze_body and response_body:
            response_body_matches = self._analyze_json_data(response_body, DataLocation.RESPONSE_BODY)
            analysis.sensitive_data_found.extend(response_body_matches)
        
        # Update analysis statistics
        analysis.total_matches = len(analysis.sensitive_data_found)
        analysis.has_critical_data = any(match.exposure_risk == SeverityLevel.CRITICAL for match in analysis.sensitive_data_found)
        analysis.has_high_risk_data = any(match.exposure_risk in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] for match in analysis.sensitive_data_found)
        
        # Determine overall risk level
        analysis.overall_risk = self._determine_overall_risk(analysis.sensitive_data_found)
        
        # Generate recommendations
        analysis.recommendations = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_headers(self, headers: Dict[str, str], location: DataLocation) -> List[SensitiveDataMatch]:
        """Analyze headers for sensitive data"""
        matches = []
        headers_str = json.dumps(headers)
        
        for pattern in self.patterns:
            if pattern.data_type in [SensitiveDataType.TOKEN, SensitiveDataType.API_KEY]:
                # Special handling for auth headers
                for header_name, header_value in headers.items():
                    if self._matches_pattern(header_value, pattern):
                        matches.append(self._create_match(
                            pattern, header_value, location, header_name, header_value
                        ))
            else:
                # General header analysis
                if self._matches_pattern(headers_str, pattern):
                    # Find the specific header that matched
                    for header_name, header_value in headers.items():
                        if self._matches_pattern(header_value, pattern):
                            matches.append(self._create_match(
                                pattern, header_value, location, header_name, header_value
                            ))
        
        return matches
    
    def _analyze_json_data(self, data: Dict[str, Any], location: DataLocation) -> List[SensitiveDataMatch]:
        """Analyze JSON data for sensitive data"""
        matches = []
        data_str = json.dumps(data)
        
        for pattern in self.patterns:
            if self._matches_pattern(data_str, pattern):
                # Find specific fields that matched
                matches.extend(self._find_matching_fields(data, pattern, location))
        
        return matches
    
    def _analyze_params(self, params: Dict[str, Any], location: DataLocation) -> List[SensitiveDataMatch]:
        """Analyze URL parameters for sensitive data"""
        matches = []
        params_str = json.dumps(params)
        
        for pattern in self.patterns:
            if self._matches_pattern(params_str, pattern):
                for param_name, param_value in params.items():
                    if self._matches_pattern(str(param_value), pattern):
                        matches.append(self._create_match(
                            pattern, str(param_value), location, param_name, str(param_value)
                        ))
        
        return matches
    
    def _find_matching_fields(self, data: Dict[str, Any], pattern: DetectionPattern, location: DataLocation) -> List[SensitiveDataMatch]:
        """Find specific fields in JSON data that match a pattern"""
        matches = []
        
        def search_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, str):
                        if self._matches_pattern(value, pattern):
                            matches.append(self._create_match(
                                pattern, value, location, current_path, value
                            ))
                    elif isinstance(value, (dict, list)):
                        search_recursive(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    search_recursive(item, current_path)
        
        search_recursive(data)
        return matches
    
    def _matches_pattern(self, text: str, pattern: DetectionPattern) -> bool:
        """Check if text matches a pattern"""
        try:
            return bool(re.search(pattern.regex_pattern, text, re.IGNORECASE))
        except re.error:
            return False
    
    def _create_match(self, pattern: DetectionPattern, value: str, location: DataLocation, 
                     field_name: str, original_value: str) -> SensitiveDataMatch:
        """Create a sensitive data match"""
        
        # Mask the value if configured
        if self.config.mask_detected_data:
            masked_value = self._mask_sensitive_data(value, pattern.data_type)
        else:
            masked_value = value
        
        # Determine if data is encrypted or masked
        is_encrypted = self._is_encrypted(value)
        is_masked = self._is_masked(value)
        
        # Determine exposure risk
        exposure_risk = self._determine_exposure_risk(pattern, location, is_encrypted, is_masked)
        
        return SensitiveDataMatch(
            data_type=pattern.data_type,
            location=location,
            field_name=field_name,
            value=masked_value,
            confidence=pattern.confidence,
            pattern_matched=pattern.name,
            is_encrypted=is_encrypted,
            is_masked=is_masked,
            exposure_risk=exposure_risk
        )
    
    def _mask_sensitive_data(self, value: str, data_type: SensitiveDataType) -> str:
        """Mask sensitive data for logging"""
        if len(value) <= 4:
            return "*" * len(value)
        
        if data_type == SensitiveDataType.EMAIL:
            # Mask email: user@domain.com -> u***@d***.com
            parts = value.split('@')
            if len(parts) == 2:
                username = parts[0]
                domain = parts[1]
                masked_username = username[0] + "*" * (len(username) - 1)
                domain_parts = domain.split('.')
                if len(domain_parts) >= 2:
                    masked_domain = domain_parts[0][0] + "*" * (len(domain_parts[0]) - 1) + "." + domain_parts[-1]
                    return f"{masked_username}@{masked_domain}"
        
        elif data_type == SensitiveDataType.PHONE:
            # Mask phone: 123-456-7890 -> 123-***-7890
            if len(value) >= 10:
                return value[:3] + "-***-" + value[-4:]
        
        elif data_type == SensitiveDataType.SSN:
            # Mask SSN: 123-45-6789 -> ***-**-6789
            if len(value) >= 9:
                return "***-**-" + value[-4:]
        
        elif data_type == SensitiveDataType.CREDIT_CARD:
            # Mask credit card: 1234-5678-9012-3456 -> ****-****-****-3456
            if len(value) >= 16:
                return "****-****-****-" + value[-4:]
        
        # Default masking
        return value[:2] + "*" * (len(value) - 4) + value[-2:] if len(value) > 4 else "*" * len(value)
    
    def _is_encrypted(self, value: str) -> bool:
        """Check if value appears to be encrypted"""
        # Simple heuristics for encrypted data
        encrypted_indicators = [
            len(value) > 32,  # Long strings
            re.match(r'^[A-Za-z0-9+/=]+$', value),  # Base64-like
            re.match(r'^[A-Fa-f0-9]+$', value),  # Hex-like
        ]
        return any(encrypted_indicators)
    
    def _is_masked(self, value: str) -> bool:
        """Check if value appears to be masked"""
        # Check for common masking patterns
        masked_indicators = [
            '*' in value,
            '#' in value,
            'X' in value and len(set(value)) <= 2,
        ]
        return any(masked_indicators)
    
    def _determine_exposure_risk(self, pattern: DetectionPattern, location: DataLocation, 
                                is_encrypted: bool, is_masked: bool) -> SeverityLevel:
        """Determine the exposure risk level"""
        
        # Base risk from pattern
        base_risk = pattern.risk_level
        
        # Adjust based on location
        if location in [DataLocation.RESPONSE_BODY, DataLocation.RESPONSE_HEADER]:
            # Data in response is more risky
            if base_risk == SeverityLevel.LOW:
                base_risk = SeverityLevel.MEDIUM
            elif base_risk == SeverityLevel.MEDIUM:
                base_risk = SeverityLevel.HIGH
        
        # Adjust based on encryption/masking
        if is_encrypted:
            # Reduce risk if encrypted
            if base_risk == SeverityLevel.CRITICAL:
                base_risk = SeverityLevel.HIGH
            elif base_risk == SeverityLevel.HIGH:
                base_risk = SeverityLevel.MEDIUM
        
        if is_masked:
            # Reduce risk if masked
            if base_risk == SeverityLevel.CRITICAL:
                base_risk = SeverityLevel.HIGH
            elif base_risk == SeverityLevel.HIGH:
                base_risk = SeverityLevel.MEDIUM
        
        return base_risk
    
    def _determine_overall_risk(self, matches: List[SensitiveDataMatch]) -> SeverityLevel:
        """Determine overall risk level for an analysis"""
        if not matches:
            return SeverityLevel.LOW
        
        # Count by severity
        severity_counts = {}
        for match in matches:
            severity_counts[match.exposure_risk] = severity_counts.get(match.exposure_risk, 0) + 1
        
        # Determine overall risk
        if SeverityLevel.CRITICAL in severity_counts:
            return SeverityLevel.CRITICAL
        elif SeverityLevel.HIGH in severity_counts:
            return SeverityLevel.HIGH
        elif SeverityLevel.MEDIUM in severity_counts:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _generate_recommendations(self, analysis: SensitiveDataAnalysis) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if analysis.has_critical_data:
            recommendations.append("Critical sensitive data detected - implement encryption and access controls")
        
        if analysis.has_high_risk_data:
            recommendations.append("High-risk sensitive data found - review data handling practices")
        
        # Check for specific data types
        data_types_found = set(match.data_type for match in analysis.sensitive_data_found)
        
        if SensitiveDataType.PASSWORD in data_types_found:
            recommendations.append("Passwords detected - ensure secure transmission and storage")
        
        if SensitiveDataType.CREDIT_CARD in data_types_found:
            recommendations.append("Credit card data found - ensure PCI DSS compliance")
        
        if SensitiveDataType.SSN in data_types_found:
            recommendations.append("SSN detected - ensure proper data protection measures")
        
        if SensitiveDataType.TOKEN in data_types_found:
            recommendations.append("Authentication tokens found - ensure secure token handling")
        
        # Check response exposure
        response_matches = [m for m in analysis.sensitive_data_found if m.location in [DataLocation.RESPONSE_BODY, DataLocation.RESPONSE_HEADER]]
        if response_matches:
            recommendations.append("Sensitive data in responses - implement proper authorization checks")
        
        return recommendations
    
    def generate_report(self, analyses: List[SensitiveDataAnalysis], target_api: str) -> SensitiveDataReport:
        """Generate comprehensive sensitive data report"""
        
        # Calculate statistics
        total_requests = len(analyses)
        requests_with_sensitive_data = len([a for a in analyses if a.total_matches > 0])
        total_matches = sum(a.total_matches for a in analyses)
        
        # Breakdown by data type
        data_type_breakdown = {}
        location_breakdown = {}
        risk_breakdown = {}
        
        for analysis in analyses:
            for match in analysis.sensitive_data_found:
                # Data type breakdown
                data_type_breakdown[match.data_type] = data_type_breakdown.get(match.data_type, 0) + 1
                
                # Location breakdown
                location_breakdown[match.location] = location_breakdown.get(match.location, 0) + 1
                
                # Risk breakdown
                risk_breakdown[match.exposure_risk] = risk_breakdown.get(match.exposure_risk, 0) + 1
        
        # Calculate overall risk score
        if total_matches > 0:
            critical_count = risk_breakdown.get(SeverityLevel.CRITICAL, 0)
            high_count = risk_breakdown.get(SeverityLevel.HIGH, 0)
            medium_count = risk_breakdown.get(SeverityLevel.MEDIUM, 0)
            
            risk_score = min(10, (critical_count * 3 + high_count * 2 + medium_count) / total_matches * 10)
        else:
            risk_score = 0
        
        # Determine overall risk level
        if risk_score >= 8:
            overall_risk_level = SeverityLevel.CRITICAL
        elif risk_score >= 6:
            overall_risk_level = SeverityLevel.HIGH
        elif risk_score >= 4:
            overall_risk_level = SeverityLevel.MEDIUM
        else:
            overall_risk_level = SeverityLevel.LOW
        
        # Generate compliance issues
        compliance_issues = []
        if SensitiveDataType.CREDIT_CARD in data_type_breakdown:
            compliance_issues.append("PCI DSS compliance required for credit card data")
        if SensitiveDataType.SSN in data_type_breakdown:
            compliance_issues.append("GDPR/CCPA compliance required for SSN data")
        if SensitiveDataType.EMAIL in data_type_breakdown:
            compliance_issues.append("Email data handling requires privacy compliance")
        
        return SensitiveDataReport(
            report_name=f"Sensitive Data Analysis - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
            target_api=target_api,
            generated_at=datetime.utcnow(),
            total_requests_analyzed=total_requests,
            requests_with_sensitive_data=requests_with_sensitive_data,
            total_sensitive_matches=total_matches,
            data_type_breakdown=data_type_breakdown,
            location_breakdown=location_breakdown,
            risk_breakdown=risk_breakdown,
            analyses=analyses,
            overall_risk_score=risk_score,
            overall_risk_level=overall_risk_level,
            compliance_issues=compliance_issues
        ) 