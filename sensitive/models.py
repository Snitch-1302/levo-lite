from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any, Union
from datetime import datetime
from enum import Enum

class SensitiveDataType(str, Enum):
    """Types of sensitive data"""
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    PASSWORD = "password"
    TOKEN = "token"
    API_KEY = "api_key"
    NAME = "name"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    IP_ADDRESS = "ip_address"
    UUID = "uuid"
    SESSION_ID = "session_id"
    CUSTOM = "custom"

class DataLocation(str, Enum):
    """Where sensitive data was found"""
    REQUEST_HEADER = "request_header"
    REQUEST_BODY = "request_body"
    REQUEST_PARAMS = "request_params"
    RESPONSE_HEADER = "response_header"
    RESPONSE_BODY = "response_body"
    URL = "url"

class SeverityLevel(str, Enum):
    """Severity of sensitive data exposure"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SensitiveDataMatch(BaseModel):
    """Represents a single sensitive data match"""
    id: Optional[int] = None
    data_type: SensitiveDataType = Field(..., description="Type of sensitive data")
    location: DataLocation = Field(..., description="Where the data was found")
    field_name: str = Field(..., description="Field name where data was found")
    value: str = Field(..., description="The sensitive data value")
    confidence: float = Field(..., description="Confidence score (0-1)")
    pattern_matched: str = Field(..., description="Pattern that matched")
    
    # Context
    context: Optional[str] = Field(default=None, description="Surrounding context")
    line_number: Optional[int] = Field(default=None, description="Line number in payload")
    
    # Security assessment
    is_encrypted: bool = Field(default=False, description="Whether the data is encrypted")
    is_masked: bool = Field(default=False, description="Whether the data is masked")
    exposure_risk: SeverityLevel = Field(..., description="Risk level of exposure")
    
    # Metadata
    detected_at: datetime = Field(default_factory=datetime.utcnow, description="When detected")
    
    class Config:
        from_attributes = True

class SensitiveDataAnalysis(BaseModel):
    """Analysis of sensitive data in a single request/response"""
    id: Optional[int] = None
    endpoint: str = Field(..., description="API endpoint")
    method: str = Field(..., description="HTTP method")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Analysis timestamp")
    
    # Request analysis
    request_headers: Dict[str, str] = Field(default_factory=dict, description="Request headers")
    request_body: Optional[Dict[str, Any]] = Field(default=None, description="Request body")
    request_params: Dict[str, Any] = Field(default_factory=dict, description="Request parameters")
    
    # Response analysis
    response_headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    response_body: Optional[Dict[str, Any]] = Field(default=None, description="Response body")
    response_status: int = Field(..., description="Response status code")
    
    # Sensitive data findings
    sensitive_data_found: List[SensitiveDataMatch] = Field(default_factory=list, description="Sensitive data matches")
    total_matches: int = Field(default=0, description="Total sensitive data matches")
    
    # Security assessment
    has_critical_data: bool = Field(default=False, description="Contains critical sensitive data")
    has_high_risk_data: bool = Field(default=False, description="Contains high-risk sensitive data")
    overall_risk: SeverityLevel = Field(default=SeverityLevel.LOW, description="Overall risk level")
    
    # Recommendations
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    
    class Config:
        from_attributes = True

class SensitiveDataReport(BaseModel):
    """Comprehensive report of sensitive data analysis"""
    id: Optional[int] = None
    report_name: str = Field(..., description="Report name")
    target_api: str = Field(..., description="Target API URL")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Report generation time")
    
    # Summary statistics
    total_requests_analyzed: int = Field(..., description="Total requests analyzed")
    requests_with_sensitive_data: int = Field(..., description="Requests containing sensitive data")
    total_sensitive_matches: int = Field(..., description="Total sensitive data matches")
    
    # Breakdown by data type
    data_type_breakdown: Dict[SensitiveDataType, int] = Field(default_factory=dict, description="Matches by data type")
    location_breakdown: Dict[DataLocation, int] = Field(default_factory=dict, description="Matches by location")
    risk_breakdown: Dict[SeverityLevel, int] = Field(default_factory=dict, description="Matches by risk level")
    
    # Detailed analysis
    analyses: List[SensitiveDataAnalysis] = Field(default_factory=list, description="Detailed analyses")
    
    # Risk assessment
    overall_risk_score: float = Field(..., description="Overall risk score (0-10)")
    overall_risk_level: SeverityLevel = Field(..., description="Overall risk level")
    
    # Compliance
    compliance_issues: List[str] = Field(default_factory=list, description="Compliance issues found")
    
    class Config:
        from_attributes = True

class DetectionPattern(BaseModel):
    """Pattern for detecting sensitive data"""
    name: str = Field(..., description="Pattern name")
    data_type: SensitiveDataType = Field(..., description="Data type this pattern detects")
    regex_pattern: str = Field(..., description="Regex pattern for detection")
    confidence: float = Field(default=0.8, description="Default confidence score")
    risk_level: SeverityLevel = Field(..., description="Default risk level")
    description: str = Field(..., description="Pattern description")
    
    class Config:
        from_attributes = True

class ClassifierConfig(BaseModel):
    """Configuration for sensitive data classifier"""
    # Detection settings
    enable_regex_detection: bool = Field(default=True, description="Enable regex-based detection")
    enable_ml_detection: bool = Field(default=False, description="Enable ML-based detection")
    enable_custom_patterns: bool = Field(default=True, description="Enable custom patterns")
    
    # Pattern settings
    min_confidence: float = Field(default=0.6, description="Minimum confidence for detection")
    max_value_length: int = Field(default=1000, description="Maximum value length to analyze")
    
    # Analysis settings
    analyze_headers: bool = Field(default=True, description="Analyze request/response headers")
    analyze_body: bool = Field(default=True, description="Analyze request/response body")
    analyze_params: bool = Field(default=True, description="Analyze URL parameters")
    
    # Security settings
    mask_detected_data: bool = Field(default=True, description="Mask detected data in logs")
    log_sensitive_data: bool = Field(default=False, description="Log sensitive data values")
    
    # Custom patterns
    custom_patterns: List[DetectionPattern] = Field(default_factory=list, description="Custom detection patterns")
    
    class Config:
        from_attributes = True

class DataFlowAnalysis(BaseModel):
    """Analysis of data flow through the API"""
    id: Optional[int] = None
    source_endpoint: str = Field(..., description="Source endpoint")
    destination_endpoint: str = Field(..., description="Destination endpoint")
    data_type: SensitiveDataType = Field(..., description="Type of data flowing")
    flow_direction: str = Field(..., description="Direction of data flow")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Flow timestamp")
    
    # Security assessment
    is_encrypted_in_transit: bool = Field(default=False, description="Data encrypted in transit")
    is_properly_authorized: bool = Field(default=False, description="Proper authorization in place")
    compliance_issues: List[str] = Field(default_factory=list, description="Compliance issues")
    
    class Config:
        from_attributes = True 