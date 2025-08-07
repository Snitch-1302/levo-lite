from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any
from datetime import datetime
from enum import Enum

class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

class AuthType(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    COOKIE = "cookie"

class SecurityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class APIEndpoint(BaseModel):
    """Represents a discovered API endpoint"""
    id: Optional[int] = None
    path: str = Field(..., description="API endpoint path")
    method: HTTPMethod = Field(..., description="HTTP method")
    host: str = Field(..., description="Host address")
    port: int = Field(..., description="Port number")
    scheme: str = Field(..., description="HTTP scheme (http/https)")
    
    # Request details
    query_params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Query parameters")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="Request headers")
    body: Optional[Dict[str, Any]] = Field(default=None, description="Request body")
    
    # Response details
    status_code: Optional[int] = Field(default=None, description="Response status code")
    response_headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="Response headers")
    response_body: Optional[Dict[str, Any]] = Field(default=None, description="Response body")
    
    # Security analysis
    auth_type: AuthType = Field(default=AuthType.NONE, description="Authentication type detected")
    has_auth: bool = Field(default=False, description="Whether endpoint requires authentication")
    security_level: SecurityLevel = Field(default=SecurityLevel.LOW, description="Security level assessment")
    
    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.utcnow, description="When endpoint was discovered")
    last_seen: datetime = Field(default_factory=datetime.utcnow, description="Last time endpoint was accessed")
    request_count: int = Field(default=1, description="Number of times this endpoint was accessed")
    
    # Analysis flags
    contains_sensitive_data: bool = Field(default=False, description="Whether endpoint contains sensitive data")
    potential_idor: bool = Field(default=False, description="Potential IDOR vulnerability")
    missing_auth: bool = Field(default=False, description="Missing authentication on sensitive endpoint")
    
    class Config:
        from_attributes = True

class APIDiscoverySession(BaseModel):
    """Represents a discovery session"""
    id: Optional[int] = None
    session_name: str = Field(..., description="Name of the discovery session")
    target_host: str = Field(..., description="Target host being monitored")
    target_port: int = Field(..., description="Target port being monitored")
    start_time: datetime = Field(default_factory=datetime.utcnow, description="Session start time")
    end_time: Optional[datetime] = Field(default=None, description="Session end time")
    total_requests: int = Field(default=0, description="Total requests captured")
    unique_endpoints: int = Field(default=0, description="Unique endpoints discovered")
    
    # Summary statistics
    auth_endpoints: int = Field(default=0, description="Endpoints with authentication")
    sensitive_endpoints: int = Field(default=0, description="Endpoints with sensitive data")
    vulnerable_endpoints: int = Field(default=0, description="Potentially vulnerable endpoints")
    
    class Config:
        from_attributes = True

class DiscoveryConfig(BaseModel):
    """Configuration for API discovery"""
    target_host: str = Field(default="localhost", description="Target host to monitor")
    target_port: int = Field(default=8000, description="Target port to monitor")
    proxy_port: int = Field(default=8080, description="Proxy port for traffic interception")
    capture_headers: bool = Field(default=True, description="Whether to capture request/response headers")
    capture_body: bool = Field(default=True, description="Whether to capture request/response bodies")
    max_body_size: int = Field(default=1024*1024, description="Maximum body size to capture (bytes)")
    session_name: str = Field(default="default", description="Name for this discovery session")
    
    # Security analysis settings
    detect_sensitive_data: bool = Field(default=True, description="Enable sensitive data detection")
    detect_auth_patterns: bool = Field(default=True, description="Enable authentication pattern detection")
    detect_idor_patterns: bool = Field(default=True, description="Enable IDOR pattern detection")

class DiscoverySummary(BaseModel):
    """Summary of discovery results"""
    total_endpoints: int
    unique_paths: int
    methods_used: List[HTTPMethod]
    auth_endpoints: int
    sensitive_endpoints: int
    vulnerable_endpoints: int
    discovery_duration: float  # in seconds
    
    # Top endpoints by request count
    most_accessed_endpoints: List[Dict[str, Any]]
    
    # Security findings
    security_findings: List[Dict[str, Any]]
    
    class Config:
        from_attributes = True 