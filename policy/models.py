from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any, Union
from datetime import datetime
from enum import Enum

class RuleType(str, Enum):
    """Types of policy rules"""
    SECURITY = "security"
    COMPLIANCE = "compliance"
    PERFORMANCE = "performance"
    CUSTOM = "custom"

class ConditionType(str, Enum):
    """Types of rule conditions"""
    ENDPOINT_MATCH = "endpoint_match"
    METHOD_MATCH = "method_match"
    HEADER_PRESENT = "header_present"
    HEADER_VALUE = "header_value"
    BODY_CONTAINS = "body_contains"
    RESPONSE_STATUS = "response_status"
    RESPONSE_TIME = "response_time"
    SENSITIVE_DATA = "sensitive_data"
    AUTH_REQUIRED = "auth_required"
    CUSTOM_REGEX = "custom_regex"

class OperatorType(str, Enum):
    """Comparison operators"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    REGEX_MATCH = "regex_match"
    REGEX_NOT_MATCH = "regex_not_match"

class ActionType(str, Enum):
    """Types of policy actions"""
    BLOCK = "block"
    WARN = "warn"
    LOG = "log"
    ALERT = "alert"
    REDIRECT = "redirect"
    RATE_LIMIT = "rate_limit"

class SeverityLevel(str, Enum):
    """Policy violation severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PolicyCondition(BaseModel):
    """Represents a condition in a policy rule"""
    type: ConditionType = Field(..., description="Type of condition")
    field: str = Field(..., description="Field to check")
    operator: OperatorType = Field(..., description="Comparison operator")
    value: Any = Field(..., description="Value to compare against")
    description: str = Field(..., description="Human-readable description")
    
    class Config:
        from_attributes = True

class PolicyAction(BaseModel):
    """Represents an action to take when a rule is violated"""
    type: ActionType = Field(..., description="Type of action")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    description: str = Field(..., description="Human-readable description")
    
    class Config:
        from_attributes = True

class PolicyRule(BaseModel):
    """Represents a single policy rule"""
    id: Optional[str] = None
    name: str = Field(..., description="Rule name")
    description: str = Field(..., description="Rule description")
    rule_type: RuleType = Field(..., description="Type of rule")
    severity: SeverityLevel = Field(..., description="Violation severity")
    enabled: bool = Field(default=True, description="Whether rule is enabled")
    
    # Conditions
    conditions: List[PolicyCondition] = Field(..., description="Rule conditions")
    condition_logic: str = Field(default="AND", description="Logic for combining conditions (AND/OR)")
    
    # Actions
    actions: List[PolicyAction] = Field(..., description="Actions to take on violation")
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation time")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update time")
    tags: List[str] = Field(default_factory=list, description="Rule tags")
    
    class Config:
        from_attributes = True

class PolicyViolation(BaseModel):
    """Represents a policy violation"""
    id: Optional[str] = None
    rule_id: str = Field(..., description="Violated rule ID")
    rule_name: str = Field(..., description="Violated rule name")
    endpoint: str = Field(..., description="Violating endpoint")
    method: str = Field(..., description="HTTP method")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Violation time")
    
    # Violation details
    severity: SeverityLevel = Field(..., description="Violation severity")
    description: str = Field(..., description="Violation description")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Evidence of violation")
    
    # Request/response context
    request_headers: Dict[str, str] = Field(default_factory=dict, description="Request headers")
    request_body: Optional[Dict[str, Any]] = Field(default=None, description="Request body")
    response_status: int = Field(..., description="Response status")
    response_headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    response_body: Optional[Dict[str, Any]] = Field(default=None, description="Response body")
    
    # Actions taken
    actions_taken: List[str] = Field(default_factory=list, description="Actions that were taken")
    
    class Config:
        from_attributes = True

class PolicyEvaluation(BaseModel):
    """Represents the evaluation of a single request/response against policies"""
    id: Optional[str] = None
    endpoint: str = Field(..., description="API endpoint")
    method: str = Field(..., description="HTTP method")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Evaluation time")
    
    # Evaluation results
    rules_evaluated: int = Field(..., description="Number of rules evaluated")
    violations_found: int = Field(..., description="Number of violations found")
    violations: List[PolicyViolation] = Field(default_factory=list, description="Policy violations")
    
    # Request/response data
    request_headers: Dict[str, str] = Field(default_factory=dict, description="Request headers")
    request_body: Optional[Dict[str, Any]] = Field(default=None, description="Request body")
    response_status: int = Field(..., description="Response status")
    response_headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    response_body: Optional[Dict[str, Any]] = Field(default=None, description="Response body")
    
    # Summary
    overall_severity: SeverityLevel = Field(..., description="Overall severity level")
    blocked: bool = Field(default=False, description="Whether request was blocked")
    
    class Config:
        from_attributes = True

class PolicyReport(BaseModel):
    """Comprehensive policy evaluation report"""
    id: Optional[str] = None
    report_name: str = Field(..., description="Report name")
    target_api: str = Field(..., description="Target API URL")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Report generation time")
    
    # Summary statistics
    total_requests_evaluated: int = Field(..., description="Total requests evaluated")
    requests_with_violations: int = Field(..., description="Requests with violations")
    total_violations: int = Field(..., description="Total policy violations")
    
    # Violation breakdown
    violations_by_severity: Dict[SeverityLevel, int] = Field(default_factory=dict, description="Violations by severity")
    violations_by_rule: Dict[str, int] = Field(default_factory=dict, description="Violations by rule")
    violations_by_endpoint: Dict[str, int] = Field(default_factory=dict, description="Violations by endpoint")
    
    # Detailed results
    evaluations: List[PolicyEvaluation] = Field(default_factory=list, description="Detailed evaluations")
    
    # Risk assessment
    overall_risk_score: float = Field(..., description="Overall risk score (0-10)")
    overall_risk_level: SeverityLevel = Field(..., description="Overall risk level")
    
    # Compliance
    compliance_issues: List[str] = Field(default_factory=list, description="Compliance issues found")
    
    class Config:
        from_attributes = True

class PolicyConfig(BaseModel):
    """Configuration for policy engine"""
    # Engine settings
    enable_realtime_evaluation: bool = Field(default=True, description="Enable real-time evaluation")
    enable_blocking: bool = Field(default=False, description="Enable request blocking")
    enable_logging: bool = Field(default=True, description="Enable detailed logging")
    
    # Evaluation settings
    evaluate_requests: bool = Field(default=True, description="Evaluate incoming requests")
    evaluate_responses: bool = Field(default=True, description="Evaluate responses")
    max_evaluation_time: float = Field(default=1.0, description="Max evaluation time in seconds")
    
    # Reporting settings
    generate_reports: bool = Field(default=True, description="Generate evaluation reports")
    report_format: str = Field(default="json", description="Report format")
    include_evidence: bool = Field(default=True, description="Include evidence in reports")
    
    # Custom settings
    custom_rules_file: Optional[str] = Field(default=None, description="Custom rules file path")
    policy_directory: str = Field(default="policies", description="Policy directory")
    
    class Config:
        from_attributes = True

class PolicyTemplate(BaseModel):
    """Template for creating policy rules"""
    name: str = Field(..., description="Template name")
    description: str = Field(..., description="Template description")
    category: str = Field(..., description="Template category")
    
    # Template structure
    conditions_template: List[Dict[str, Any]] = Field(..., description="Condition templates")
    actions_template: List[Dict[str, Any]] = Field(..., description="Action templates")
    
    # Parameters
    parameters: List[Dict[str, Any]] = Field(default_factory=list, description="Template parameters")
    
    class Config:
        from_attributes = True

class PolicySet(BaseModel):
    """Collection of related policy rules"""
    id: Optional[str] = None
    name: str = Field(..., description="Policy set name")
    description: str = Field(..., description="Policy set description")
    version: str = Field(..., description="Policy set version")
    
    # Rules
    rules: List[PolicyRule] = Field(default_factory=list, description="Policy rules")
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation time")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update time")
    tags: List[str] = Field(default_factory=list, description="Policy set tags")
    
    class Config:
        from_attributes = True 