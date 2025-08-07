import yaml
import json
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path

from models import (
    PolicyRule, PolicyCondition, PolicyAction, PolicyViolation,
    PolicyEvaluation, PolicyReport, PolicyConfig, PolicySet,
    RuleType, ConditionType, OperatorType, ActionType, SeverityLevel
)

class PolicyEngine:
    """YAML-driven policy engine for API governance"""
    
    def __init__(self, config: PolicyConfig):
        self.config = config
        self.rules: List[PolicyRule] = []
        self.evaluations: List[PolicyEvaluation] = []
        self.load_policies()
    
    def load_policies(self):
        """Load policies from YAML files"""
        policy_dir = Path(self.config.policy_directory)
        
        if not policy_dir.exists():
            print(f"⚠️  Policy directory not found: {policy_dir}")
            self._create_default_policies()
            return
        
        # Load all YAML files in policy directory
        for yaml_file in policy_dir.glob("*.yaml"):
            try:
                with open(yaml_file, 'r') as f:
                    policy_data = yaml.safe_load(f)
                
                if isinstance(policy_data, dict):
                    if 'rules' in policy_data:
                        # Policy set format
                        self._load_policy_set(policy_data)
                    elif 'name' in policy_data and 'conditions' in policy_data:
                        # Single rule format
                        self._load_single_rule(policy_data)
                elif isinstance(policy_data, list):
                    # List of rules format
                    for rule_data in policy_data:
                        self._load_single_rule(rule_data)
                
                print(f"✅ Loaded policies from {yaml_file}")
                
            except Exception as e:
                print(f"❌ Error loading policies from {yaml_file}: {e}")
        
        # Load custom rules if specified
        if self.config.custom_rules_file and Path(self.config.custom_rules_file).exists():
            self._load_custom_rules()
    
    def _create_default_policies(self):
        """Create default policy directory and sample policies"""
        policy_dir = Path(self.config.policy_directory)
        policy_dir.mkdir(exist_ok=True)
        
        # Create default security policies
        default_policies = self._get_default_policies()
        
        for policy_name, policy_content in default_policies.items():
            policy_file = policy_dir / f"{policy_name}.yaml"
            with open(policy_file, 'w') as f:
                yaml.dump(policy_content, f, default_flow_style=False, indent=2)
        
        print(f"✅ Created default policies in {policy_dir}")
        self.load_policies()
    
    def _get_default_policies(self) -> Dict[str, Any]:
        """Get default policy definitions"""
        return {
            "security_policies": {
                "name": "Security Policies",
                "description": "Default security policies for API governance",
                "version": "1.0.0",
                "rules": [
                    {
                        "name": "No Plaintext Passwords",
                        "description": "Block requests containing plaintext passwords",
                        "rule_type": "security",
                        "severity": "high",
                        "conditions": [
                            {
                                "type": "body_contains",
                                "field": "password",
                                "operator": "contains",
                                "value": "password",
                                "description": "Request body contains password field"
                            }
                        ],
                        "actions": [
                            {
                                "type": "block",
                                "parameters": {"reason": "Plaintext password detected"},
                                "description": "Block the request"
                            },
                            {
                                "type": "log",
                                "parameters": {"level": "warning"},
                                "description": "Log the violation"
                            }
                        ]
                    },
                    {
                        "name": "Require Authentication",
                        "description": "Require authentication for sensitive endpoints",
                        "rule_type": "security",
                        "severity": "critical",
                        "conditions": [
                            {
                                "type": "endpoint_match",
                                "field": "path",
                                "operator": "regex_match",
                                "value": r"/(admin|internal|debug|users|profiles)",
                                "description": "Sensitive endpoint accessed"
                            },
                            {
                                "type": "header_present",
                                "field": "Authorization",
                                "operator": "not_equals",
                                "value": "present",
                                "description": "No authorization header"
                            }
                        ],
                        "condition_logic": "AND",
                        "actions": [
                            {
                                "type": "block",
                                "parameters": {"reason": "Authentication required"},
                                "description": "Block unauthenticated access"
                            },
                            {
                                "type": "alert",
                                "parameters": {"channel": "security"},
                                "description": "Send security alert"
                            }
                        ]
                    },
                    {
                        "name": "Rate Limiting",
                        "description": "Enforce rate limiting on API endpoints",
                        "rule_type": "performance",
                        "severity": "medium",
                        "conditions": [
                            {
                                "type": "custom_regex",
                                "field": "request_count",
                                "operator": "greater_than",
                                "value": 100,
                                "description": "Request count exceeds limit"
                            }
                        ],
                        "actions": [
                            {
                                "type": "rate_limit",
                                "parameters": {"window": 60, "max_requests": 100},
                                "description": "Apply rate limiting"
                            }
                        ]
                    }
                ]
            },
            "compliance_policies": {
                "name": "Compliance Policies",
                "description": "Default compliance policies for data protection",
                "version": "1.0.0",
                "rules": [
                    {
                        "name": "PII Data Protection",
                        "description": "Ensure PII data is properly protected",
                        "rule_type": "compliance",
                        "severity": "critical",
                        "conditions": [
                            {
                                "type": "body_contains",
                                "field": "ssn",
                                "operator": "contains",
                                "value": "ssn",
                                "description": "SSN data in request/response"
                            }
                        ],
                        "actions": [
                            {
                                "type": "log",
                                "parameters": {"level": "critical"},
                                "description": "Log PII exposure"
                            },
                            {
                                "type": "alert",
                                "parameters": {"channel": "compliance"},
                                "description": "Alert compliance team"
                            }
                        ]
                    },
                    {
                        "name": "HTTPS Enforcement",
                        "description": "Enforce HTTPS for all API communications",
                        "rule_type": "security",
                        "severity": "high",
                        "conditions": [
                            {
                                "type": "header_value",
                                "field": "X-Forwarded-Proto",
                                "operator": "not_equals",
                                "value": "https",
                                "description": "Non-HTTPS request"
                            }
                        ],
                        "actions": [
                            {
                                "type": "redirect",
                                "parameters": {"url": "https://"},
                                "description": "Redirect to HTTPS"
                            }
                        ]
                    }
                ]
            }
        }
    
    def _load_policy_set(self, policy_data: Dict[str, Any]):
        """Load a policy set from YAML data"""
        for rule_data in policy_data.get('rules', []):
            self._load_single_rule(rule_data)
    
    def _load_single_rule(self, rule_data: Dict[str, Any]):
        """Load a single policy rule from YAML data"""
        try:
            # Parse conditions
            conditions = []
            for cond_data in rule_data.get('conditions', []):
                condition = PolicyCondition(
                    type=ConditionType(cond_data['type']),
                    field=cond_data['field'],
                    operator=OperatorType(cond_data['operator']),
                    value=cond_data['value'],
                    description=cond_data['description']
                )
                conditions.append(condition)
            
            # Parse actions
            actions = []
            for action_data in rule_data.get('actions', []):
                action = PolicyAction(
                    type=ActionType(action_data['type']),
                    parameters=action_data.get('parameters', {}),
                    description=action_data['description']
                )
                actions.append(action)
            
            # Create rule
            rule = PolicyRule(
                id=rule_data.get('id', f"rule_{len(self.rules)}"),
                name=rule_data['name'],
                description=rule_data['description'],
                rule_type=RuleType(rule_data['rule_type']),
                severity=SeverityLevel(rule_data['severity']),
                enabled=rule_data.get('enabled', True),
                conditions=conditions,
                condition_logic=rule_data.get('condition_logic', 'AND'),
                actions=actions,
                tags=rule_data.get('tags', [])
            )
            
            self.rules.append(rule)
            
        except Exception as e:
            print(f"❌ Error loading rule {rule_data.get('name', 'unknown')}: {e}")
    
    def _load_custom_rules(self):
        """Load custom rules from specified file"""
        try:
            with open(self.config.custom_rules_file, 'r') as f:
                custom_rules = yaml.safe_load(f)
            
            if isinstance(custom_rules, list):
                for rule_data in custom_rules:
                    self._load_single_rule(rule_data)
            elif isinstance(custom_rules, dict):
                self._load_single_rule(custom_rules)
            
            print(f"✅ Loaded custom rules from {self.config.custom_rules_file}")
            
        except Exception as e:
            print(f"❌ Error loading custom rules: {e}")
    
    def evaluate_request_response(self, endpoint: str, method: str,
                                request_headers: Dict[str, str],
                                request_body: Optional[Dict[str, Any]],
                                response_status: int,
                                response_headers: Dict[str, str],
                                response_body: Optional[Dict[str, Any]]) -> PolicyEvaluation:
        """Evaluate a request/response against all policies"""
        
        evaluation = PolicyEvaluation(
            endpoint=endpoint,
            method=method,
            request_headers=request_headers,
            request_body=request_body,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body
        )
        
        violations = []
        rules_evaluated = 0
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            rules_evaluated += 1
            
            # Check if rule conditions are met
            if self._evaluate_rule_conditions(rule, endpoint, method, request_headers, 
                                            request_body, response_status, response_headers, response_body):
                
                # Create violation
                violation = PolicyViolation(
                    rule_id=rule.id or rule.name,
                    rule_name=rule.name,
                    endpoint=endpoint,
                    method=method,
                    severity=rule.severity,
                    description=rule.description,
                    evidence=self._collect_violation_evidence(rule, endpoint, method, 
                                                           request_headers, request_body, 
                                                           response_status, response_headers, response_body),
                    request_headers=request_headers,
                    request_body=request_body,
                    response_status=response_status,
                    response_headers=response_headers,
                    response_body=response_body,
                    actions_taken=[action.type.value for action in rule.actions]
                )
                
                violations.append(violation)
                
                # Execute actions
                self._execute_actions(rule.actions, violation)
        
        # Update evaluation
        evaluation.rules_evaluated = rules_evaluated
        evaluation.violations_found = len(violations)
        evaluation.violations = violations
        
        # Determine overall severity
        if violations:
            max_severity = max(violation.severity for violation in violations)
            evaluation.overall_severity = max_severity
            evaluation.blocked = any(action.type == ActionType.BLOCK for violation in violations 
                                   for action in violations[0].actions_taken)
        else:
            evaluation.overall_severity = SeverityLevel.LOW
        
        self.evaluations.append(evaluation)
        return evaluation
    
    def _evaluate_rule_conditions(self, rule: PolicyRule, endpoint: str, method: str,
                                 request_headers: Dict[str, str], request_body: Optional[Dict[str, Any]],
                                 response_status: int, response_headers: Dict[str, str],
                                 response_body: Optional[Dict[str, Any]]) -> bool:
        """Evaluate if a rule's conditions are met"""
        
        condition_results = []
        
        for condition in rule.conditions:
            result = self._evaluate_condition(condition, endpoint, method, request_headers,
                                           request_body, response_status, response_headers, response_body)
            condition_results.append(result)
        
        # Apply condition logic
        if rule.condition_logic.upper() == "AND":
            return all(condition_results)
        elif rule.condition_logic.upper() == "OR":
            return any(condition_results)
        else:
            return all(condition_results)  # Default to AND
    
    def _evaluate_condition(self, condition: PolicyCondition, endpoint: str, method: str,
                           request_headers: Dict[str, str], request_body: Optional[Dict[str, Any]],
                           response_status: int, response_headers: Dict[str, str],
                           response_body: Optional[Dict[str, Any]]) -> bool:
        """Evaluate a single condition"""
        
        if condition.type == ConditionType.ENDPOINT_MATCH:
            return self._evaluate_endpoint_match(condition, endpoint)
        
        elif condition.type == ConditionType.METHOD_MATCH:
            return self._evaluate_method_match(condition, method)
        
        elif condition.type == ConditionType.HEADER_PRESENT:
            return self._evaluate_header_present(condition, request_headers, response_headers)
        
        elif condition.type == ConditionType.HEADER_VALUE:
            return self._evaluate_header_value(condition, request_headers, response_headers)
        
        elif condition.type == ConditionType.BODY_CONTAINS:
            return self._evaluate_body_contains(condition, request_body, response_body)
        
        elif condition.type == ConditionType.RESPONSE_STATUS:
            return self._evaluate_response_status(condition, response_status)
        
        elif condition.type == ConditionType.SENSITIVE_DATA:
            return self._evaluate_sensitive_data(condition, request_body, response_body)
        
        elif condition.type == ConditionType.AUTH_REQUIRED:
            return self._evaluate_auth_required(condition, request_headers)
        
        elif condition.type == ConditionType.CUSTOM_REGEX:
            return self._evaluate_custom_regex(condition, endpoint, method, request_headers, 
                                             request_body, response_headers, response_body)
        
        return False
    
    def _evaluate_endpoint_match(self, condition: PolicyCondition, endpoint: str) -> bool:
        """Evaluate endpoint matching condition"""
        if condition.operator == OperatorType.REGEX_MATCH:
            return bool(re.search(condition.value, endpoint))
        elif condition.operator == OperatorType.EQUALS:
            return endpoint == condition.value
        elif condition.operator == OperatorType.CONTAINS:
            return condition.value in endpoint
        return False
    
    def _evaluate_method_match(self, condition: PolicyCondition, method: str) -> bool:
        """Evaluate HTTP method matching condition"""
        if condition.operator == OperatorType.EQUALS:
            return method.upper() == condition.value.upper()
        return False
    
    def _evaluate_header_present(self, condition: PolicyCondition, 
                                request_headers: Dict[str, str], 
                                response_headers: Dict[str, str]) -> bool:
        """Evaluate header presence condition"""
        header_name = condition.field
        headers = {**request_headers, **response_headers}
        
        if condition.operator == OperatorType.EQUALS:
            return header_name in headers
        elif condition.operator == OperatorType.NOT_EQUALS:
            return header_name not in headers
        return False
    
    def _evaluate_header_value(self, condition: PolicyCondition,
                              request_headers: Dict[str, str],
                              response_headers: Dict[str, str]) -> bool:
        """Evaluate header value condition"""
        header_name = condition.field
        headers = {**request_headers, **response_headers}
        
        if header_name not in headers:
            return False
        
        header_value = headers[header_name]
        
        if condition.operator == OperatorType.EQUALS:
            return header_value == condition.value
        elif condition.operator == OperatorType.CONTAINS:
            return condition.value in header_value
        elif condition.operator == OperatorType.REGEX_MATCH:
            return bool(re.search(condition.value, header_value))
        return False
    
    def _evaluate_body_contains(self, condition: PolicyCondition,
                               request_body: Optional[Dict[str, Any]],
                               response_body: Optional[Dict[str, Any]]) -> bool:
        """Evaluate body content condition"""
        bodies = []
        if request_body:
            bodies.append(json.dumps(request_body))
        if response_body:
            bodies.append(json.dumps(response_body))
        
        body_text = " ".join(bodies)
        
        if condition.operator == OperatorType.CONTAINS:
            return condition.value.lower() in body_text.lower()
        elif condition.operator == OperatorType.REGEX_MATCH:
            return bool(re.search(condition.value, body_text, re.IGNORECASE))
        return False
    
    def _evaluate_response_status(self, condition: PolicyCondition, response_status: int) -> bool:
        """Evaluate response status condition"""
        if condition.operator == OperatorType.EQUALS:
            return response_status == condition.value
        elif condition.operator == OperatorType.GREATER_THAN:
            return response_status > condition.value
        elif condition.operator == OperatorType.LESS_THAN:
            return response_status < condition.value
        return False
    
    def _evaluate_sensitive_data(self, condition: PolicyCondition,
                                request_body: Optional[Dict[str, Any]],
                                response_body: Optional[Dict[str, Any]]) -> bool:
        """Evaluate sensitive data condition"""
        # This would integrate with the sensitive data classifier
        # For now, use simple pattern matching
        bodies = []
        if request_body:
            bodies.append(json.dumps(request_body))
        if response_body:
            bodies.append(json.dumps(response_body))
        
        body_text = " ".join(bodies)
        
        sensitive_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit card
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, body_text):
                return True
        
        return False
    
    def _evaluate_auth_required(self, condition: PolicyCondition, request_headers: Dict[str, str]) -> bool:
        """Evaluate authentication requirement condition"""
        auth_headers = ['Authorization', 'X-API-Key', 'X-Auth-Token']
        
        has_auth = any(header in request_headers for header in auth_headers)
        
        if condition.operator == OperatorType.EQUALS:
            return has_auth == condition.value
        return has_auth
    
    def _evaluate_custom_regex(self, condition: PolicyCondition, endpoint: str, method: str,
                              request_headers: Dict[str, str], request_body: Optional[Dict[str, Any]],
                              response_headers: Dict[str, str], response_body: Optional[Dict[str, Any]]) -> bool:
        """Evaluate custom regex condition"""
        # Combine all data for regex search
        data_to_search = [
            endpoint,
            method,
            json.dumps(request_headers),
            json.dumps(request_body) if request_body else "",
            json.dumps(response_headers),
            json.dumps(response_body) if response_body else ""
        ]
        
        search_text = " ".join(data_to_search)
        
        if condition.operator == OperatorType.REGEX_MATCH:
            return bool(re.search(condition.value, search_text, re.IGNORECASE))
        elif condition.operator == OperatorType.REGEX_NOT_MATCH:
            return not bool(re.search(condition.value, search_text, re.IGNORECASE))
        return False
    
    def _collect_violation_evidence(self, rule: PolicyRule, endpoint: str, method: str,
                                   request_headers: Dict[str, str], request_body: Optional[Dict[str, Any]],
                                   response_status: int, response_headers: Dict[str, str],
                                   response_body: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Collect evidence for a policy violation"""
        return {
            "rule_name": rule.name,
            "rule_description": rule.description,
            "endpoint": endpoint,
            "method": method,
            "request_headers": {k: v for k, v in request_headers.items() if k.lower() not in ['authorization', 'cookie']},
            "response_status": response_status,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _execute_actions(self, actions: List[PolicyAction], violation: PolicyViolation):
        """Execute policy actions"""
        for action in actions:
            if action.type == ActionType.LOG:
                print(f"🚨 POLICY VIOLATION: {violation.rule_name} - {violation.description}")
            
            elif action.type == ActionType.ALERT:
                print(f"🚨 ALERT: {violation.rule_name} violation detected!")
                print(f"   Endpoint: {violation.endpoint}")
                print(f"   Severity: {violation.severity.value}")
            
            elif action.type == ActionType.BLOCK:
                print(f"🚫 BLOCKED: {violation.rule_name} - Request blocked due to policy violation")
    
    def generate_report(self, target_api: str) -> PolicyReport:
        """Generate comprehensive policy evaluation report"""
        
        total_requests = len(self.evaluations)
        requests_with_violations = len([e for e in self.evaluations if e.violations_found > 0])
        total_violations = sum(e.violations_found for e in self.evaluations)
        
        # Violation breakdown
        violations_by_severity = {}
        violations_by_rule = {}
        violations_by_endpoint = {}
        
        for evaluation in self.evaluations:
            for violation in evaluation.violations:
                # By severity
                violations_by_severity[violation.severity] = violations_by_severity.get(violation.severity, 0) + 1
                
                # By rule
                violations_by_rule[violation.rule_name] = violations_by_rule.get(violation.rule_name, 0) + 1
                
                # By endpoint
                violations_by_endpoint[violation.endpoint] = violations_by_endpoint.get(violation.endpoint, 0) + 1
        
        # Calculate risk score
        if total_violations > 0:
            critical_count = violations_by_severity.get(SeverityLevel.CRITICAL, 0)
            high_count = violations_by_severity.get(SeverityLevel.HIGH, 0)
            medium_count = violations_by_severity.get(SeverityLevel.MEDIUM, 0)
            
            risk_score = min(10, (critical_count * 3 + high_count * 2 + medium_count) / total_violations * 10)
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
        if violations_by_severity.get(SeverityLevel.CRITICAL, 0) > 0:
            compliance_issues.append("Critical policy violations detected")
        if violations_by_rule.get("No Plaintext Passwords", 0) > 0:
            compliance_issues.append("Plaintext passwords detected in API traffic")
        if violations_by_rule.get("Require Authentication", 0) > 0:
            compliance_issues.append("Unauthenticated access to sensitive endpoints")
        
        return PolicyReport(
            report_name=f"Policy Evaluation Report - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
            target_api=target_api,
            generated_at=datetime.utcnow(),
            total_requests_evaluated=total_requests,
            requests_with_violations=requests_with_violations,
            total_violations=total_violations,
            violations_by_severity=violations_by_severity,
            violations_by_rule=violations_by_rule,
            violations_by_endpoint=violations_by_endpoint,
            evaluations=self.evaluations,
            overall_risk_score=risk_score,
            overall_risk_level=overall_risk_level,
            compliance_issues=compliance_issues
        ) 