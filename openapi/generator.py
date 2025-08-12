import json
import yaml
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse
import re
from datetime import datetime
from pathlib import Path

# Import local discovery models
try:
    from discovery.models import APIEndpoint, HTTPMethod, AuthType, SecurityLevel
except ImportError:
    # Fallback if discovery models not available
    from enum import Enum

    class HTTPMethod(Enum):
        GET = "GET"
        POST = "POST"
        PUT = "PUT"
        DELETE = "DELETE"
        PATCH = "PATCH"
        HEAD = "HEAD"
        OPTIONS = "OPTIONS"

    class AuthType(Enum):
        NONE = "none"
        BEARER = "bearer"
        API_KEY = "api_key"
        BASIC = "basic"

    class SecurityLevel(Enum):
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
    
    class APIEndpoint:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

# Define OpenAPI model classes since they're not imported
class Operation:
    def __init__(self, operationId=None, summary=None, description=None, tags=None, 
                 parameters=None, requestBody=None, responses=None, security=None):
        self.operationId = operationId
        self.summary = summary
        self.description = description
        self.tags = tags or []
        self.parameters = parameters or []
        self.requestBody = requestBody
        self.responses = responses or {}
        self.security = security
    
    def dict(self, exclude_none=True):
        result = {}
        for key, value in self.__dict__.items():
            if not exclude_none or value is not None:
                if isinstance(value, list) and all(hasattr(item, 'dict') for item in value):
                    result[key] = [item.dict(exclude_none=exclude_none) for item in value]
                elif hasattr(value, 'dict'):
                    result[key] = value.dict(exclude_none=exclude_none)
                else:
                    result[key] = value
        return result

class Parameter:
    def __init__(self, name, in_, required=False, schema=None, description=None):
        self.name = name
        self.in_ = in_  # 'path', 'query', 'header', etc.
        self.required = required
        self.schema = schema or {}
        self.description = description
    
    def dict(self, exclude_none=True):
        result = {
            "name": self.name,
            "in": self.in_,
            "required": self.required,
            "schema": self.schema
        }
        if not exclude_none or self.description:
            result["description"] = self.description
        return result

class MediaType:
    def __init__(self, schema=None):
        self.schema = schema or {}
    
    def dict(self, exclude_none=True):
        return {"schema": self.schema}

class RequestBody:
    def __init__(self, required=False, content=None):
        self.required = required
        self.content = content or {}
    
    def dict(self, exclude_none=True):
        result = {"required": self.required}
        if self.content:
            content_dict = {}
            for media_type, media_obj in self.content.items():
                if hasattr(media_obj, 'dict'):
                    content_dict[media_type] = media_obj.dict(exclude_none=exclude_none)
                else:
                    content_dict[media_type] = media_obj
            result["content"] = content_dict
        return result

class Response:
    def __init__(self, description, content=None):
        self.description = description
        self.content = content or {}
    
    def dict(self, exclude_none=True):
        result = {"description": self.description}
        if self.content:
            content_dict = {}
            for media_type, media_obj in self.content.items():
                if hasattr(media_obj, 'dict'):
                    content_dict[media_type] = media_obj.dict(exclude_none=exclude_none)
                else:
                    content_dict[media_type] = media_obj
            result["content"] = content_dict
        return result

class OpenAPISpec:
    def __init__(self, spec_dict):
        self.spec_dict = spec_dict
    
    def dict(self, exclude_none=True):
        return self.spec_dict

class OpenAPIGenerator:
    """Generator for converting discovered API traffic to OpenAPI 3.0 specifications"""
    
    def __init__(self, db_path: str = "discovery.db"):
        self.db_path = db_path
        self.generated_schemas = {}
        
    def load_discovered_endpoints(self) -> List[APIEndpoint]:
        """Load discovered endpoints from database"""
        try: 
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
        
            cursor.execute('''
                SELECT 
                    path, method, host, port, scheme, query_params, headers, body,
                    status_code, response_headers, response_body, auth_type, has_auth,
                    security_level, contains_sensitive_data, potential_idor, missing_auth,
                    discovered_at, last_seen, request_count
                FROM endpoints
                ORDER BY path, method
            ''')
        
            endpoints = []
            for row in cursor.fetchall():
                endpoint = APIEndpoint(
                    path=row[0],
                    method=HTTPMethod(row[1]),
                    host=row[2],
                    port=row[3],
                    scheme=row[4],
                    query_params=json.loads(row[5]) if row[5] else {},
                    headers=json.loads(row[6]) if row[6] else {},
                    body=json.loads(row[7]) if row[7] else None,
                    status_code=row[8],
                    response_headers=json.loads(row[9]) if row[9] else {},
                    response_body=json.loads(row[10]) if row[10] else None,
                    auth_type=AuthType(row[11]),
                    has_auth=bool(row[12]),
                    security_level=SecurityLevel(row[13]),
                    contains_sensitive_data=bool(row[14]),
                    potential_idor=bool(row[15]),
                    missing_auth=bool(row[16]),
                    discovered_at=row[17],
                    last_seen=row[18],
                    request_count=row[19]
                )
                endpoints.append(endpoint)
        
            conn.close()
            return endpoints
        except Exception as e:
            print(f"Warning: Could not load endpoints from database: {e}")
            return []
    
    def generate_openapi_spec(self, title: str = "Discovered API", version: str = "1.0.0") -> OpenAPISpec:
        """Generate OpenAPI specification from discovered endpoints"""
        
        endpoints = self.load_discovered_endpoints()
        
        # Group endpoints by path
        paths = {}
        for endpoint in endpoints:
            if endpoint.path not in paths:
                paths[endpoint.path] = {}
            
            # Create operation
            operation = self._create_operation(endpoint)
            
            # Add operation to path item
            paths[endpoint.path][endpoint.method.value.lower()] = operation.dict()

        
        # Create OpenAPI spec
        openapi_spec = {
            "openapi": "3.0.3",
            "info": {
                "title": title,
                "version": version,
                "description": f"Auto-generated API specification from discovered traffic. Generated on {datetime.utcnow().isoformat()}",
                "contact": {
                    "name": "LevoLite API Discovery",
                    "url": "https://github.com/levolite"
                }
            },
            "paths": paths,
            "servers": [
                {
                    "url": "http://localhost:8000",
                    "description": "Development server"
                }
            ],
            "components": self._create_components(endpoints)
        }
        
        # Add global security if needed
        security = self._create_global_security(endpoints)
        if security:
            openapi_spec["security"] = security

        return OpenAPISpec(openapi_spec)
    
    def _create_operation(self, endpoint: APIEndpoint) -> Operation:
        """Create an OpenAPI operation from an endpoint"""
        
        # Generate operation ID
        operation_id = self._generate_operation_id(endpoint.path, endpoint.method)
        
        # Create parameters
        parameters = self._extract_parameters(endpoint)
        
        # Create request body
        request_body = self._create_request_body(endpoint)
        
        # Create responses
        responses = self._create_responses(endpoint)
        
        # Create security requirements
        security = self._create_security_requirement(endpoint)
        
        # Generate description
        description = self._generate_description(endpoint)
        
        # Generate tags
        tags = self._extract_tags(endpoint.path)
        
        return Operation(
            operationId=operation_id,
            summary=self._generate_summary(endpoint),
            description=description,
            tags=tags,
            parameters=parameters,
            requestBody=request_body,
            responses=responses,
            security=security
        )
    
    def _generate_operation_id(self, path: str, method: HTTPMethod) -> str:
        """Generate a unique operation ID"""
        # Convert path to camelCase
        path_parts = path.strip('/').split('/')
        operation_id = method.value.lower()
        
        for part in path_parts:
            if part.startswith('{') and part.endswith('}'):
                # Path parameter
                param_name = part[1:-1]
                operation_id += f"By{param_name.capitalize()}"
            else:
                # Regular path part
                operation_id += part.capitalize()
        
        return operation_id
    
    def _extract_parameters(self, endpoint: APIEndpoint) -> List[Parameter]:
        """Extract parameters from endpoint"""
        parameters = []
        
        # Path parameters
        path_params = re.findall(r'\{([^}]+)\}', endpoint.path)
        for param_name in path_params:
            parameters.append(Parameter(
                name=param_name,
                in_="path",
                required=True,
                schema={"type": "string"},
                description=f"ID of the {param_name.replace('_', ' ')}"
            ))
        
        # Query parameters
        for param_name, param_value in endpoint.query_params.items():
            param_type = self._infer_parameter_type(param_value)
            parameters.append(Parameter(
                name=param_name,
                in_="query",
                required=False,
                schema={"type": param_type},
                description=f"Query parameter: {param_name}"
            ))
        
        return parameters
    
    def _create_request_body(self, endpoint: APIEndpoint) -> Optional[RequestBody]:
        """Create request body from endpoint"""
        if not endpoint.body or endpoint.method in [HTTPMethod.GET, HTTPMethod.DELETE, HTTPMethod.HEAD, HTTPMethod.OPTIONS]:
            return None
        
        # Infer content type
        content_type = "application/json"
        if endpoint.headers:
            content_type = endpoint.headers.get("content-type", "application/json")
        
        # Create schema from body
        schema = self._infer_schema_from_data(endpoint.body)
        
        return RequestBody(
            required=True,
            content={
                content_type: MediaType(
                    schema=schema
                )
            }
        )
    
    def _create_responses(self, endpoint: APIEndpoint) -> Dict[str, Response]:
        """Create responses from endpoint"""
        responses = {}
        
        # Add the actual response if we have it
        if endpoint.status_code:
            status_code = str(endpoint.status_code)
            description = self._get_status_description(endpoint.status_code)
            
            content = {}
            if endpoint.response_body:
                schema = self._infer_schema_from_data(endpoint.response_body)
                content["application/json"] = MediaType(schema=schema)
            
            responses[status_code] = Response(
                description=description,
                content=content
            )
        else:
            # Default responses based on method
            if endpoint.method == HTTPMethod.GET:
                responses["200"] = Response(description="Successful response")
                responses["404"] = Response(description="Resource not found")
            elif endpoint.method == HTTPMethod.POST:
                responses["201"] = Response(description="Resource created")
                responses["400"] = Response(description="Bad request")
            elif endpoint.method == HTTPMethod.PUT:
                responses["200"] = Response(description="Resource updated")
                responses["404"] = Response(description="Resource not found")
            elif endpoint.method == HTTPMethod.DELETE:
                responses["204"] = Response(description="Resource deleted")
                responses["404"] = Response(description="Resource not found")
        
        # Add common error responses
        responses["401"] = Response(description="Unauthorized")
        responses["403"] = Response(description="Forbidden")
        responses["500"] = Response(description="Internal server error")
        
        return responses
    
    def _create_security_requirement(self, endpoint: APIEndpoint) -> Optional[List[Dict[str, List[str]]]]:
        """Create security requirements for endpoint"""
        if not endpoint.has_auth:
            return None
        
        if endpoint.auth_type == AuthType.BEARER:
            return [{"bearerAuth": []}]
        elif endpoint.auth_type == AuthType.API_KEY:
            return [{"apiKeyAuth": []}]
        elif endpoint.auth_type == AuthType.BASIC:
            return [{"basicAuth": []}]
        else:
            return None
    
    def _create_components(self, endpoints: List[APIEndpoint]) -> Dict[str, Any]:
        """Create components section"""
        components = {
            "schemas": {},
            "securitySchemes": {}
        }
        
        # Generate schemas from request/response bodies
        for endpoint in endpoints:
            if endpoint.body:
                schema_name = self._generate_schema_name(endpoint.path, "Request")
                components["schemas"][schema_name] = self._infer_schema_from_data(endpoint.body)
            
            if endpoint.response_body:
                schema_name = self._generate_schema_name(endpoint.path, "Response")
                components["schemas"][schema_name] = self._infer_schema_from_data(endpoint.response_body)
        
        # Add security schemes
        auth_types = set(endpoint.auth_type for endpoint in endpoints if endpoint.has_auth)
        
        if AuthType.BEARER in auth_types:
            components["securitySchemes"]["bearerAuth"] = {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        
        if AuthType.API_KEY in auth_types:
            components["securitySchemes"]["apiKeyAuth"] = {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key"
            }
        
        if AuthType.BASIC in auth_types:
            components["securitySchemes"]["basicAuth"] = {
                "type": "http",
                "scheme": "basic"
            }
        
        return components
    
    def _create_global_security(self, endpoints: List[APIEndpoint]) -> Optional[List[Dict[str, List[str]]]]:
        """Create global security schemes"""
        auth_endpoints = [e for e in endpoints if e.has_auth]
        if not auth_endpoints:
            return None
        
        # Use the most common auth type
        auth_types = {}
        for endpoint in auth_endpoints:
            auth_types[endpoint.auth_type] = auth_types.get(endpoint.auth_type, 0) + 1
        
        most_common = max(auth_types.items(), key=lambda x: x[1])[0]
        
        if most_common == AuthType.BEARER:
            return [{"bearerAuth": []}]
        elif most_common == AuthType.API_KEY:
            return [{"apiKeyAuth": []}]
        elif most_common == AuthType.BASIC:
            return [{"basicAuth": []}]
        
        return None
    
    def _generate_summary(self, endpoint: APIEndpoint) -> str:
        """Generate operation summary"""
        method = endpoint.method.value
        path = endpoint.path
        
        if "users" in path:
            if "{id}" in path:
                return f"{method} user by ID"
            else:
                return f"{method} users"
        elif "profiles" in path:
            if "{id}" in path:
                return f"{method} profile by ID"
            else:
                return f"{method} profiles"
        elif "admin" in path:
            return f"{method} admin data"
        elif "login" in path:
            return f"{method} authentication"
        elif "health" in path:
            return f"{method} health status"
        else:
            return f"{method} {path.strip('/').replace('/', ' ')}"
    
    def _generate_description(self, endpoint: APIEndpoint) -> str:
        """Generate operation description"""
        description = f"Endpoint discovered on {endpoint.discovered_at}"
        
        if endpoint.contains_sensitive_data:
            description += "\n\n⚠️ **Contains sensitive data**"
        
        if endpoint.potential_idor:
            description += "\n\n🚨 **Potential IDOR vulnerability detected**"
        
        if endpoint.missing_auth:
            description += "\n\n🔒 **Missing authentication on sensitive endpoint**"
        
        if endpoint.has_auth:
            description += f"\n\n🔐 **Requires {endpoint.auth_type.value} authentication**"
        
        return description
    
    def _extract_tags(self, path: str) -> List[str]:
        """Extract tags from path"""
        tags = []
        
        if "admin" in path:
            tags.append("admin")
        if "users" in path:
            tags.append("users")
        if "profiles" in path:
            tags.append("profiles")
        if "auth" in path or "login" in path:
            tags.append("authentication")
        if "health" in path:
            tags.append("health")
        
        return tags or ["api"]
    
    def _infer_parameter_type(self, value: Any) -> str:
        """Infer parameter type from value"""
        if isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int):
            return "integer"
        elif isinstance(value, float):
            return "number"
        else:
            return "string"
    
    def _infer_schema_from_data(self, data: Any) -> Dict[str, Any]:
        """Infer JSON schema from data"""
        if isinstance(data, dict):
            properties = {}
            required = []
            
            for key, value in data.items():
                if value is not None:
                    properties[key] = self._infer_schema_from_data(value)
                    required.append(key)
            
            schema = {"type": "object", "properties": properties}
            if required:
                schema["required"] = required
            return schema
        
        elif isinstance(data, list):
            if data:
                items_schema = self._infer_schema_from_data(data[0])
            else:
                items_schema = {"type": "object"}
            
            return {"type": "array", "items": items_schema}
        
        elif isinstance(data, bool):
            return {"type": "boolean"}
        
        elif isinstance(data, int):
            return {"type": "integer"}
        
        elif isinstance(data, float):
            return {"type": "number"}
        
        else:
            return {"type": "string"}
    
    def _generate_schema_name(self, path: str, suffix: str) -> str:
        """Generate schema name from path"""
        # Convert path to PascalCase
        path_parts = path.strip('/').split('/')
        schema_name = ''.join(part.capitalize() for part in path_parts if part and not part.startswith('{'))
        return f"{schema_name}{suffix}" if schema_name else f"Default{suffix}"
    
    def _get_status_description(self, status_code: int) -> str:
        """Get description for status code"""
        descriptions = {
            200: "OK",
            201: "Created",
            204: "No Content",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error"
        }
        return descriptions.get(status_code, f"Status {status_code}")
    
    def export_yaml(self, output_file: str = "openapi.yaml") -> str:
        """Export OpenAPI spec to YAML"""
        spec = self.generate_openapi_spec()
        
        # Convert to dict
        spec_dict = spec.dict(exclude_none=True)
        
        # Write to file
        with open(output_file, 'w') as f:
            yaml.dump(spec_dict, f, default_flow_style=False, sort_keys=False)
        
        return f"OpenAPI spec exported to {output_file}"
    
    def export_json(self, output_file: str = "openapi.json") -> str:
        """Export OpenAPI spec to JSON"""
        spec = self.generate_openapi_spec()
        
        # Convert to dict
        spec_dict = spec.dict(exclude_none=True)
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump(spec_dict, f, indent=2)
        
        return f"OpenAPI spec exported to {output_file}"
    
    def export_postman(self, output_file: str = "postman_collection.json") -> str:
        """Export to Postman collection format"""
        endpoints = self.load_discovered_endpoints()
        
        collection = {
            "info": {
                "name": "Discovered API Collection",
                "description": "Auto-generated Postman collection from discovered API traffic",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": []
        }
        
        # Group by tags
        tag_groups = {}
        for endpoint in endpoints:
            tags = self._extract_tags(endpoint.path)
            tag = tags[0] if tags else "api"
            
            if tag not in tag_groups:
                tag_groups[tag] = []
            tag_groups[tag].append(endpoint)
        
        # Create collection items
        for tag, tag_endpoints in tag_groups.items():
            folder = {
                "name": tag.capitalize(),
                "item": []
            }
            
            for endpoint in tag_endpoints:
                request = {
                    "name": self._generate_summary(endpoint),
                    "request": {
                        "method": endpoint.method.value,
                        "header": [],
                        "url": {
                            "raw": f"http://localhost:8000{endpoint.path}",
                            "protocol": "http",
                            "host": ["localhost"],
                            "port": "8000",
                            "path": endpoint.path.strip('/').split('/') if endpoint.path.strip('/') else []
                        }
                    }
                }
                
                # Add headers
                if endpoint.headers:
                    for key, value in endpoint.headers.items():
                        if key.lower() not in ['host', 'content-length']:
                            request["request"]["header"].append({
                                "key": key,
                                "value": value
                            })
                
                # Add query parameters
                if endpoint.query_params:
                    request["request"]["url"]["query"] = []
                    for key, value in endpoint.query_params.items():
                        request["request"]["url"]["query"].append({
                            "key": key,
                            "value": str(value)
                        })
                
                # Add body
                if endpoint.body and endpoint.method not in [HTTPMethod.GET, HTTPMethod.DELETE]:
                    request["request"]["body"] = {
                        "mode": "raw",
                        "raw": json.dumps(endpoint.body, indent=2),
                        "options": {
                            "raw": {
                                "language": "json"
                            }
                        }
                    }
                
                folder["item"].append(request)
            
            collection["item"].append(folder)
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump(collection, f, indent=2)
        
        return f"Postman collection exported to {output_file}"