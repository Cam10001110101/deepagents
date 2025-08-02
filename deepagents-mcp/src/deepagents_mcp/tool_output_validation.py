"""Tool Output Schema Validation for MCP 2025-06-18 Compliance.

This module provides comprehensive validation for tool outputs to ensure they
conform to expected schemas and don't contain malicious or malformed data.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Union, Type, get_type_hints
from dataclasses import dataclass, field
from enum import Enum
import html

logger = logging.getLogger(__name__)


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""
    INFO = "info"
    WARNING = "warning" 
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationIssue:
    """Represents a validation issue found in tool output."""
    severity: ValidationSeverity
    message: str
    field_path: str = ""
    suggested_fix: Optional[str] = None


@dataclass
class OutputValidationResult:
    """Result of tool output validation."""
    valid: bool
    sanitized_output: Any = None
    issues: List[ValidationIssue] = field(default_factory=list)
    schema_version: str = "2025-06-18"
    
    def has_errors(self) -> bool:
        """Check if result has any errors or critical issues."""
        return any(issue.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL] 
                  for issue in self.issues)
    
    def has_warnings(self) -> bool:
        """Check if result has any warnings."""
        return any(issue.severity == ValidationSeverity.WARNING for issue in self.issues)


class MCPContentType(Enum):
    """MCP content types for tool outputs."""
    TEXT = "text"
    IMAGE = "image"
    RESOURCE = "resource"
    ERROR = "error"


@dataclass
class MCPContent:
    """MCP content structure for tool outputs."""
    type: str
    text: Optional[str] = None
    data: Optional[str] = None  # Base64 encoded for binary data
    mimeType: Optional[str] = None
    uri: Optional[str] = None
    code: Optional[str] = None  # Error code for error type content
    
    def validate(self) -> List[ValidationIssue]:
        """Validate MCP content structure."""
        issues = []
        
        # Validate required type field
        if not self.type:
            issues.append(ValidationIssue(
                ValidationSeverity.ERROR,
                "Content type is required",
                "type"
            ))
        elif self.type not in [ct.value for ct in MCPContentType]:
            issues.append(ValidationIssue(
                ValidationSeverity.WARNING,
                f"Unknown content type: {self.type}",
                "type",
                f"Use one of: {', '.join([ct.value for ct in MCPContentType])}"
            ))
        
        # Type-specific validation
        if self.type == MCPContentType.TEXT.value:
            if not self.text:
                issues.append(ValidationIssue(
                    ValidationSeverity.ERROR,
                    "Text content requires 'text' field",
                    "text"
                ))
        elif self.type == MCPContentType.IMAGE.value:
            if not self.data and not self.uri:
                issues.append(ValidationIssue(
                    ValidationSeverity.ERROR,
                    "Image content requires either 'data' or 'uri' field",
                    "data/uri"
                ))
            if not self.mimeType:
                issues.append(ValidationIssue(
                    ValidationSeverity.WARNING,
                    "Image content should include mimeType",
                    "mimeType",
                    "Add mimeType field (e.g., 'image/png')"
                ))
            elif self.mimeType and not re.match(r'^[a-zA-Z][a-zA-Z0-9]*/[a-zA-Z0-9][a-zA-Z0-9\-\.]*$', self.mimeType):
                issues.append(ValidationIssue(
                    ValidationSeverity.ERROR,
                    f"Invalid MIME type format: {self.mimeType}",
                    "mimeType",
                    "Use valid MIME type format (e.g., 'image/png')"
                ))
        elif self.type == MCPContentType.RESOURCE.value:
            if not self.uri:
                issues.append(ValidationIssue(
                    ValidationSeverity.ERROR,
                    "Resource content requires 'uri' field",
                    "uri"
                ))
        elif self.type == MCPContentType.ERROR.value:
            if not self.text:
                issues.append(ValidationIssue(
                    ValidationSeverity.ERROR,
                    "Error content requires 'text' field",
                    "text"
                ))
            if not self.code:
                issues.append(ValidationIssue(
                    ValidationSeverity.WARNING,
                    "Error content should include 'code' field",
                    "code",
                    "Add error code field for better error handling"
                ))
        
        return issues


class ToolOutputValidator:
    """Comprehensive validator for MCP tool outputs."""
    
    def __init__(self, strict_mode: bool = True, sanitize: bool = True):
        """Initialize tool output validator.
        
        Args:
            strict_mode: Whether to enforce strict MCP 2025-06-18 compliance
            sanitize: Whether to sanitize outputs automatically
        """
        self.strict_mode = strict_mode
        self.sanitize = sanitize
        
        # Define dangerous patterns for output sanitization
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',  # JavaScript
            r'javascript:',               # JavaScript URLs
            r'data:text/html',           # HTML data URLs
            r'onclick\s*=',              # Event handlers
            r'onload\s*=',               # Event handlers
            r'onerror\s*=',              # Event handlers
        ]
        
        # Define maximum sizes for different content types
        self.max_sizes = {
            "text": 1048576,      # 1MB for text content
            "image": 10485760,   # 10MB for images
            "resource": 104857600,  # 100MB for resources
            "default": 1048576   # 1MB default
        }
        
        logger.info(f"Tool output validator initialized (strict={strict_mode}, sanitize={sanitize})")
    
    def validate_tool_result(self, result: Any, tool_name: str = "unknown") -> OutputValidationResult:
        """Validate complete tool result structure.
        
        Args:
            result: Tool result to validate
            tool_name: Name of the tool that produced this result
            
        Returns:
            Validation result with sanitized output
        """
        validation_result = OutputValidationResult(valid=True, sanitized_output=result)
        
        try:
            # Handle different result types
            if isinstance(result, dict):
                validation_result = self._validate_dict_result(result, tool_name)
            elif isinstance(result, str):
                validation_result = self._validate_string_result(result, tool_name)
            elif isinstance(result, list):
                validation_result = self._validate_list_result(result, tool_name)
            else:
                # Convert other types to string
                validation_result.sanitized_output = str(result)
                validation_result.issues.append(ValidationIssue(
                    ValidationSeverity.WARNING,
                    f"Converted {type(result).__name__} to string",
                    "root"
                ))
            
            # Final validation
            validation_result.valid = not validation_result.has_errors()
            
            if validation_result.valid:
                logger.debug(f"Tool output validation passed for {tool_name}")
            else:
                logger.warning(f"Tool output validation failed for {tool_name}: {[i.message for i in validation_result.issues if i.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL]]}")
            
        except Exception as e:
            logger.error(f"Tool output validation error: {e}")
            validation_result.valid = False
            validation_result.issues.append(ValidationIssue(
                ValidationSeverity.CRITICAL,
                f"Validation error: {e}",
                "root"
            ))
        
        return validation_result
    
    def _validate_dict_result(self, result: Dict[str, Any], tool_name: str) -> OutputValidationResult:
        """Validate dictionary-based tool result."""
        validation_result = OutputValidationResult(valid=True, sanitized_output={})
        
        # Check for MCP-style content structure
        if "content" in result:
            content_validation = self._validate_mcp_content(result["content"])
            validation_result.issues.extend(content_validation.issues)
            validation_result.sanitized_output["content"] = content_validation.sanitized_output
        
        # Validate other fields
        for key, value in result.items():
            if key == "content":
                continue  # Already handled above
            
            # Recursively validate nested structures
            if isinstance(value, dict):
                nested_result = self._validate_dict_result(value, f"{tool_name}.{key}")
                validation_result.issues.extend(nested_result.issues)
                validation_result.sanitized_output[key] = nested_result.sanitized_output
            elif isinstance(value, list):
                nested_result = self._validate_list_result(value, f"{tool_name}.{key}")
                validation_result.issues.extend(nested_result.issues)
                validation_result.sanitized_output[key] = nested_result.sanitized_output
            elif isinstance(value, str):
                nested_result = self._validate_string_result(value, f"{tool_name}.{key}")
                validation_result.issues.extend(nested_result.issues)
                validation_result.sanitized_output[key] = nested_result.sanitized_output
            else:
                validation_result.sanitized_output[key] = value
        
        return validation_result
    
    def _validate_mcp_content(self, content: Union[List[Dict], Dict]) -> OutputValidationResult:
        """Validate MCP content structure."""
        validation_result = OutputValidationResult(valid=True)
        
        if isinstance(content, list):
            # Array of content items
            sanitized_content = []
            for i, item in enumerate(content):
                if isinstance(item, dict):
                    mcp_content = MCPContent(**item)
                    content_issues = mcp_content.validate()
                    
                    # Add size validation
                    if "text" in item and isinstance(item["text"], str):
                        text_size = len(item["text"])
                        if text_size > self.max_sizes["text"]:
                            content_issues.append(ValidationIssue(
                                ValidationSeverity.ERROR,
                                f"Text content exceeds maximum size ({self.max_sizes['text']} bytes)",
                                "text",
                                "Truncate or split content"
                            ))
                    
                    # Add field path context
                    for issue in content_issues:
                        issue.field_path = f"content[{i}].{issue.field_path}"
                    
                    validation_result.issues.extend(content_issues)
                    
                    # Sanitize content
                    sanitized_item = self._sanitize_content_item(item)
                    sanitized_content.append(sanitized_item)
                else:
                    validation_result.issues.append(ValidationIssue(
                        ValidationSeverity.ERROR,
                        f"Content item {i} must be an object",
                        f"content[{i}]"
                    ))
            
            validation_result.sanitized_output = sanitized_content
            
        elif isinstance(content, dict):
            # Single content item
            mcp_content = MCPContent(**content)
            content_issues = mcp_content.validate()
            
            # Add size validation
            if "text" in content and isinstance(content["text"], str):
                text_size = len(content["text"])
                if text_size > self.max_sizes["text"]:
                    content_issues.append(ValidationIssue(
                        ValidationSeverity.ERROR,
                        f"Text content exceeds maximum size ({self.max_sizes['text']} bytes)",
                        "text",
                        "Truncate or split content"
                    ))
            
            # Add field path context
            for issue in content_issues:
                issue.field_path = f"content.{issue.field_path}"
            
            validation_result.issues.extend(content_issues)
            validation_result.sanitized_output = self._sanitize_content_item(content)
            
        else:
            validation_result.issues.append(ValidationIssue(
                ValidationSeverity.ERROR,
                "Content must be an object or array of objects",
                "content"
            ))
        
        return validation_result
    
    def _sanitize_content_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize individual content item."""
        sanitized = item.copy()
        
        # Sanitize text content
        if "text" in sanitized and isinstance(sanitized["text"], str):
            sanitized["text"] = self._sanitize_text(sanitized["text"])
        
        # Validate and sanitize URIs
        if "uri" in sanitized and isinstance(sanitized["uri"], str):
            sanitized["uri"] = self._sanitize_uri(sanitized["uri"])
        
        # Validate MIME types
        if "mimeType" in sanitized and isinstance(sanitized["mimeType"], str):
            sanitized["mimeType"] = self._sanitize_mime_type(sanitized["mimeType"])
        
        # Validate base64 data
        if "data" in sanitized and isinstance(sanitized["data"], str):
            sanitized["data"] = self._validate_base64(sanitized["data"])
        
        return sanitized
    
    def _validate_string_result(self, result: str, tool_name: str) -> OutputValidationResult:
        """Validate string-based tool result."""
        validation_result = OutputValidationResult(valid=True)
        
        # Check size limits
        if len(result) > self.max_sizes["text"]:
            validation_result.issues.append(ValidationIssue(
                ValidationSeverity.ERROR,
                f"Text content exceeds maximum size ({self.max_sizes['text']} bytes)",
                "text",
                "Truncate or split content"
            ))
        
        # Sanitize the string
        validation_result.sanitized_output = self._sanitize_text(result)
        
        return validation_result
    
    def _validate_list_result(self, result: List[Any], tool_name: str) -> OutputValidationResult:
        """Validate list-based tool result."""
        validation_result = OutputValidationResult(valid=True, sanitized_output=[])
        
        # Check if this is a list of MCP content items
        is_mcp_content_list = all(
            isinstance(item, dict) and "type" in item 
            for item in result
        )
        
        if is_mcp_content_list:
            # Treat as MCP content array
            mcp_result = self._validate_mcp_content(result)
            validation_result.issues.extend(mcp_result.issues)
            validation_result.sanitized_output = mcp_result.sanitized_output
        else:
            # Treat as generic list
            for i, item in enumerate(result):
                if isinstance(item, dict):
                    item_result = self._validate_dict_result(item, f"{tool_name}[{i}]")
                elif isinstance(item, str):
                    item_result = self._validate_string_result(item, f"{tool_name}[{i}]")
                else:
                    item_result = OutputValidationResult(valid=True, sanitized_output=item)
                
                validation_result.issues.extend(item_result.issues)
                validation_result.sanitized_output.append(item_result.sanitized_output)
        
        return validation_result
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize text content."""
        if not self.sanitize:
            return text
        
        sanitized = text
        
        # Remove dangerous patterns
        for pattern in self.dangerous_patterns:
            sanitized = re.sub(pattern, "[REMOVED_UNSAFE_CONTENT]", sanitized, flags=re.IGNORECASE)
        
        # HTML escape if not already escaped
        if '<' in sanitized and '&lt;' not in sanitized:
            sanitized = html.escape(sanitized)
        
        return sanitized
    
    def _sanitize_uri(self, uri: str) -> str:
        """Sanitize URI content."""
        if not uri:
            return uri
        
        # Only allow safe protocols
        allowed_protocols = ['http', 'https', 'ftp', 'ftps', 'file', 'data']
        
        # Check protocol
        if '://' in uri:
            protocol = uri.split('://')[0].lower()
            if protocol not in allowed_protocols:
                logger.warning(f"Blocked URI with disallowed protocol: {protocol}")
                return "[BLOCKED_URI]"
        
        return uri
    
    def _validate_mime_type(self, mime_type: str) -> Optional[str]:
        """Validate MIME type with strict mode support."""
        if not mime_type:
            return mime_type
        
        # Basic MIME type validation (type/subtype)
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9]*/[a-zA-Z0-9][a-zA-Z0-9\-\.]*$', mime_type):
            logger.warning(f"Invalid MIME type format: {mime_type}")
            if self.strict:
                return None  # Fail validation in strict mode
            return "application/octet-stream"  # Safe default in lenient mode
        
        return mime_type.lower()
    
    def _sanitize_mime_type(self, mime_type: str) -> str:
        """Sanitize MIME type (legacy method)."""
        result = self._validate_mime_type(mime_type)
        return result if result is not None else "application/octet-stream"
    
    def _validate_base64(self, data: str) -> str:
        """Validate base64 encoded data."""
        if not data:
            return data
        
        try:
            import base64
            # Attempt to decode to validate
            decoded = base64.b64decode(data, validate=True)
            
            # Check size limits
            if len(decoded) > self.max_sizes["image"]:
                logger.warning(f"Base64 data exceeds size limit: {len(decoded)} bytes")
                return "[DATA_TOO_LARGE]"
            
            return data
        except Exception as e:
            logger.warning(f"Invalid base64 data: {e}")
            return "[INVALID_BASE64]"
    
    def create_error_result(self, error_message: str, error_code: Optional[str] = None) -> Dict[str, Any]:
        """Create standardized error result for tool failures.
        
        Args:
            error_message: Human-readable error message
            error_code: Optional error code for programmatic handling
            
        Returns:
            Standardized error result structure
        """
        return {
            "content": [
                {
                    "type": "error",
                    "text": self._sanitize_text(error_message),
                    "code": error_code or "TOOL_ERROR"
                }
            ]
        }


class SchemaValidator:
    """JSON Schema validator for tool outputs."""
    
    def __init__(self):
        """Initialize schema validator."""
        # Define common MCP schemas
        self.schemas = {
            "mcp_content": {
                "type": "object",
                "required": ["type"],
                "properties": {
                    "type": {"type": "string", "enum": ["text", "image", "resource", "error"]},
                    "text": {"type": "string", "maxLength": 1048576},
                    "data": {"type": "string", "pattern": "^[A-Za-z0-9+/]*={0,2}$"},  # Base64
                    "mimeType": {"type": "string", "pattern": r"^[a-zA-Z][a-zA-Z0-9]*/[a-zA-Z0-9][a-zA-Z0-9\-\.]*$"},
                    "uri": {"type": "string", "maxLength": 2048}
                },
                "additionalProperties": False
            },
            "mcp_result": {
                "type": "object",
                "properties": {
                    "content": {
                        "oneOf": [
                            {"$ref": "#/definitions/mcp_content"},
                            {"type": "array", "items": {"$ref": "#/definitions/mcp_content"}}
                        ]
                    }
                },
                "definitions": {
                    "mcp_content": {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": {"type": "string", "enum": ["text", "image", "resource", "error"]},
                            "text": {"type": "string", "maxLength": 1048576},
                            "data": {"type": "string", "pattern": "^[A-Za-z0-9+/]*={0,2}$"},
                            "mimeType": {"type": "string", "pattern": r"^[a-zA-Z][a-zA-Z0-9]*/[a-zA-Z0-9][a-zA-Z0-9\-\.]*$"},
                            "uri": {"type": "string", "maxLength": 2048}
                        },
                        "additionalProperties": False
                    }
                }
            }
        }
    
    def validate_against_schema(self, data: Any, schema_name: str) -> OutputValidationResult:
        """Validate data against named schema.
        
        Args:
            data: Data to validate
            schema_name: Name of schema to validate against
            
        Returns:
            Validation result
        """
        try:
            import jsonschema
            
            if schema_name not in self.schemas:
                return OutputValidationResult(
                    valid=False,
                    issues=[ValidationIssue(
                        ValidationSeverity.ERROR,
                        f"Unknown schema: {schema_name}",
                        "schema"
                    )]
                )
            
            schema = self.schemas[schema_name]
            jsonschema.validate(data, schema)
            
            return OutputValidationResult(valid=True, sanitized_output=data)
            
        except ImportError:
            logger.warning("jsonschema not available, skipping schema validation")
            return OutputValidationResult(valid=True, sanitized_output=data)
        except jsonschema.ValidationError as e:
            return OutputValidationResult(
                valid=False,
                issues=[ValidationIssue(
                    ValidationSeverity.ERROR,
                    f"Schema validation failed: {e.message}",
                    str(e.json_path) if hasattr(e, 'json_path') else "unknown"
                )],
                sanitized_output=data
            )


# Pre-configured validators
STRICT_VALIDATOR = ToolOutputValidator(strict_mode=True, sanitize=True)
LENIENT_VALIDATOR = ToolOutputValidator(strict_mode=False, sanitize=True)
SCHEMA_VALIDATOR = SchemaValidator()


def validate_tool_output(output: Any, tool_name: str = "unknown", 
                        strict: bool = True) -> OutputValidationResult:
    """Convenience function to validate tool output.
    
    Args:
        output: Tool output to validate
        tool_name: Name of the tool that produced the output
        strict: Whether to use strict validation
        
    Returns:
        Validation result with sanitized output
    """
    validator = STRICT_VALIDATOR if strict else LENIENT_VALIDATOR
    return validator.validate_tool_result(output, tool_name)


def create_safe_error_response(error_message: str, error_code: str = "TOOL_ERROR") -> Dict[str, Any]:
    """Create a safe error response for tool failures.
    
    Args:
        error_message: Error message to include
        error_code: Error code for the failure
        
    Returns:
        Safe error response structure
    """
    return STRICT_VALIDATOR.create_error_result(error_message, error_code)