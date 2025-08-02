"""MCP 2025-06-18 Protocol Compliance Utilities.

This module provides utilities to ensure compliance with the MCP 2025-06-18 
specification requirements, including protocol version enforcement.
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ComplianceLevel(Enum):
    """MCP protocol compliance levels."""
    BASIC = "basic"          # Basic MCP compliance  
    STRICT = "strict"        # Strict 2025-06-18 compliance
    PARANOID = "paranoid"    # Maximum compliance validation


@dataclass
class ComplianceResult:
    """Result of MCP protocol compliance check."""
    compliant: bool
    violations: List[str]
    warnings: List[str]
    protocol_version: Optional[str] = None
    
    def __post_init__(self):
        if self.violations is None:
            self.violations = []
        if self.warnings is None:
            self.warnings = []


class MCPProtocolValidator:
    """Validator for MCP 2025-06-18 protocol compliance."""
    
    SPEC_VERSION = "2025-06-18"
    SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26"]
    
    def __init__(self, compliance_level: ComplianceLevel = ComplianceLevel.STRICT):
        """Initialize protocol validator.
        
        Args:
            compliance_level: Level of compliance validation to enforce
        """
        self.compliance_level = compliance_level
        logger.info(f"MCP protocol validator initialized (level: {compliance_level.value})")
    
    def validate_http_headers(self, headers: Dict[str, str]) -> ComplianceResult:
        """Validate HTTP headers for MCP compliance.
        
        Args:
            headers: HTTP headers to validate
            
        Returns:
            Compliance validation result
        """
        result = ComplianceResult(compliant=True, violations=[], warnings=[])
        
        # Check for required MCP-Protocol-Version header
        protocol_version = headers.get('MCP-Protocol-Version')
        if not protocol_version:
            result.compliant = False
            result.violations.append("Missing required MCP-Protocol-Version header")
            logger.error("HTTP request missing MCP-Protocol-Version header")
        else:
            result.protocol_version = protocol_version
            
            # Validate protocol version
            if protocol_version not in self.SUPPORTED_VERSIONS:
                result.compliant = False
                result.violations.append(f"Unsupported protocol version: {protocol_version}")
                logger.error(f"Unsupported MCP protocol version: {protocol_version}")
            elif protocol_version != self.SPEC_VERSION:
                result.warnings.append(f"Using older protocol version: {protocol_version}")
                logger.warning(f"Using older MCP protocol version: {protocol_version}")
        
        # Strict compliance checks
        if self.compliance_level in [ComplianceLevel.STRICT, ComplianceLevel.PARANOID]:
            # Check for proper content type
            content_type = headers.get('Content-Type', '').lower()
            if 'application/json' not in content_type:
                result.warnings.append("Content-Type should be application/json for MCP messages")
            
            # Check for HTTPS requirement in paranoid mode
            if self.compliance_level == ComplianceLevel.PARANOID:
                # Note: We can't check the scheme from headers alone, 
                # this would need to be done at the transport level
                if 'x-forwarded-proto' in headers and headers['x-forwarded-proto'] != 'https':
                    result.violations.append("HTTPS required for maximum security compliance")
        
        return result
    
    def validate_json_rpc_message(self, message: Dict[str, Any]) -> ComplianceResult:
        """Validate JSON-RPC message for MCP compliance.
        
        Args:
            message: JSON-RPC message to validate
            
        Returns:
            Compliance validation result
        """
        result = ComplianceResult(compliant=True, violations=[], warnings=[])
        
        # Basic JSON-RPC 2.0 validation
        if not isinstance(message, dict):
            result.compliant = False
            result.violations.append("Message must be a JSON object")
            return result
        
        # Check jsonrpc field
        if message.get('jsonrpc') != '2.0':
            result.compliant = False
            result.violations.append("Invalid or missing jsonrpc field (must be '2.0')")
        
        # Check for batching (not supported in MCP 2025-06-18)
        if isinstance(message, list):
            result.compliant = False
            result.violations.append("JSON-RPC batching is not supported in MCP 2025-06-18")
        
        # Method validation for requests/notifications
        if 'method' in message:
            method = message['method']
            if not isinstance(method, str) or not method:
                result.compliant = False
                result.violations.append("Method must be a non-empty string")
            else:
                # Validate MCP method patterns
                if not self._validate_mcp_method(method):
                    result.warnings.append(f"Method '{method}' does not follow MCP naming patterns")
        
        # ID validation
        if 'id' in message:
            id_value = message['id']
            # MCP requires non-null IDs for requests and responses
            if id_value is None:
                result.compliant = False
                result.violations.append("MCP requires non-null IDs for requests and responses")
        
        return result
    
    def _validate_mcp_method(self, method: str) -> bool:
        """Validate that method follows MCP naming patterns.
        
        Args:
            method: Method name to validate
            
        Returns:
            True if method follows MCP patterns
        """
        # Known MCP method patterns
        mcp_patterns = [
            'initialize', 'initialized', 'ping', 'progress', 'cancelled',
            'tools/', 'resources/', 'prompts/', 'completion/', 'roots/',
            'sampling/', 'elicitation/', 'notifications/'
        ]
        
        return any(method.startswith(pattern) or method == pattern.rstrip('/') 
                  for pattern in mcp_patterns)
    
    def create_compliant_headers(self, base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Create HTTP headers that are MCP 2025-06-18 compliant.
        
        Args:
            base_headers: Optional base headers to extend
            
        Returns:
            Compliant HTTP headers
        """
        headers = base_headers.copy() if base_headers else {}
        
        # Ensure MCP-Protocol-Version header
        if 'MCP-Protocol-Version' not in headers:
            headers['MCP-Protocol-Version'] = self.SPEC_VERSION
        
        # Ensure proper content type
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        
        logger.debug(f"Created MCP-compliant headers: {headers}")
        return headers
    
    def validate_connection_config(self, config: Dict[str, Any]) -> ComplianceResult:
        """Validate MCP connection configuration for compliance.
        
        Args:
            config: MCP connection configuration
            
        Returns:
            Compliance validation result
        """
        result = ComplianceResult(compliant=True, violations=[], warnings=[])
        
        transport = config.get('transport', '')
        
        # Validate transport type
        if transport not in ['stdio', 'streamable_http']:
            result.violations.append(f"Invalid transport type: {transport}")
            result.compliant = False
        
        # HTTP transport specific validation
        if transport == 'streamable_http':
            if 'url' not in config:
                result.violations.append("HTTP transport requires 'url' field")
                result.compliant = False
            else:
                url = config['url']
                # Check for HTTPS in strict/paranoid mode
                if self.compliance_level in [ComplianceLevel.STRICT, ComplianceLevel.PARANOID]:
                    if not url.startswith('https://'):
                        if self.compliance_level == ComplianceLevel.PARANOID:
                            result.violations.append("HTTPS required for HTTP transport in paranoid mode")
                            result.compliant = False
                        else:
                            result.warnings.append("HTTPS recommended for HTTP transport")
        
        # Validate authentication configuration
        if 'auth' in config:
            auth_config = config['auth']
            if not isinstance(auth_config, dict):
                result.violations.append("Auth configuration must be an object")
                result.compliant = False
            elif 'type' not in auth_config:
                result.warnings.append("Auth type not specified")
        
        return result


def create_default_compliance_validator() -> MCPProtocolValidator:
    """Create default MCP protocol validator.
    
    Returns:
        Configured validator instance
    """
    return MCPProtocolValidator(ComplianceLevel.STRICT)


def create_permissive_compliance_validator() -> MCPProtocolValidator:
    """Create permissive MCP protocol validator for development.
    
    Returns:
        Configured validator instance
    """
    return MCPProtocolValidator(ComplianceLevel.BASIC)


def validate_mcp_connection(config: Dict[str, Any]) -> ComplianceResult:
    """Convenience function to validate MCP connection configuration.
    
    Args:
        config: MCP connection configuration
        
    Returns:
        Compliance validation result
    """
    validator = create_default_compliance_validator()
    return validator.validate_connection_config(config)


def ensure_protocol_compliance(headers: Dict[str, str], 
                             message: Optional[Dict[str, Any]] = None) -> ComplianceResult:
    """Ensure HTTP headers and message are MCP protocol compliant.
    
    Args:
        headers: HTTP headers to validate
        message: Optional JSON-RPC message to validate
        
    Returns:
        Overall compliance validation result
    """
    validator = create_default_compliance_validator()
    
    # Validate headers
    header_result = validator.validate_http_headers(headers)
    
    # Validate message if provided
    if message:
        message_result = validator.validate_json_rpc_message(message)
        
        # Combine results
        combined_result = ComplianceResult(
            compliant=header_result.compliant and message_result.compliant,
            violations=header_result.violations + message_result.violations,
            warnings=header_result.warnings + message_result.warnings,
            protocol_version=header_result.protocol_version
        )
    else:
        combined_result = header_result
    
    if not combined_result.compliant:
        logger.error(f"MCP protocol compliance violations: {combined_result.violations}")
    elif combined_result.warnings:
        logger.warning(f"MCP protocol compliance warnings: {combined_result.warnings}")
    else:
        logger.debug("MCP protocol compliance validated successfully")
    
    return combined_result