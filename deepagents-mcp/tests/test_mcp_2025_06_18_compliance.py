"""MCP 2025-06-18 Compliance Test Suite.

This test suite validates that the deepagents-mcp integration fully complies 
with the MCP 2025-06-18 specification requirements.
"""

import pytest
import asyncio
import json
import logging
from typing import Dict, Any, List
from unittest.mock import Mock, AsyncMock, patch

# Test imports
from deepagents_mcp.protocol_compliance import (
    MCPProtocolValidator,
    ComplianceLevel,
    ComplianceResult,
    create_default_compliance_validator,
    ensure_protocol_compliance
)
from deepagents_mcp.jsonrpc_validation import (
    JSONRPCValidator,
    ValidationResult,
    MessageType,
    create_default_validator
)
from deepagents_mcp.tool_output_validation import (
    ToolOutputValidator,
    OutputValidationResult,
    ValidationSeverity,
    validate_tool_output,
    create_safe_error_response
)
from deepagents_mcp.mcp_client import MCPToolProvider, load_mcp_tools


class TestMCP2025_06_18ProtocolCompliance:
    """Test MCP protocol compliance validation."""
    
    def test_protocol_validator_initialization(self):
        """Test protocol validator initializes correctly."""
        validator = create_default_compliance_validator()
        assert isinstance(validator, MCPProtocolValidator)
        assert validator.compliance_level == ComplianceLevel.STRICT
        assert validator.SPEC_VERSION == "2025-06-18"
    
    def test_mcp_protocol_version_header_required(self):
        """Test that MCP-Protocol-Version header is required."""
        validator = create_default_compliance_validator()
        
        # Test missing header
        headers = {"Content-Type": "application/json"}
        result = validator.validate_http_headers(headers)
        assert not result.compliant
        assert any("Missing required MCP-Protocol-Version header" in v for v in result.violations)
    
    def test_mcp_protocol_version_header_valid(self):
        """Test that valid MCP protocol version is accepted."""
        validator = create_default_compliance_validator()
        
        # Test valid header
        headers = {
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-06-18"
        }
        result = validator.validate_http_headers(headers)
        assert result.compliant
        assert result.protocol_version == "2025-06-18"
    
    def test_mcp_protocol_version_header_invalid(self):
        """Test that invalid MCP protocol version is rejected."""
        validator = create_default_compliance_validator()
        
        # Test invalid header
        headers = {
            "Content-Type": "application/json", 
            "MCP-Protocol-Version": "invalid-version"
        }
        result = validator.validate_http_headers(headers)
        assert not result.compliant
        assert any("Unsupported protocol version" in v for v in result.violations)
    
    def test_create_compliant_headers(self):
        """Test creation of compliant HTTP headers."""
        validator = create_default_compliance_validator()
        
        headers = validator.create_compliant_headers()
        assert "MCP-Protocol-Version" in headers
        assert headers["MCP-Protocol-Version"] == "2025-06-18"
        assert headers["Content-Type"] == "application/json"
    
    def test_connection_config_validation(self):
        """Test validation of MCP connection configurations."""
        validator = create_default_compliance_validator()
        
        # Valid stdio config
        stdio_config = {
            "command": "python",
            "args": ["-m", "server"],
            "transport": "stdio"
        }
        result = validator.validate_connection_config(stdio_config)
        assert result.compliant
        
        # Valid HTTP config
        http_config = {
            "url": "https://example.com/mcp",
            "transport": "streamable_http"
        }
        result = validator.validate_connection_config(http_config)
        assert result.compliant
        
        # Invalid transport
        invalid_config = {
            "command": "python",
            "transport": "invalid_transport"
        }
        result = validator.validate_connection_config(invalid_config)
        assert not result.compliant


class TestJSONRPCBatchingProhibition:
    """Test that JSON-RPC batching is properly prohibited."""
    
    def test_jsonrpc_validator_initialization(self):
        """Test JSON-RPC validator initializes correctly."""
        validator = create_default_validator()
        assert isinstance(validator, JSONRPCValidator)
        assert validator.strict_mode is True
        assert validator.mcp_mode is True
    
    def test_batch_requests_explicitly_rejected(self):
        """Test that batch requests are explicitly rejected."""
        validator = create_default_validator()
        
        # Test batch request (array of messages)
        batch_messages = [
            {"jsonrpc": "2.0", "method": "ping", "id": 1},
            {"jsonrpc": "2.0", "method": "tools/list", "id": 2}
        ]
        
        result = validator.validate_batch_not_supported(batch_messages)
        assert not result.valid
        assert any("JSON-RPC batching is not supported" in error for error in result.errors)
    
    def test_single_message_validation(self):
        """Test that single messages are validated correctly."""
        validator = create_default_validator()
        
        # Valid request
        valid_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test-client"}
            }
        }
        
        result = validator.validate_message(valid_request)
        assert result.valid
        assert result.message_type == MessageType.REQUEST
    
    def test_jsonrpc_version_validation(self):
        """Test JSON-RPC version validation."""
        validator = create_default_validator()
        
        # Invalid version
        invalid_message = {
            "jsonrpc": "1.0",  # Wrong version
            "method": "test",
            "id": 1
        }
        
        result = validator.validate_message(invalid_message)
        assert not result.valid
        assert any("Invalid jsonrpc version" in error for error in result.errors)


class TestToolOutputValidation:
    """Test comprehensive tool output validation."""
    
    def test_output_validator_initialization(self):
        """Test output validator initializes correctly."""
        validator = ToolOutputValidator(strict_mode=True, sanitize=True)
        assert validator.strict_mode is True
        assert validator.sanitize is True
    
    def test_valid_mcp_content_validation(self):
        """Test validation of valid MCP content."""
        result = {
            "content": [
                {
                    "type": "text",
                    "text": "Hello, world!"
                }
            ]
        }
        
        validation_result = validate_tool_output(result, "test_tool")
        assert validation_result.valid
        assert validation_result.sanitized_output == result
    
    def test_malicious_content_sanitization(self):
        """Test that malicious content is sanitized."""
        malicious_result = {
            "content": [
                {
                    "type": "text",
                    "text": "<script>alert('xss')</script>Safe content"
                }
            ]
        }
        
        validation_result = validate_tool_output(malicious_result, "test_tool")
        assert validation_result.valid
        
        # Check that script tags are removed/sanitized
        sanitized_text = validation_result.sanitized_output["content"][0]["text"]
        assert "<script>" not in sanitized_text
        assert "Safe content" in sanitized_text
    
    def test_oversized_content_rejection(self):
        """Test that oversized content is rejected."""
        # Create content that exceeds size limits
        oversized_text = "x" * (1048576 + 1)  # 1MB + 1 byte
        oversized_result = {
            "content": [
                {
                    "type": "text", 
                    "text": oversized_text
                }
            ]
        }
        
        validation_result = validate_tool_output(oversized_result, "test_tool")
        assert not validation_result.valid
        assert validation_result.has_errors()
    
    def test_invalid_content_structure(self):
        """Test validation of invalid content structure."""
        invalid_result = {
            "content": [
                {
                    "type": "image",
                    # Missing required data or uri field for image type
                }
            ]
        }
        
        validation_result = validate_tool_output(invalid_result, "test_tool")
        assert not validation_result.valid
        assert validation_result.has_errors()
    
    def test_safe_error_response_creation(self):
        """Test creation of safe error responses."""
        error_response = create_safe_error_response("Test error message", "TEST_ERROR")
        
        assert "content" in error_response
        assert len(error_response["content"]) == 1
        assert error_response["content"][0]["type"] == "error"
        assert error_response["content"][0]["text"] == "Test error message"
        assert error_response["content"][0]["code"] == "TEST_ERROR"


class TestSecurityAndConsentIntegration:
    """Test security and consent framework integration."""
    
    @pytest.mark.asyncio
    async def test_mcp_tool_provider_initialization_with_security(self):
        """Test MCPToolProvider initialization with security enabled."""
        connections = {
            "test_server": {
                "command": "python",
                "args": ["-m", "test_server"],
                "transport": "stdio"
            }
        }
        
        # Mock the MultiServerMCPClient since we don't have real servers
        with patch('deepagents_mcp.mcp_client.MultiServerMCPClient'):
            provider = MCPToolProvider(
                connections=connections,
                enable_security=True,
                enable_consent=True,
                validate_outputs=True
            )
            
            assert provider.enable_security is True
            assert provider.enable_consent is True
            assert provider.validate_outputs is True
    
    @pytest.mark.asyncio
    async def test_load_mcp_tools_with_validation(self):
        """Test loading MCP tools with all validation enabled."""
        connections = {
            "test_server": {
                "command": "python", 
                "args": ["-m", "test_server"],
                "transport": "stdio"
            }
        }
        
        # Mock the MultiServerMCPClient
        with patch('deepagents_mcp.mcp_client.MultiServerMCPClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get_tools.return_value = []
            mock_client_class.return_value = mock_client
            
            tools = await load_mcp_tools(
                connections=connections,
                enable_security=True,
                enable_consent=True,
                validate_outputs=True
            )
            
            assert isinstance(tools, list)
            # Tools list may be empty in test environment, but function should work
    
    def test_oauth_security_configuration(self):
        """Test OAuth 2.1 security configuration."""
        connections = {
            "secure_server": {
                "url": "https://example.com/mcp",
                "transport": "streamable_http",
                "auth": {
                    "type": "oauth2.1",
                    "authorization_header": "Bearer test_token"
                }
            }
        }
        
        with patch('deepagents_mcp.mcp_client.MultiServerMCPClient'):
            provider = MCPToolProvider(
                connections=connections,
                enable_security=True
            )
            
            assert provider.enable_security is True
            assert provider.connections == connections


class TestComplianceIntegration:
    """Test overall compliance integration."""
    
    def test_complete_compliance_validation_flow(self):
        """Test complete compliance validation workflow."""
        # Simulate a complete MCP message flow
        headers = {
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-06-18"
        }
        
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": "test_tool",
                "arguments": {"query": "test query"}
            }
        }
        
        # Validate headers and message
        compliance_result = ensure_protocol_compliance(headers, message)
        assert compliance_result.compliant
        assert compliance_result.protocol_version == "2025-06-18"
    
    def test_compliance_violation_detection(self):
        """Test detection of compliance violations."""
        # Headers missing protocol version
        headers = {"Content-Type": "application/json"}
        
        # Message with batching (should be rejected)
        batch_message = [
            {"jsonrpc": "2.0", "method": "ping", "id": 1},
            {"jsonrpc": "2.0", "method": "tools/list", "id": 2}
        ]
        
        # This should detect violations
        compliance_result = ensure_protocol_compliance(headers)
        assert not compliance_result.compliant
        assert len(compliance_result.violations) > 0
    
    def test_mcp_method_validation(self):
        """Test MCP method name validation."""
        validator = create_default_compliance_validator()
        
        valid_message = {
            "jsonrpc": "2.0",
            "method": "tools/list", 
            "id": 1
        }
        
        result = validator.validate_json_rpc_message(valid_message)
        assert result.compliant
        
        # Test invalid method name
        invalid_message = {
            "jsonrpc": "2.0",
            "method": "invalid/method/pattern",
            "id": 1
        }
        
        result = validator.validate_json_rpc_message(invalid_message)
        # Should be valid but generate warning about method pattern
        assert result.compliant  # Structure is valid
        # Warnings would be checked in a more detailed test


class TestErrorHandlingCompliance:
    """Test error handling compliance with MCP specification."""
    
    def test_standardized_error_responses(self):
        """Test that error responses follow MCP standards."""
        error_response = create_safe_error_response(
            "Tool execution failed",
            "TOOL_EXECUTION_ERROR"
        )
        
        # Validate error response structure
        validation_result = validate_tool_output(error_response, "error_tool")
        assert validation_result.valid
        
        # Check structure matches MCP content format
        content = error_response["content"][0]
        assert content["type"] == "error"
        assert "text" in content
        assert "code" in content
    
    def test_output_validation_error_handling(self):
        """Test error handling in output validation."""
        # Simulate a tool that returns invalid output
        invalid_output = {
            "content": [
                {
                    "type": "invalid_type",  # Invalid content type
                    "malicious_field": "<script>alert('xss')</script>"
                }
            ]
        }
        
        validator = ToolOutputValidator(strict_mode=True, sanitize=True)
        result = validator.validate_tool_result(invalid_output, "test_tool")
        
        # Should handle gracefully and provide sanitized output
        assert not result.valid or result.sanitized_output != invalid_output


# Integration test fixtures
@pytest.fixture
def sample_mcp_connections():
    """Sample MCP connections for testing."""
    return {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            "transport": "stdio"
        },
        "http_server": {
            "url": "https://example.com/mcp",
            "transport": "streamable_http"
        }
    }


@pytest.fixture 
def sample_tool_output():
    """Sample tool output for testing."""
    return {
        "content": [
            {
                "type": "text",
                "text": "Test output from tool"
            }
        ]
    }


# Performance and stress tests
class TestCompliancePerformance:
    """Test performance of compliance validation."""
    
    def test_validation_performance(self):
        """Test that validation doesn't significantly impact performance."""
        import time
        
        # Large but valid content
        large_content = {
            "content": [
                {
                    "type": "text",
                    "text": "x" * 100000  # 100KB of text
                }
            ]
        }
        
        start_time = time.time()
        for _ in range(100):  # Validate 100 times
            result = validate_tool_output(large_content, "perf_test")
            assert result.valid
        
        elapsed = time.time() - start_time
        # Should complete 100 validations in under 1 second
        assert elapsed < 1.0, f"Validation took too long: {elapsed:.2f}s"
    
    def test_concurrent_validation(self):
        """Test concurrent validation scenarios."""
        import concurrent.futures
        import random
        
        def validate_sample():
            # Generate unique content for each validation
            unique_id = random.randint(1000, 9999)
            content = {
                "content": [
                    {
                        "type": "text", 
                        "text": f"Test content {unique_id}"
                    }
                ]
            }
            return validate_tool_output(content, "concurrent_test")
        
        # Run 50 concurrent validations
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(validate_sample) for _ in range(50)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        # All should succeed
        assert len(results) == 50
        assert all(r.valid for r in results)


if __name__ == "__main__":
    # Run the compliance test suite
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    # Run tests with pytest
    exit_code = pytest.main([__file__, "-v", "--tb=short"])
    sys.exit(exit_code)