"""Basic import and initialization tests for MCP compliance modules."""

import pytest
import sys
import importlib.util


def test_protocol_compliance_import():
    """Test that protocol compliance module imports correctly."""
    try:
        from deepagents_mcp.protocol_compliance import (
            MCPProtocolValidator,
            create_default_compliance_validator,
            ComplianceLevel
        )
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import protocol compliance: {e}")


def test_jsonrpc_validation_import():
    """Test that JSON-RPC validation module imports correctly."""
    try:
        from deepagents_mcp.jsonrpc_validation import (
            JSONRPCValidator,
            create_default_validator,
            MessageType
        )
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import JSON-RPC validation: {e}")


def test_tool_output_validation_import():
    """Test that tool output validation module imports correctly."""
    try:
        from deepagents_mcp.tool_output_validation import (
            ToolOutputValidator,
            validate_tool_output,
            create_safe_error_response
        )
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import tool output validation: {e}")


def test_mcp_client_compliance_imports():
    """Test that MCP client imports compliance modules correctly."""
    try:
        from deepagents_mcp.mcp_client import MCPToolProvider
        # This should work even if some optional dependencies are missing
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import MCP client: {e}")


def test_basic_compliance_validator_creation():
    """Test basic compliance validator creation."""
    from deepagents_mcp.protocol_compliance import create_default_compliance_validator
    
    validator = create_default_compliance_validator()
    assert validator is not None
    assert hasattr(validator, 'compliance_level')
    assert hasattr(validator, 'validate_http_headers')


def test_basic_jsonrpc_validator_creation():
    """Test basic JSON-RPC validator creation."""
    from deepagents_mcp.jsonrpc_validation import create_default_validator
    
    validator = create_default_validator()
    assert validator is not None
    assert hasattr(validator, 'validate_message')
    assert hasattr(validator, 'validate_batch_not_supported')


def test_basic_output_validator_creation():
    """Test basic output validator creation."""
    from deepagents_mcp.tool_output_validation import ToolOutputValidator
    
    validator = ToolOutputValidator()
    assert validator is not None
    assert hasattr(validator, 'validate_tool_result')


def test_compliance_constants():
    """Test that compliance constants are defined correctly."""
    from deepagents_mcp.protocol_compliance import MCPProtocolValidator
    
    assert MCPProtocolValidator.SPEC_VERSION == "2025-06-18"
    assert "2025-06-18" in MCPProtocolValidator.SUPPORTED_VERSIONS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])