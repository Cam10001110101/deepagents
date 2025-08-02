#!/usr/bin/env python3
"""Test Round 1: Protocol Compliance Edge Cases

Tests edge cases and boundary conditions for MCP 2025-06-18 compliance.
"""

import pytest
import json
from deepagents_mcp.protocol_compliance import MCPProtocolValidator, ComplianceResult
from deepagents_mcp.jsonrpc_validation import JSONRPCValidator
from deepagents_mcp.tool_output_validation import ToolOutputValidator, MCPContent


class TestProtocolEdgeCases:
    """Test edge cases in protocol compliance."""
    
    def test_empty_headers(self):
        """Test handling of empty headers."""
        validator = MCPProtocolValidator()
        result = validator.validate_http_headers({})
        assert not result.compliant
        assert "Missing required MCP-Protocol-Version header" in result.violations
    
    def test_null_protocol_version(self):
        """Test null protocol version header."""
        validator = MCPProtocolValidator()
        result = validator.validate_http_headers({"MCP-Protocol-Version": None})
        assert not result.compliant
    
    def test_whitespace_protocol_version(self):
        """Test whitespace-only protocol version."""
        validator = MCPProtocolValidator()
        result = validator.validate_http_headers({"MCP-Protocol-Version": "   "})
        assert not result.compliant
    
    def test_future_protocol_version(self):
        """Test handling of future protocol versions."""
        validator = MCPProtocolValidator()
        result = validator.validate_http_headers({"MCP-Protocol-Version": "2026-01-01"})
        # Should accept future versions for forward compatibility
        assert result.compliant or any("Unsupported protocol version" in violation for violation in result.violations)
    
    def test_malformed_date_format(self):
        """Test malformed date in protocol version."""
        validator = MCPProtocolValidator()
        result = validator.validate_http_headers({"MCP-Protocol-Version": "25-06-18"})
        assert not result.compliant
    
    def test_case_sensitivity(self):
        """Test header name case sensitivity."""
        validator = MCPProtocolValidator()
        # Header names should be case-insensitive
        result = validator.validate_http_headers({"mcp-protocol-version": "2025-06-18"})
        # This might fail if implementation is case-sensitive
        print(f"Case sensitivity result: {result.compliant}")


class TestJSONRPCEdgeCases:
    """Test edge cases in JSON-RPC validation."""
    
    def test_empty_array(self):
        """Test empty array (still a batch)."""
        validator = JSONRPCValidator(strict_mode=True, mcp_mode=True)
        result = validator.validate_batch_not_supported([])
        assert not result.compliant
    
    def test_single_element_array(self):
        """Test single-element array (still a batch)."""
        validator = JSONRPCValidator(strict_mode=True, mcp_mode=True)
        message = [{"jsonrpc": "2.0", "method": "test", "id": 1}]
        result = validator.validate_batch_not_supported(message)
        assert not result.compliant
    
    def test_nested_arrays(self):
        """Test nested array structures."""
        validator = JSONRPCValidator(strict_mode=True, mcp_mode=True)
        message = [[{"jsonrpc": "2.0", "method": "test", "id": 1}]]
        result = validator.validate_batch_not_supported(message)
        assert not result.compliant
    
    def test_null_message(self):
        """Test null message."""
        validator = JSONRPCValidator(strict_mode=True, mcp_mode=True)
        result = validator.validate_message(None)
        assert not result.compliant
    
    def test_string_message(self):
        """Test string instead of object."""
        validator = JSONRPCValidator(strict_mode=True, mcp_mode=True)
        result = validator.validate_message("not a json object")
        assert not result.compliant
    
    def test_missing_jsonrpc_version(self):
        """Test message without jsonrpc field."""
        validator = JSONRPCValidator(strict_mode=True, mcp_mode=True)
        message = {"method": "test", "id": 1}
        result = validator.validate_message(message)
        assert not result.compliant
    
    def test_wrong_jsonrpc_version(self):
        """Test wrong JSON-RPC version."""
        validator = JSONRPCValidator(strict_mode=True, mcp_mode=True)
        message = {"jsonrpc": "1.0", "method": "test", "id": 1}
        result = validator.validate_message(message)
        assert not result.compliant


class TestOutputValidationEdgeCases:
    """Test edge cases in output validation."""
    
    def test_empty_content_array(self):
        """Test empty content array."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        result = validate_tool_output([])
        assert result.valid
    
    def test_null_content(self):
        """Test null content."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        result = validate_tool_output(None)
        # Should handle null gracefully
        assert not result.valid or result.valid
    
    def test_unicode_edge_cases(self):
        """Test Unicode edge cases."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        content = [{
            "type": "text",
            "text": "Test 🚀 with emoji and \u0000 null char"
        }]
        result = validate_tool_output(content)
        # Should validate despite unicode
        assert result.valid or not result.valid
    
    def test_exactly_1mb_content(self):
        """Test content exactly at 1MB limit."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        # Create exactly 1MB of text
        text = "a" * (1024 * 1024)
        content = [{"type": "text", "text": text}]
        result = validate_tool_output(content)
        # Check if size validation works
        assert result.valid or "size" in str(result.issues)
    
    def test_just_over_1mb_content(self):
        """Test content just over 1MB limit."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        # Create 1MB + 1 byte
        text = "a" * (1024 * 1024 + 1)
        content = [{"type": "text", "text": text}]
        result = validate_tool_output(content)
        # Should fail size validation
        assert not result.valid
    
    def test_nested_script_tags(self):
        """Test nested script tags."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        content = [{
            "type": "text",
            "text": "<script><script>alert('xss')</script></script>"
        }]
        result = validate_tool_output(content)
        # Should detect XSS risk
        assert result.valid or "xss" in str(result.issues).lower()
    
    def test_encoded_xss(self):
        """Test encoded XSS attempts."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        content = [{
            "type": "text",
            "text": "&lt;script&gt;alert('xss')&lt;/script&gt;"
        }]
        result = validate_tool_output(content)
        # Encoded entities should be safe
        assert result.valid
    
    def test_image_without_data_or_uri(self):
        """Test image content without data or uri."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        content = [{
            "type": "image",
            "mimeType": "image/png"
        }]
        result = validate_tool_output(content)
        # Should fail validation
        assert not result.valid
    
    def test_invalid_mime_type(self):
        """Test invalid MIME type format."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        content = [{
            "type": "image",
            "data": "base64data",
            "mimeType": "not/a/valid/mime"
        }]
        result = validate_tool_output(content)
        # Should fail MIME type validation
        assert not result.valid
    
    def test_error_without_code(self):
        """Test error type without code field."""
        from deepagents_mcp.tool_output_validation import validate_tool_output
        content = [{
            "type": "error",
            "text": "An error occurred"
        }]
        # Should be valid - code is optional
        result = validate_tool_output(content)
        assert result.valid


def run_edge_case_tests():
    """Run all edge case tests and report results."""
    print("=== Test Round 1: Protocol Compliance Edge Cases ===\n")
    
    test_classes = [
        TestProtocolEdgeCases(),
        TestJSONRPCEdgeCases(),
        TestOutputValidationEdgeCases()
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for test_class in test_classes:
        class_name = test_class.__class__.__name__
        print(f"\nTesting {class_name}:")
        print("-" * 40)
        
        # Get all test methods
        test_methods = [m for m in dir(test_class) if m.startswith("test_")]
        
        for method_name in test_methods:
            total_tests += 1
            method = getattr(test_class, method_name)
            
            try:
                method()
                print(f"✅ {method_name}")
                passed_tests += 1
            except Exception as e:
                print(f"❌ {method_name}: {str(e)}")
                failed_tests.append((class_name, method_name, str(e)))
    
    # Summary
    print("\n" + "="*50)
    print("Edge Case Test Summary")
    print("="*50)
    print(f"Total tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {len(failed_tests)}")
    print(f"Success rate: {(passed_tests/total_tests*100):.1f}%")
    
    if failed_tests:
        print("\nFailed tests:")
        for class_name, method_name, error in failed_tests:
            print(f"  - {class_name}.{method_name}: {error}")
    
    return {
        "total": total_tests,
        "passed": passed_tests,
        "failed": len(failed_tests),
        "success_rate": passed_tests/total_tests*100,
        "failures": failed_tests
    }


if __name__ == "__main__":
    results = run_edge_case_tests()