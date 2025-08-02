"""End-to-End Tests for MCP 2025-06-18 Compliance.

This module contains comprehensive E2E tests that verify the entire MCP integration
works correctly from initialization through tool execution with all compliance 
features enabled.
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
from typing import Dict, Any, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

# Test imports
from deepagents_mcp.mcp_client import MCPToolProvider, load_mcp_tools
from deepagents_mcp.protocol_compliance import (
    MCPProtocolValidator,
    ComplianceLevel,
    create_default_compliance_validator
)
from deepagents_mcp.initialization import (
    MCPInitializationManager,
    create_default_initialization_manager,
    InitializationState
)
from deepagents_mcp.tool_output_validation import (
    validate_tool_output,
    create_safe_error_response
)

# Configure logging for tests
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class MockMCPServer:
    """Mock MCP server for testing."""
    
    def __init__(self, name: str = "test-server", version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.initialized = False
        self.tools = []
        self.protocol_version = "2025-06-18"
        
    async def initialize(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialization request."""
        # Validate protocol version
        client_version = request.get("params", {}).get("protocolVersion")
        if client_version not in ["2025-06-18", "2025-03-26"]:
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {
                    "code": -32602,
                    "message": f"Unsupported protocol version: {client_version}"
                }
            }
            
        self.initialized = True
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "protocolVersion": self.protocol_version,
                "serverInfo": {
                    "name": self.name,
                    "version": self.version
                },
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": True},
                    "logging": {}
                }
            }
        }
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """Return available tools."""
        return [
            {
                "name": "test_tool",
                "title": "Test Tool",
                "description": "A test tool for E2E testing",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "count": {"type": "integer", "minimum": 1}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "dangerous_tool",
                "title": "Dangerous Tool",
                "description": "A tool that returns potentially dangerous content",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string"}
                    }
                }
            }
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool and return result."""
        if not self.initialized:
            return create_safe_error_response("Server not initialized", "NOT_INITIALIZED")
            
        if tool_name == "test_tool":
            query = arguments.get("query", "")
            count = arguments.get("count", 1)
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Processed query '{query}' with count {count}"
                    }
                ]
            }
        elif tool_name == "dangerous_tool":
            # Return content with XSS attempt
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "<script>alert('xss')</script>Safe content here"
                    }
                ]
            }
        else:
            return create_safe_error_response(f"Unknown tool: {tool_name}", "UNKNOWN_TOOL")


class TestE2EMCPCompliance:
    """End-to-end tests for MCP compliance."""
    
    @pytest.mark.asyncio
    async def test_full_lifecycle_stdio_transport(self):
        """Test complete MCP lifecycle with stdio transport."""
        # Create mock server
        mock_server = MockMCPServer()
        
        # Mock stdio transport connection
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
            mock_client_class.return_value = mock_client
            
            # Setup mock responses
            mock_client.initialize.return_value = await mock_server.initialize({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0.0"}
                }
            })
            
            # Create mock tool objects
            from unittest.mock import MagicMock
            mock_tools = []
            for tool_dict in await mock_server.list_tools():
                tool = MagicMock()
                tool.name = tool_dict["name"]
                tool.title = tool_dict["title"]
                tool.description = tool_dict["description"]
                tool.input_schema = tool_dict["inputSchema"]
                mock_tools.append(tool)
            
            mock_client.get_tools.return_value = mock_tools
            
            # Create provider with all security features enabled
            provider = MCPToolProvider(
                connections=connections,
                enable_security=True,
                enable_consent=True,
                validate_outputs=True
            )
            
            # Load tools
            tools = await provider.get_tools()
            
            # Verify tools loaded
            assert len(tools) == 2
            assert any(t.name == "test_server::test_tool" for t in tools)
            assert any(t.name == "test_server::dangerous_tool" for t in tools)
            
            # Test tool execution with validation
            test_tool = next(t for t in tools if "test_tool" in t.name)
            
            # Mock tool execution
            mock_client.call_tool.return_value = await mock_server.call_tool(
                "test_tool", 
                {"query": "test query", "count": 5}
            )
            
            # Execute tool (with mocked consent)
            with patch.object(provider.consent_manager, 'request_consent', return_value=True):
                result = await test_tool.ainvoke({"query": "test query", "count": 5})
            
            # Verify result is validated and safe
            assert "Processed query 'test query' with count 5" in str(result)
            
            logger.info("✓ Full lifecycle stdio transport test passed")
    
    @pytest.mark.asyncio
    async def test_http_transport_with_security(self):
        """Test HTTP transport with full security features."""
        # Mock HTTP server configuration
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
        
        # Create protocol validator
        validator = create_default_compliance_validator()
        
        # Test headers validation
        headers = {
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-06-18",
            "Authorization": "Bearer test_token"
        }
        
        compliance_result = validator.validate_http_headers(headers)
        assert compliance_result.compliant
        assert compliance_result.protocol_version == "2025-06-18"
        
        # Test missing protocol version header
        bad_headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer test_token"
        }
        
        compliance_result = validator.validate_http_headers(bad_headers)
        assert not compliance_result.compliant
        assert any("MCP-Protocol-Version" in v for v in compliance_result.violations)
        
        logger.info("✓ HTTP transport security test passed")
    
    @pytest.mark.asyncio
    async def test_tool_output_validation_e2e(self):
        """Test end-to-end tool output validation."""
        mock_server = MockMCPServer()
        
        # Initialize the server first
        await mock_server.initialize({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        })
        
        # Test 1: Safe content validation
        safe_result = await mock_server.call_tool("test_tool", {"query": "safe test"})
        validation_result = validate_tool_output(safe_result, "test_tool")
        assert validation_result.valid
        assert validation_result.sanitized_output == safe_result
        
        # Test 2: Dangerous content sanitization
        dangerous_result = await mock_server.call_tool("dangerous_tool", {"action": "test"})
        validation_result = validate_tool_output(dangerous_result, "dangerous_tool")
        assert validation_result.valid
        
        # Check that dangerous content was sanitized
        sanitized_text = validation_result.sanitized_output["content"][0]["text"]
        assert "<script>" not in sanitized_text
        assert "Safe content here" in sanitized_text
        
        # Test 3: Oversized content rejection
        oversized_result = {
            "content": [{
                "type": "text",
                "text": "x" * (1048576 + 1)  # Exceeds 1MB limit
            }]
        }
        validation_result = validate_tool_output(oversized_result, "test_tool")
        assert not validation_result.valid
        assert validation_result.has_errors()
        
        # Test 4: Invalid content structure
        invalid_result = {
            "content": [{
                "type": "image",
                # Missing required data or uri for image type
            }]
        }
        validation_result = validate_tool_output(invalid_result, "test_tool")
        assert not validation_result.valid
        
        logger.info("✓ Tool output validation E2E test passed")
    
    @pytest.mark.asyncio
    async def test_initialization_negotiation(self):
        """Test protocol version negotiation during initialization."""
        manager = create_default_initialization_manager(
            "test-server",
            "1.0.0",
            tools_enabled=True,
            resources_enabled=True
        )
        
        session_id = "test-session"
        
        # Test 1: Current version (2025-06-18)
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"roots": {"listChanged": True}},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        }
        
        response = await manager.handle_initialize_request(init_request, session_id)
        assert "result" in response
        assert response["result"]["protocolVersion"] == "2025-06-18"
        
        # Send initialized notification
        initialized_notif = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        
        await manager.handle_initialized_notification(initialized_notif, session_id)
        assert manager.is_session_initialized(session_id)
        
        # Test 2: Older supported version (2025-03-26)
        session_id_2 = "test-session-2"
        older_request = init_request.copy()
        older_request["params"]["protocolVersion"] = "2025-03-26"
        
        response = await manager.handle_initialize_request(older_request, session_id_2)
        assert "result" in response
        assert response["result"]["protocolVersion"] == "2025-03-26"
        
        # Test 3: Unsupported version
        session_id_3 = "test-session-3"
        unsupported_request = init_request.copy()
        unsupported_request["params"]["protocolVersion"] = "2020-01-01"
        
        response = await manager.handle_initialize_request(unsupported_request, session_id_3)
        # Should still work but negotiate to supported version
        if "result" in response:
            assert response["result"]["protocolVersion"] in ["2025-06-18", "2025-03-26"]
        
        logger.info("✓ Initialization negotiation test passed")
    
    @pytest.mark.asyncio
    async def test_json_rpc_batch_rejection(self):
        """Test that JSON-RPC batches are properly rejected."""
        from deepagents_mcp.jsonrpc_validation import create_default_validator
        
        validator = create_default_validator()
        
        # Test batch request (should be rejected)
        batch_request = [
            {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            {"jsonrpc": "2.0", "method": "resources/list", "id": 2}
        ]
        
        result = validator.validate_batch_not_supported(batch_request)
        assert not result.valid
        assert any("batching is not supported" in error for error in result.errors)
        
        # Test single request (should be accepted)
        single_request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        result = validator.validate_message(single_request)
        assert result.valid
        
        logger.info("✓ JSON-RPC batch rejection test passed")
    
    @pytest.mark.asyncio
    async def test_error_handling_compliance(self):
        """Test error handling meets MCP standards."""
        mock_server = MockMCPServer()
        
        # Test 1: Uninitialized server error
        error_result = await mock_server.call_tool("test_tool", {})
        validation_result = validate_tool_output(error_result, "test_tool")
        assert validation_result.valid
        assert error_result["content"][0]["type"] == "error"
        assert error_result["content"][0]["code"] == "NOT_INITIALIZED"
        
        # Initialize server
        await mock_server.initialize({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        })
        
        # Test 2: Unknown tool error
        error_result = await mock_server.call_tool("unknown_tool", {})
        validation_result = validate_tool_output(error_result, "unknown_tool")
        assert validation_result.valid
        assert error_result["content"][0]["type"] == "error"
        assert error_result["content"][0]["code"] == "UNKNOWN_TOOL"
        
        # Test 3: Create standardized error
        error_response = create_safe_error_response(
            "Test error message",
            "TEST_ERROR_CODE"
        )
        
        validation_result = validate_tool_output(error_response, "error_test")
        assert validation_result.valid
        assert len(error_response["content"]) == 1
        assert error_response["content"][0]["type"] == "error"
        assert error_response["content"][0]["text"] == "Test error message"
        assert error_response["content"][0]["code"] == "TEST_ERROR_CODE"
        
        logger.info("✓ Error handling compliance test passed")
    
    @pytest.mark.asyncio
    async def test_security_features_integration(self):
        """Test integration of all security features."""
        connections = {
            "secure_server": {
                "command": "python",
                "args": ["-m", "secure_server"],
                "transport": "stdio"
            }
        }
        
        # Mock the client with security features
        with patch('deepagents_mcp.mcp_client.MultiServerMCPClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            # Mock secure initialization
            mock_client.initialize.return_value = {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "secure-server", "version": "1.0.0"},
                    "capabilities": {"tools": {"listChanged": True}}
                }
            }
            
            # Mock tool with sensitive operation
            mock_client.get_tools.return_value = [{
                "name": "sensitive_tool",
                "title": "Sensitive Tool",
                "description": "Performs sensitive operations",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string"},
                        "target": {"type": "string"}
                    },
                    "required": ["action", "target"]
                }
            }]
            
            # Create provider with all security enabled
            provider = MCPToolProvider(
                connections=connections,
                enable_security=True,
                enable_consent=True,
                validate_outputs=True
            )
            
            # Load tools
            tools = await provider.get_tools()
            assert len(tools) == 1
            
            sensitive_tool = tools[0]
            
            # Test consent requirement
            mock_client.call_tool.return_value = {
                "content": [{
                    "type": "text",
                    "text": "Sensitive operation completed"
                }]
            }
            
            # Without consent (should be blocked)
            with patch.object(provider.consent_manager, 'request_consent', return_value=False):
                try:
                    result = await sensitive_tool.ainvoke({
                        "action": "delete",
                        "target": "important_file"
                    })
                    # Should not reach here
                    assert False, "Tool should have been blocked without consent"
                except Exception as e:
                    assert "consent" in str(e).lower() or "denied" in str(e).lower()
            
            # With consent (should proceed with validation)
            with patch.object(provider.consent_manager, 'request_consent', return_value=True):
                result = await sensitive_tool.ainvoke({
                    "action": "delete", 
                    "target": "important_file"
                })
                assert "Sensitive operation completed" in str(result)
            
            logger.info("✓ Security features integration test passed")
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Test concurrent MCP operations."""
        connections = {
            f"server_{i}": {
                "command": "python",
                "args": ["-m", f"server_{i}"],
                "transport": "stdio"
            }
            for i in range(3)
        }
        
        with patch('deepagents_mcp.mcp_client.MultiServerMCPClient') as mock_client_class:
            # Create multiple mock clients
            mock_clients = {}
            for server_name in connections:
                mock_client = AsyncMock()
                mock_client.initialize.return_value = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "serverInfo": {"name": server_name, "version": "1.0.0"},
                        "capabilities": {"tools": {}}
                    }
                }
                mock_client.get_tools.return_value = [{
                    "name": f"tool_{server_name}",
                    "title": f"Tool for {server_name}",
                    "description": "Test tool",
                    "inputSchema": {"type": "object"}
                }]
                mock_clients[server_name] = mock_client
            
            def get_client_for_server(server_name):
                return mock_clients[server_name]
            
            mock_client_class.side_effect = lambda conn, name: mock_clients[name]
            
            # Create provider
            provider = MCPToolProvider(
                connections=connections,
                enable_security=True,
                enable_consent=True,
                validate_outputs=True
            )
            
            # Load tools concurrently
            tools = await provider.get_tools()
            
            # Should have 3 tools total
            assert len(tools) == 3
            
            # Test concurrent tool execution
            async def execute_tool(tool):
                mock_clients[tool.name.split("::")[0]].call_tool.return_value = {
                    "content": [{
                        "type": "text",
                        "text": f"Result from {tool.name}"
                    }]
                }
                
                with patch.object(provider.consent_manager, 'request_consent', return_value=True):
                    return await tool.ainvoke({})
            
            # Execute all tools concurrently
            results = await asyncio.gather(*[execute_tool(tool) for tool in tools])
            
            # Verify all completed successfully
            assert len(results) == 3
            for i, result in enumerate(results):
                assert f"Result from" in str(result)
            
            logger.info("✓ Concurrent operations test passed")


class TestE2EIntegrationScenarios:
    """Integration scenario tests."""
    
    @pytest.mark.asyncio
    async def test_real_world_scenario(self):
        """Test a real-world usage scenario."""
        # Simulate a code analysis tool scenario
        connections = {
            "code_analyzer": {
                "command": "python",
                "args": ["-m", "code_analyzer"],
                "transport": "stdio"
            }
        }
        
        with patch('deepagents_mcp.mcp_client.MultiServerMCPClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            # Initialize with code analysis capabilities
            mock_client.initialize.return_value = {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {
                        "name": "code-analyzer",
                        "version": "2.0.0",
                        "description": "Advanced code analysis MCP server"
                    },
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": True}
                    }
                }
            }
            
            # Provide code analysis tools
            mock_client.get_tools.return_value = [
                {
                    "name": "analyze_code",
                    "title": "Analyze Code",
                    "description": "Analyze code for quality, security, and best practices",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string"},
                            "language": {"type": "string", "enum": ["python", "javascript", "typescript"]},
                            "checks": {
                                "type": "array",
                                "items": {"type": "string", "enum": ["security", "quality", "performance"]}
                            }
                        },
                        "required": ["code", "language"]
                    }
                },
                {
                    "name": "suggest_improvements",
                    "title": "Suggest Improvements",
                    "description": "Get improvement suggestions for code",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "analysis_id": {"type": "string"}
                        },
                        "required": ["analysis_id"]
                    }
                }
            ]
            
            # Create provider
            provider = MCPToolProvider(
                connections=connections,
                enable_security=True,
                enable_consent=True,
                validate_outputs=True
            )
            
            # Load tools
            tools = await provider.get_tools()
            analyze_tool = next(t for t in tools if "analyze_code" in t.name)
            suggest_tool = next(t for t in tools if "suggest_improvements" in t.name)
            
            # Simulate code analysis workflow
            test_code = """
def process_user_input(user_data):
    # Potential SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_data['id']}"
    return execute_query(query)
"""
            
            # Step 1: Analyze code
            mock_client.call_tool.return_value = {
                "content": [{
                    "type": "text",
                    "text": json.dumps({
                        "analysis_id": "12345",
                        "issues": [
                            {
                                "type": "security",
                                "severity": "high",
                                "message": "SQL injection vulnerability detected",
                                "line": 3
                            }
                        ],
                        "score": {"security": 2, "quality": 7, "performance": 8}
                    })
                }]
            }
            
            with patch.object(provider.consent_manager, 'request_consent', return_value=True):
                analysis_result = await analyze_tool.ainvoke({
                    "code": test_code,
                    "language": "python",
                    "checks": ["security", "quality"]
                })
            
            # Verify analysis completed
            assert "SQL injection vulnerability" in str(analysis_result)
            
            # Step 2: Get improvement suggestions
            mock_client.call_tool.return_value = {
                "content": [{
                    "type": "text",
                    "text": json.dumps({
                        "suggestions": [
                            {
                                "issue_id": "sql_injection_1",
                                "suggestion": "Use parameterized queries",
                                "example": "query = 'SELECT * FROM users WHERE id = ?'\nexecute_query(query, [user_data['id']])"
                            }
                        ]
                    })
                }]
            }
            
            with patch.object(provider.consent_manager, 'request_consent', return_value=True):
                suggestions_result = await suggest_tool.ainvoke({
                    "analysis_id": "12345"
                })
            
            # Verify suggestions received
            assert "parameterized queries" in str(suggestions_result)
            
            logger.info("✓ Real-world scenario test passed")
    
    @pytest.mark.asyncio 
    async def test_error_recovery_scenario(self):
        """Test error recovery in various failure scenarios."""
        connections = {
            "unreliable_server": {
                "command": "python",
                "args": ["-m", "unreliable_server"],
                "transport": "stdio"
            }
        }
        
        with patch('deepagents_mcp.mcp_client.MultiServerMCPClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            # Scenario 1: Initialization failure then recovery
            call_count = 0
            async def init_with_retry(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    # First call fails
                    raise ConnectionError("Server not ready")
                else:
                    # Second call succeeds
                    return {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "serverInfo": {"name": "unreliable", "version": "1.0.0"},
                            "capabilities": {"tools": {}}
                        }
                    }
            
            mock_client.initialize.side_effect = init_with_retry
            mock_client.get_tools.return_value = []
            
            # Should handle initialization failure gracefully
            provider = MCPToolProvider(
                connections=connections,
                enable_security=True,
                enable_consent=True,
                validate_outputs=True
            )
            
            try:
                tools = await provider.get_tools()
                # If we get here, initialization recovered
                assert call_count > 1  # Verify retry happened
            except Exception as e:
                # Initial failure is expected
                assert "not ready" in str(e)
            
            logger.info("✓ Error recovery scenario test passed")


async def run_all_e2e_tests():
    """Run all end-to-end tests."""
    print("\n" + "="*60)
    print("Running MCP 2025-06-18 Compliance End-to-End Tests")
    print("="*60 + "\n")
    
    # Create test instance
    compliance_tests = TestE2EMCPCompliance()
    integration_tests = TestE2EIntegrationScenarios()
    
    # Run all tests
    tests = [
        ("Full Lifecycle STDIO Transport", compliance_tests.test_full_lifecycle_stdio_transport),
        ("HTTP Transport with Security", compliance_tests.test_http_transport_with_security),
        ("Tool Output Validation E2E", compliance_tests.test_tool_output_validation_e2e),
        ("Initialization Negotiation", compliance_tests.test_initialization_negotiation),
        ("JSON-RPC Batch Rejection", compliance_tests.test_json_rpc_batch_rejection),
        ("Error Handling Compliance", compliance_tests.test_error_handling_compliance),
        ("Security Features Integration", compliance_tests.test_security_features_integration),
        ("Concurrent Operations", compliance_tests.test_concurrent_operations),
        ("Real World Scenario", integration_tests.test_real_world_scenario),
        ("Error Recovery Scenario", integration_tests.test_error_recovery_scenario),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"Running: {test_name}...", end=" ")
            await test_func()
            print("✅ PASSED")
            passed += 1
        except Exception as e:
            print(f"❌ FAILED: {e}")
            failed += 1
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    # Run the tests
    success = asyncio.run(run_all_e2e_tests())
    sys.exit(0 if success else 1)