"""Mock MCP Server for E2E Testing.

This module provides a mock MCP server that implements the full MCP 2025-06-18
protocol for testing purposes.
"""

import asyncio
import json
import logging
import sys
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import uuid

logger = logging.getLogger(__name__)


@dataclass
class MockTool:
    """Mock tool definition."""
    name: str
    title: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Optional[Dict[str, Any]] = None
    handler: Optional[Any] = None


@dataclass 
class MockResource:
    """Mock resource definition."""
    uri: str
    name: str
    title: str
    description: str
    mime_type: str = "text/plain"
    content: str = ""


class MockMCPServerProtocol:
    """Mock MCP server implementing stdio protocol."""
    
    def __init__(self, name: str = "mock-mcp-server", version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.initialized = False
        self.protocol_version = None
        self.client_info = None
        self.client_capabilities = None
        
        # Server capabilities
        self.capabilities = {
            "tools": {"listChanged": True},
            "resources": {"subscribe": True, "listChanged": True},
            "logging": {},
            "completions": {}
        }
        
        # Available tools
        self.tools: Dict[str, MockTool] = self._create_default_tools()
        
        # Available resources  
        self.resources: Dict[str, MockResource] = self._create_default_resources()
        
        # Session tracking
        self.session_id = str(uuid.uuid4())
        self.request_count = 0
        
    def _create_default_tools(self) -> Dict[str, MockTool]:
        """Create default tools for testing."""
        return {
            "echo": MockTool(
                name="echo",
                title="Echo Tool",
                description="Echoes back the input message",
                input_schema={
                    "type": "object",
                    "properties": {
                        "message": {"type": "string"},
                        "uppercase": {"type": "boolean", "default": False}
                    },
                    "required": ["message"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string"},
                                    "text": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            ),
            "calculate": MockTool(
                name="calculate",
                title="Calculator",
                description="Performs basic arithmetic operations",
                input_schema={
                    "type": "object",
                    "properties": {
                        "operation": {
                            "type": "string",
                            "enum": ["add", "subtract", "multiply", "divide"]
                        },
                        "a": {"type": "number"},
                        "b": {"type": "number"}
                    },
                    "required": ["operation", "a", "b"]
                }
            ),
            "dangerous_tool": MockTool(
                name="dangerous_tool",
                title="Dangerous Tool",
                description="A tool that could return unsafe content",
                input_schema={
                    "type": "object",
                    "properties": {
                        "action": {"type": "string"}
                    }
                }
            )
        }
    
    def _create_default_resources(self) -> Dict[str, MockResource]:
        """Create default resources for testing."""
        return {
            "test://config": MockResource(
                uri="test://config",
                name="config",
                title="Configuration",
                description="Server configuration file",
                mime_type="application/json",
                content=json.dumps({
                    "server": self.name,
                    "version": self.version,
                    "protocol": "2025-06-18"
                })
            ),
            "test://readme": MockResource(
                uri="test://readme",
                name="readme",
                title="README",
                description="Server documentation",
                mime_type="text/markdown",
                content="# Mock MCP Server\n\nThis is a mock server for testing."
            )
        }
    
    async def handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle incoming JSON-RPC message."""
        self.request_count += 1
        
        # Check for batch (should be rejected)
        if isinstance(message, list):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "JSON-RPC batching is not supported in MCP"
                }
            }
        
        # Validate JSON-RPC structure
        if not isinstance(message, dict):
            return self._error_response(None, -32700, "Parse error")
            
        if message.get("jsonrpc") != "2.0":
            return self._error_response(
                message.get("id"),
                -32600,
                "Invalid Request: jsonrpc must be '2.0'"
            )
        
        method = message.get("method")
        if not method:
            return self._error_response(
                message.get("id"),
                -32600,
                "Invalid Request: method is required"
            )
        
        # Route to appropriate handler
        handlers = {
            "initialize": self._handle_initialize,
            "notifications/initialized": self._handle_initialized,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tool_call,
            "resources/list": self._handle_resources_list,
            "resources/read": self._handle_resource_read,
            "completion/complete": self._handle_completion,
            "ping": self._handle_ping
        }
        
        handler = handlers.get(method)
        if not handler:
            return self._error_response(
                message.get("id"),
                -32601,
                f"Method not found: {method}"
            )
        
        try:
            return await handler(message)
        except Exception as e:
            logger.error(f"Error handling {method}: {e}")
            return self._error_response(
                message.get("id"),
                -32603,
                f"Internal error: {str(e)}"
            )
    
    async def _handle_initialize(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialize request."""
        params = message.get("params", {})
        
        # Validate required fields
        if not params.get("protocolVersion"):
            return self._error_response(
                message.get("id"),
                -32602,
                "Invalid params: protocolVersion is required"
            )
            
        if not params.get("capabilities"):
            return self._error_response(
                message.get("id"),
                -32602,
                "Invalid params: capabilities is required"
            )
            
        if not params.get("clientInfo"):
            return self._error_response(
                message.get("id"),
                -32602,
                "Invalid params: clientInfo is required"
            )
        
        # Version negotiation
        client_version = params["protocolVersion"]
        supported_versions = ["2025-06-18", "2025-03-26"]
        
        if client_version not in supported_versions:
            return self._error_response(
                message.get("id"),
                -32602,
                f"Unsupported protocol version: {client_version}"
            )
        
        # Use the client's version if supported
        self.protocol_version = client_version
        self.client_info = params["clientInfo"]
        self.client_capabilities = params["capabilities"]
        self.initialized = True
        
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "protocolVersion": self.protocol_version,
                "serverInfo": {
                    "name": self.name,
                    "version": self.version,
                    "description": "Mock MCP server for testing"
                },
                "capabilities": self.capabilities,
                "sessionId": self.session_id
            }
        }
    
    async def _handle_initialized(self, message: Dict[str, Any]) -> None:
        """Handle initialized notification."""
        # Notifications don't get responses
        logger.info("Client initialization complete")
        return None
    
    async def _handle_tools_list(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/list request."""
        if not self.initialized:
            return self._error_response(
                message.get("id"),
                -32002,
                "Server not initialized"
            )
        
        tools = []
        for tool_name, tool in self.tools.items():
            tool_def = {
                "name": tool.name,
                "title": tool.title,
                "description": tool.description,
                "inputSchema": tool.input_schema
            }
            if tool.output_schema:
                tool_def["outputSchema"] = tool.output_schema
            tools.append(tool_def)
        
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": tools}
        }
    
    async def _handle_tool_call(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/call request."""
        if not self.initialized:
            return self._error_response(
                message.get("id"),
                -32002,
                "Server not initialized"
            )
        
        params = message.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if not tool_name:
            return self._error_response(
                message.get("id"),
                -32602,
                "Invalid params: name is required"
            )
        
        tool = self.tools.get(tool_name)
        if not tool:
            return self._error_response(
                message.get("id"),
                -32601,
                f"Unknown tool: {tool_name}"
            )
        
        # Execute tool
        try:
            result = await self._execute_tool(tool, arguments)
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": result
            }
        except Exception as e:
            return self._error_response(
                message.get("id"),
                -32603,
                f"Tool execution error: {str(e)}"
            )
    
    async def _execute_tool(self, tool: MockTool, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool and return result."""
        if tool.name == "echo":
            message = arguments.get("message", "")
            uppercase = arguments.get("uppercase", False)
            text = message.upper() if uppercase else message
            
            return {
                "content": [{
                    "type": "text",
                    "text": text
                }]
            }
            
        elif tool.name == "calculate":
            operation = arguments.get("operation")
            a = arguments.get("a", 0)
            b = arguments.get("b", 0)
            
            operations = {
                "add": lambda: a + b,
                "subtract": lambda: a - b,
                "multiply": lambda: a * b,
                "divide": lambda: a / b if b != 0 else "Error: Division by zero"
            }
            
            result = operations.get(operation, lambda: "Invalid operation")()
            
            return {
                "content": [{
                    "type": "text",
                    "text": f"Result: {result}"
                }]
            }
            
        elif tool.name == "dangerous_tool":
            # Return content with potential XSS
            return {
                "content": [{
                    "type": "text",
                    "text": "<script>alert('xss')</script>This is safe content"
                }]
            }
        
        else:
            raise ValueError(f"No handler for tool: {tool.name}")
    
    async def _handle_resources_list(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle resources/list request."""
        if not self.initialized:
            return self._error_response(
                message.get("id"),
                -32002,
                "Server not initialized"
            )
        
        resources = []
        for uri, resource in self.resources.items():
            resources.append({
                "uri": resource.uri,
                "name": resource.name,
                "title": resource.title,
                "description": resource.description,
                "mimeType": resource.mime_type
            })
        
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"resources": resources}
        }
    
    async def _handle_resource_read(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle resources/read request."""
        if not self.initialized:
            return self._error_response(
                message.get("id"),
                -32002,
                "Server not initialized"
            )
        
        params = message.get("params", {})
        uri = params.get("uri")
        
        if not uri:
            return self._error_response(
                message.get("id"),
                -32602,
                "Invalid params: uri is required"
            )
        
        resource = self.resources.get(uri)
        if not resource:
            return self._error_response(
                message.get("id"),
                -32601,
                f"Resource not found: {uri}"
            )
        
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "content": [{
                    "type": "text",
                    "text": resource.content,
                    "mimeType": resource.mime_type
                }]
            }
        }
    
    async def _handle_completion(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle completion/complete request."""
        if not self.initialized:
            return self._error_response(
                message.get("id"),
                -32002,
                "Server not initialized"
            )
        
        # Simple completion example
        params = message.get("params", {})
        ref = params.get("ref", {})
        argument = params.get("argument", {})
        
        completions = []
        
        if ref.get("type") == "ref/tool" and ref.get("name") == "calculate":
            if argument.get("name") == "operation":
                completions = [
                    {"value": "add", "label": "Addition"},
                    {"value": "subtract", "label": "Subtraction"},
                    {"value": "multiply", "label": "Multiplication"},
                    {"value": "divide", "label": "Division"}
                ]
        
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"completions": completions}
        }
    
    async def _handle_ping(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ping request."""
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {}
        }
    
    def _error_response(self, id: Any, code: int, message: str) -> Dict[str, Any]:
        """Create error response."""
        return {
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message
            }
        }


async def run_mock_server():
    """Run the mock server on stdio."""
    server = MockMCPServerProtocol()
    
    logger.info(f"Mock MCP Server {server.version} starting...")
    
    # Read from stdin, write to stdout
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)
    
    writer = asyncio.StreamWriter(
        asyncio.get_event_loop()._transport,
        protocol,
        reader,
        asyncio.get_event_loop()
    )
    
    while True:
        try:
            # Read line from stdin
            line = await reader.readline()
            if not line:
                break
                
            # Parse JSON-RPC message
            try:
                message = json.loads(line.decode().strip())
            except json.JSONDecodeError:
                error = server._error_response(None, -32700, "Parse error")
                writer.write(json.dumps(error).encode() + b'\n')
                await writer.drain()
                continue
            
            # Handle message
            response = await server.handle_message(message)
            
            # Send response if not a notification
            if response is not None:
                writer.write(json.dumps(response).encode() + b'\n')
                await writer.drain()
                
        except Exception as e:
            logger.error(f"Server error: {e}")
            break
    
    logger.info("Mock server shutting down")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run server
    asyncio.run(run_mock_server())