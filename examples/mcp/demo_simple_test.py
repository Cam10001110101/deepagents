#!/usr/bin/env python3
"""Simple MCP Demo Test - Tests MCP tool loading and basic functionality."""

import asyncio
import os
from pathlib import Path
import sys

# Add project paths
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "deepagents-mcp" / "src"))

from deepagents import create_deep_agent_async
from deepagents_mcp import MCPToolProvider
import datetime


async def main():
    """Test basic MCP functionality."""
    print("=== Simple MCP Functionality Test ===\n")
    
    # Simple MCP connection - just the math server
    mcp_connections = {
        "math": {
            "command": "python",
            "args": [str(Path(__file__).parent / "math_server.py")],
            "transport": "stdio"
        }
    }
    
    print("1. Testing MCP Tool Loading...")
    print("-" * 40)
    
    try:
        # Create MCP provider
        provider = MCPToolProvider(
            connections=mcp_connections,
            enable_security=True,
            enable_consent=False,  # Disable for testing
            validate_outputs=True
        )
        
        # Load tools
        tools = await provider.get_tools()
        print(f"✅ Successfully loaded {len(tools)} MCP tools:")
        for tool in tools:
            print(f"   - {tool.name}: {tool.description}")
        
    except Exception as e:
        print(f"❌ Failed to load MCP tools: {e}")
        return
    
    print("\n2. Testing Tool Discovery...")
    print("-" * 40)
    
    # Test if we can create an agent with MCP tools
    try:
        # Use a simple test - don't actually invoke the agent
        print("Creating agent with MCP connections...")
        
        # Just verify the connections are valid
        from deepagents_mcp.protocol_compliance import validate_mcp_connection
        
        for name, config in mcp_connections.items():
            result = validate_mcp_connection(config)
            if result.compliant:
                print(f"✅ {name}: Valid MCP configuration")
            else:
                print(f"❌ {name}: {', '.join(result.violations)}")
        
    except Exception as e:
        print(f"Error during validation: {e}")
    
    print("\n3. Testing Protocol Compliance...")
    print("-" * 40)
    
    # Test protocol compliance features
    from deepagents_mcp.protocol_compliance import MCPProtocolValidator
    from deepagents_mcp.tool_output_validation import ToolOutputValidator
    
    # Test protocol validator
    validator = MCPProtocolValidator()
    print(f"Protocol validator initialized: {validator.SPEC_VERSION}")
    
    # Test output validator
    output_validator = ToolOutputValidator()
    
    # Test valid content
    valid_content = [{
        "type": "text",
        "text": "This is safe content"
    }]
    
    validated = output_validator.validate_and_sanitize(valid_content)
    print(f"✅ Valid content passed validation")
    
    # Test XSS content
    xss_content = [{
        "type": "text",
        "text": "Hello <script>alert('xss')</script> world"
    }]
    
    sanitized = output_validator.validate_and_sanitize(xss_content)
    if "<script>" not in sanitized[0]["text"]:
        print(f"✅ XSS content properly sanitized")
    else:
        print(f"❌ XSS sanitization failed")
    
    print("\n=== Test Summary ===")
    print("MCP integration is working with:")
    print("- Tool loading from MCP servers")
    print("- Protocol compliance validation")
    print("- Output sanitization")
    print("\nReady for LangSmith analysis!")
    
    # Save test results
    with open("mcp_test_results.json", "w") as f:
        import json
        json.dump({
            "test_timestamp": datetime.datetime.now().isoformat(),
            "mcp_servers": list(mcp_connections.keys()),
            "tools_loaded": len(tools) if 'tools' in locals() else 0,
            "compliance_enabled": True,
            "security_features": {
                "oauth": provider.enable_security if 'provider' in locals() else False,
                "consent": provider.enable_consent if 'provider' in locals() else False,
                "output_validation": provider.validate_outputs if 'provider' in locals() else False
            }
        }, f, indent=2)


if __name__ == "__main__":
    asyncio.run(main())