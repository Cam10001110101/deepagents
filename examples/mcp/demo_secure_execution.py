#!/usr/bin/env python3
"""MCP Demo: Secure Tool Execution with Consent

This example demonstrates:
- MCP 2025-06-18 security features
- User consent for sensitive operations
- OAuth 2.1 authentication
- Tool output validation
"""

import asyncio
import os
from pathlib import Path
from deepagents import create_deep_agent_async
from deepagents_mcp import MCPToolProvider
from deepagents_mcp.consent import ConsentRequest


# Mock consent callback for demonstration
async def demo_consent_callback(request: ConsentRequest) -> bool:
    """Simulate user consent decision based on risk level."""
    print(f"\n🔐 CONSENT REQUEST:")
    print(f"   Tool: {request.tool_name}")
    print(f"   Risk: {request.risk_level}")
    print(f"   Reason: {request.reason}")
    print(f"   Context: {request.context}")
    
    # Auto-approve low risk, prompt for high risk
    if request.risk_level == "low":
        print("   ✅ Auto-approved (low risk)\n")
        return True
    else:
        print("   ⚠️  High-risk operation - simulating user denial")
        print("   ❌ Consent denied\n")
        return False


async def main():
    """Demonstrate secure MCP tool execution."""
    print("=== MCP Demo: Secure Tool Execution ===\n")
    print("This demo showcases MCP 2025-06-18 security features:\n")
    print("- OAuth 2.1 authentication")
    print("- User consent framework")
    print("- Tool output validation")
    print("- XSS prevention\n")
    
    # Configure MCP with security features
    mcp_connections = {
        "secure_filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", str(Path.home())],
            "transport": "stdio",
            "security": {
                "enable_oauth": True,
                "enable_consent": True,
                "validate_outputs": True
            }
        }
    }
    
    # Create custom MCP provider with consent callback
    print("Setting up secure MCP provider...\n")
    
    # Create agent with security-focused instructions
    agent = await create_deep_agent_async(
        tools=[],
        instructions="""You are a security-conscious assistant with MCP tools.

Important security guidelines:
1. All file operations require user consent
2. Outputs are validated for security issues
3. You must explain security implications before using tools
4. High-risk operations may be denied

When using tools:
- Explain what the tool will do
- Mention any security considerations
- Respect consent decisions
- Report validation errors clearly""",
        mcp_connections=mcp_connections
    )
    
    # Override consent callback for demo
    if hasattr(agent, '_tools') and agent._tools:
        for tool in agent._tools:
            if hasattr(tool, '_mcp_provider') and hasattr(tool._mcp_provider, 'consent_manager'):
                tool._mcp_provider.consent_manager.consent_callback = demo_consent_callback
    
    # Security-focused test queries
    queries = [
        "List files in the home directory (this should trigger consent)",
        
        "Try to read ~/.ssh/config file (high-risk operation that should be denied)",
        
        "Create a safe text file called 'security_test.txt' with some content",
        
        "Attempt to create a file with XSS content: <script>alert('xss')</script>",
        
        "Read a non-sensitive file like ~/.profile and summarize its purpose"
    ]
    
    print("Running secure execution tests...\n")
    
    for i, query in enumerate(queries, 1):
        print(f"[Security Test {i}] {query}")
        print("-" * 70)
        
        try:
            result = await agent.ainvoke({
                "messages": [{"role": "user", "content": query}]
            })
            
            if result.get("messages"):
                response = result["messages"][-1].content
                print(f"Response:\n{response}\n")
                
                # Save response with security context
                with open(f"output_demo5_security{i}.txt", "w") as f:
                    f.write(f"Security Test {i}\n")
                    f.write(f"Query: {query}\n\n")
                    f.write(f"Response:\n{response}\n")
                    
                    # Note any security events
                    if "consent denied" in response.lower():
                        f.write("\nSECURITY EVENT: Consent denied for high-risk operation\n")
                    if "validation" in response.lower():
                        f.write("\nSECURITY EVENT: Output validation triggered\n")
            
        except Exception as e:
            print(f"Security exception (expected for some tests): {e}\n")
    
    print("\n=== Security Demo completed! ===")
    print("Review the output files to see security features in action:")
    print("- Consent requests for file operations")
    print("- Denial of high-risk operations")
    print("- XSS content sanitization")
    print("- Secure error handling")


if __name__ == "__main__":
    asyncio.run(main())