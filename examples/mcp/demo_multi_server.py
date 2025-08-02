#!/usr/bin/env python3
"""MCP Demo: Multi-Server Orchestration

This example demonstrates:
- Using multiple MCP servers simultaneously
- Orchestrating tools from different servers
- Complex workflows across multiple data sources
"""

import asyncio
import os
from pathlib import Path
from deepagents import create_deep_agent_async


async def main():
    """Demonstrate multi-server MCP orchestration."""
    print("=== MCP Demo: Multi-Server Orchestration ===\n")
    
    # Configure multiple MCP servers
    mcp_connections = {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", str(Path.cwd())],
            "transport": "stdio"
        },
        "time": {
            "command": "npx",
            "args": ["-y", "mcp-remote", "https://mcp.time.mcpcentral.io"],
            "transport": "stdio"
        },
        "build-vault": {
            "command": "npx",
            "args": ["-y", "mcp-remote", "https://mcp.buildaipod.com/mcp"],
            "transport": "stdio"
        },
        "math": {
            "command": "python",
            "args": [str(Path(__file__).parent / "math_server.py")],
            "transport": "stdio"
        }
    }
    
    # Create agent with multi-server orchestration capabilities
    agent = await create_deep_agent_async(
        tools=[],
        instructions="""You are a multi-tool orchestrator with access to:
- Filesystem tools for local file operations
- Time tools for temporal queries and scheduling
- Build Vault for AI/startup insights
- Math tools for calculations

Your expertise includes:
1. Combining data from multiple sources
2. Creating comprehensive analyses
3. Time-aware reporting
4. Data synthesis and correlation

When responding, explicitly mention which MCP servers you're using.""",
        mcp_connections=mcp_connections
    )
    
    # Complex queries requiring multiple servers
    queries = [
        "What's the current time? Calculate how many seconds have passed since midnight and save the result to a file called 'time_analysis.txt'",
        
        "Search Build Vault for insights about MCP (Model Context Protocol), then create a summary report with the current timestamp",
        
        "Read the project's README.md file, calculate the word count, and find AI startup insights related to developer tools",
        
        "Create a comprehensive project status report that includes: current time, project file count, a calculation of project age in days (use 30 days), and relevant AI ecosystem insights"
    ]
    
    print("Running multi-server orchestration tasks...\n")
    
    for i, query in enumerate(queries, 1):
        print(f"[Query {i}] {query}")
        print("-" * 80)
        
        try:
            result = await agent.ainvoke({
                "messages": [{"role": "user", "content": query}]
            })
            
            if result.get("messages"):
                response = result["messages"][-1].content
                print(f"Response:\n{response}\n")
                
                # Save response for later analysis
                with open(f"output_demo3_query{i}.txt", "w") as f:
                    f.write(f"Query: {query}\n\n")
                    f.write(f"Response:\n{response}\n")
                
                # Also check for created files
                if result.get("files"):
                    print("Files created by agent:")
                    for filename, content in result["files"].items():
                        print(f"  - {filename} ({len(content)} bytes)")
            
        except Exception as e:
            print(f"Error: {e}\n")
    
    print("\n=== Demo completed! Outputs saved for analysis ===")


if __name__ == "__main__":
    asyncio.run(main())