#!/usr/bin/env python3
"""MCP Demo: GitHub Integration for Code Analysis

This example demonstrates:
- Using GitHub MCP server to analyze repositories
- Reviewing pull requests and issues
- Analyzing code patterns and contributors
"""

import asyncio
import os
from deepagents import create_deep_agent_async


async def main():
    """Demonstrate GitHub MCP tools for code analysis."""
    print("=== MCP Demo: GitHub Code Analysis ===\n")
    
    # Check for GitHub token
    github_token = os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN")
    if not github_token:
        print("⚠️  GITHUB_PERSONAL_ACCESS_TOKEN not set")
        print("   Using limited anonymous access")
        print("   Set the token for full functionality\n")
    
    # Configure MCP connections
    mcp_connections = {
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "transport": "stdio",
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": github_token or ""}
        }
    }
    
    # Create agent with GitHub analysis focus
    agent = await create_deep_agent_async(
        tools=[],
        instructions="""You are a GitHub repository analyst with expertise in:
- Code quality assessment
- Pull request reviews
- Issue tracking and management
- Contributor analysis
- Best practices identification

Provide detailed but actionable insights. Focus on:
1. Code organization and patterns
2. Development workflow efficiency
3. Community engagement
4. Technical debt identification""",
        mcp_connections=mcp_connections
    )
    
    # Test queries for the deepagents repository
    queries = [
        "Analyze the Cam10001110101/deepagents repository structure and main components",
        "List the most recent pull requests in Cam10001110101/deepagents and summarize their changes",
        "Search for open issues in Cam10001110101/deepagents related to MCP or testing",
        "Analyze the commit history of Cam10001110101/deepagents and identify the most active contributors"
    ]
    
    print("Analyzing deepagents repository on GitHub...\n")
    
    for i, query in enumerate(queries, 1):
        print(f"[Query {i}] {query}")
        print("-" * 60)
        
        try:
            result = await agent.ainvoke({
                "messages": [{"role": "user", "content": query}]
            })
            
            if result.get("messages"):
                response = result["messages"][-1].content
                print(f"Response:\n{response}\n")
                
                # Save response for later analysis
                with open(f"output_demo2_query{i}.txt", "w") as f:
                    f.write(f"Query: {query}\n\n")
                    f.write(f"Response:\n{response}\n")
            
        except Exception as e:
            print(f"Error: {e}\n")
    
    print("\n=== Demo completed! Outputs saved for analysis ===")


if __name__ == "__main__":
    asyncio.run(main())