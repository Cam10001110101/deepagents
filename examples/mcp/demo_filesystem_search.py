#!/usr/bin/env python3
"""MCP Demo: Filesystem + Search Combination

This example demonstrates:
- Using filesystem MCP server to read project files
- Using search MCP server to find relevant information
- Combining multiple MCP tools for code analysis
"""

import asyncio
import os
from pathlib import Path
from deepagents import create_deep_agent_async


async def main():
    """Demonstrate filesystem + search MCP tools working together."""
    print("=== MCP Demo: Filesystem + Search Combination ===\n")
    
    # Configure MCP connections
    mcp_connections = {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", str(Path.cwd())],
            "transport": "stdio"
        },
        "duckduckgo": {
            "command": "uvx",
            "args": ["duckduckgo-mcp-server"],
            "transport": "stdio"
        }
    }
    
    # Create agent with specific instructions
    agent = await create_deep_agent_async(
        tools=[],
        instructions="""You are a code analysis assistant with access to:
- Filesystem tools to read and explore project files
- Search tools to find relevant information online

Your task is to:
1. Analyze code structure and patterns
2. Search for best practices and improvements
3. Provide actionable recommendations

Be thorough but concise in your analysis.""",
        mcp_connections=mcp_connections
    )
    
    # Test queries
    queries = [
        "List all Python files in the current directory and identify the main modules",
        "Read the pyproject.toml file and summarize the project dependencies",
        "Search for best practices for Python project structure and compare with this project",
        "Analyze the README.md file and suggest improvements based on popular open source projects"
    ]
    
    print("Running filesystem + search analysis...\n")
    
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
                with open(f"output_demo1_query{i}.txt", "w") as f:
                    f.write(f"Query: {query}\n\n")
                    f.write(f"Response:\n{response}\n")
            
        except Exception as e:
            print(f"Error: {e}\n")
    
    print("\n=== Demo completed! Outputs saved for analysis ===")


if __name__ == "__main__":
    asyncio.run(main())