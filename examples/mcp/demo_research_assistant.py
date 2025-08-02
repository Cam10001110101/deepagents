#!/usr/bin/env python3
"""MCP Demo: Research Assistant with Web Tools

This example demonstrates:
- Using search and content aggregation tools
- Building a research workflow
- Synthesizing information from multiple sources
"""

import asyncio
from deepagents import create_deep_agent_async


async def main():
    """Demonstrate research assistant capabilities with MCP tools."""
    print("=== MCP Demo: Research Assistant ===\n")
    
    # Configure MCP connections for research
    mcp_connections = {
        "duckduckgo": {
            "command": "uvx",
            "args": ["duckduckgo-mcp-server"],
            "transport": "stdio"
        },
        "build-vault": {
            "command": "npx",
            "args": ["-y", "mcp-remote", "https://mcp.buildaipod.com/mcp"],
            "transport": "stdio"
        }
    }
    
    # Create specialized research agent
    agent = await create_deep_agent_async(
        tools=[],
        instructions="""You are an AI research specialist with expertise in:
- Technology trends and innovations
- Startup ecosystem analysis
- Developer tools and practices
- AI/ML applications and use cases

Your research approach:
1. Search for current information using DuckDuckGo
2. Find relevant insights from Build Vault (AI/startup knowledge)
3. Synthesize findings into actionable insights
4. Identify patterns and emerging trends
5. Provide evidence-based recommendations

Structure your responses with:
- Executive Summary
- Key Findings
- Supporting Evidence
- Recommendations
- Sources/References""",
        mcp_connections=mcp_connections,
        subagents=[{
            "name": "deep-researcher",
            "description": "Specialized researcher for in-depth analysis",
            "prompt": "Focus on finding peer-reviewed sources, technical documentation, and expert opinions. Prioritize accuracy and depth over breadth."
        }]
    )
    
    # Research queries
    queries = [
        "Research the current state of Model Context Protocol (MCP) adoption in AI applications. What are the main use cases and who are the key players?",
        
        "Analyze the intersection of LangGraph and MCP technologies. How are they being used together in production systems?",
        
        "What are the emerging security challenges in AI agent systems, and what solutions are being developed? Focus on authentication and data privacy.",
        
        "Research the future of AI agent orchestration: What patterns and architectures are gaining traction in 2024-2025?"
    ]
    
    print("Starting AI research tasks...\n")
    
    for i, query in enumerate(queries, 1):
        print(f"[Research Topic {i}] {query}")
        print("=" * 80)
        
        try:
            result = await agent.ainvoke({
                "messages": [{"role": "user", "content": query}]
            })
            
            if result.get("messages"):
                response = result["messages"][-1].content
                print(f"\n{response}\n")
                
                # Save detailed research report
                with open(f"output_demo4_research{i}.md", "w") as f:
                    f.write(f"# Research Report {i}\n\n")
                    f.write(f"## Query\n{query}\n\n")
                    f.write(f"## Research Findings\n{response}\n")
            
        except Exception as e:
            print(f"Error during research: {e}\n")
    
    print("\n=== Research completed! Reports saved as Markdown files ===")


if __name__ == "__main__":
    asyncio.run(main())