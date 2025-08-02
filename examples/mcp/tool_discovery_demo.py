#!/usr/bin/env python3
"""Demo showing MCP tool discovery without LLM execution.

This demonstrates the successful MCP integration by showing:
1. Available tools from filesystem MCP server
2. Available tools from DuckDuckGo MCP server  
3. Tool descriptions and parameters
"""

import asyncio
import json
import os
from pathlib import Path
from deepagents_mcp import MCPToolProvider

async def main():
    """Demonstrate MCP tool discovery."""
    print("🔍 DeepAgents MCP Tool Discovery Demo")
    print("=" * 50)
    
    # Load MCP configuration from file
    config_path = Path(__file__).parent / "mcp_config.json.example"
    if not config_path.exists():
        print(f"❌ MCP config file not found: {config_path}")
        return
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    mcp_connections = config.get("mcp_servers", {})
    
    print(f"📡 Connecting to {len(mcp_connections)} MCP servers...")
    for server_name in mcp_connections.keys():
        print(f"- {server_name.title()} MCP Server")
    print()
    
    try:
        # Create MCP provider
        provider = MCPToolProvider(mcp_connections)
        
        # Load tools
        tools = await provider.get_tools()
        
        print(f"✅ Successfully loaded {len(tools)} MCP tools!")
        print()
        
        # Group tools by server (based on tool name patterns)
        filesystem_tools = [t for t in tools if any(keyword in t.name.lower() 
                           for keyword in ['read', 'write', 'list', 'create', 'delete', 'move'])]
        search_tools = [t for t in tools if any(keyword in t.name.lower() 
                       for keyword in ['search', 'query', 'find'])]
        time_tools = [t for t in tools if any(keyword in t.name.lower() 
                     for keyword in ['time', 'date', 'clock', 'timezone'])]
        build_vault_tools = [t for t in tools if any(keyword in t.name.lower() 
                           for keyword in ['product', 'speaker', 'vault', 'insight'])]
        other_tools = [t for t in tools if t not in filesystem_tools and t not in search_tools 
                      and t not in time_tools and t not in build_vault_tools]
        
        # Show filesystem tools
        if filesystem_tools:
            print("📁 Filesystem MCP Tools:")
            print("-" * 25)
            for tool in filesystem_tools:
                print(f"  • {tool.name}")
                print(f"    Description: {tool.description}")
                if hasattr(tool, 'args') and tool.args:
                    print(f"    Parameters: {list(tool.args.keys())}")
                print()
        
        # Show search tools  
        if search_tools:
            print("🔍 DuckDuckGo Search MCP Tools:")
            print("-" * 30)
            for tool in search_tools:
                print(f"  • {tool.name}")
                print(f"    Description: {tool.description}")
                if hasattr(tool, 'args') and tool.args:
                    print(f"    Parameters: {list(tool.args.keys())}")
                print()
        
        # Show time tools
        if time_tools:
            print("⏰ Time MCP Tools:")
            print("-" * 18)
            for tool in time_tools:
                print(f"  • {tool.name}")
                print(f"    Description: {tool.description}")
                if hasattr(tool, 'args') and tool.args:
                    print(f"    Parameters: {list(tool.args.keys())}")
                print()
        
        # Show build vault tools
        if build_vault_tools:
            print("🏗️  Build Vault MCP Tools:")
            print("-" * 25)
            for tool in build_vault_tools:
                print(f"  • {tool.name}")
                print(f"    Description: {tool.description}")
                if hasattr(tool, 'args') and tool.args:
                    print(f"    Parameters: {list(tool.args.keys())}")
                print()
        
        # Show other tools
        if other_tools:
            print("🛠️  Other MCP Tools:")
            print("-" * 20)
            for tool in other_tools:
                print(f"  • {tool.name}")
                print(f"    Description: {tool.description}")
                if hasattr(tool, 'args') and tool.args:
                    print(f"    Parameters: {list(tool.args.keys())}")
                print()
        
        print("🎯 Integration Status:")
        print("-" * 20)
        print("✅ MCP client connection: SUCCESS")
        print("✅ Tool discovery: SUCCESS")  
        print("✅ Tool loading: SUCCESS")
        print(f"✅ Total tools available: {len(tools)}")
        print()
        print("🚀 DeepAgents can now use these MCP tools alongside:")
        print("  • Native Python tools")
        print("  • Built-in DeepAgents tools (file system, todos)")
        print("  • LangGraph task orchestration")
        
    except Exception as e:
        print(f"❌ Error connecting to MCP servers: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())