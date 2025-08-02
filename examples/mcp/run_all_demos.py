#!/usr/bin/env python3
"""Run all MCP demo examples and collect outputs for analysis."""

import subprocess
import sys
import os
from pathlib import Path
import json
import datetime


def run_demo(script_name: str, demo_number: int) -> dict:
    """Run a demo script and capture output."""
    print(f"\n{'='*60}")
    print(f"Running Demo {demo_number}: {script_name}")
    print(f"{'='*60}\n")
    
    start_time = datetime.datetime.now()
    
    try:
        # Run the demo script
        result = subprocess.run(
            [sys.executable, script_name],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )
        
        end_time = datetime.datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Collect output files
        output_files = list(Path.cwd().glob(f"output_demo{demo_number}_*.txt"))
        output_files.extend(Path.cwd().glob(f"output_demo{demo_number}_*.md"))
        
        return {
            "script": script_name,
            "success": result.returncode == 0,
            "duration": duration,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "output_files": [str(f) for f in output_files],
            "timestamp": start_time.isoformat()
        }
        
    except Exception as e:
        return {
            "script": script_name,
            "success": False,
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }


def main():
    """Run all demo scripts and save results."""
    print("🚀 Running All MCP Demo Examples")
    print("================================\n")
    
    # Demo scripts to run
    demos = [
        ("demo_filesystem_search.py", 1),
        ("demo_github_analysis.py", 2),
        ("demo_multi_server.py", 3),
        ("demo_research_assistant.py", 4),
        ("demo_secure_execution.py", 5)
    ]
    
    # Create output directory
    output_dir = Path("demo_outputs")
    output_dir.mkdir(exist_ok=True)
    
    # Run each demo
    results = []
    for script, number in demos:
        if Path(script).exists():
            result = run_demo(script, number)
            results.append(result)
            
            # Save individual demo output
            with open(output_dir / f"demo{number}_log.json", "w") as f:
                json.dump(result, f, indent=2)
        else:
            print(f"⚠️  Demo script not found: {script}")
    
    # Summary report
    print("\n" + "="*60)
    print("📊 Demo Execution Summary")
    print("="*60)
    
    for i, result in enumerate(results, 1):
        status = "✅ Success" if result.get("success") else "❌ Failed"
        duration = result.get("duration", "N/A")
        if isinstance(duration, float):
            duration = f"{duration:.2f}s"
        
        print(f"\nDemo {i}: {result['script']}")
        print(f"  Status: {status}")
        print(f"  Duration: {duration}")
        print(f"  Output files: {len(result.get('output_files', []))}")
        
        if not result.get("success"):
            if result.get("error"):
                print(f"  Error: {result['error']}")
            elif result.get("stderr"):
                print(f"  Stderr: {result['stderr'][:200]}...")
    
    # Save combined results
    with open(output_dir / "all_demos_results.json", "w") as f:
        json.dump({
            "run_timestamp": datetime.datetime.now().isoformat(),
            "demos": results,
            "summary": {
                "total": len(results),
                "successful": sum(1 for r in results if r.get("success")),
                "failed": sum(1 for r in results if not r.get("success"))
            }
        }, f, indent=2)
    
    print(f"\n✅ All demos completed!")
    print(f"📁 Results saved to: {output_dir}/")
    print("\nNext steps:")
    print("1. Review individual output files (output_demo*.txt)")
    print("2. Check demo_outputs/ for execution logs")
    print("3. Use LangSmith tools to analyze the outputs")


if __name__ == "__main__":
    main()