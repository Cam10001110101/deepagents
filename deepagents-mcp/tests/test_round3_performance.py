#!/usr/bin/env python3
"""Test Round 3: Performance and Stress Testing

Tests for performance characteristics and stress conditions.
"""

import asyncio
import time
import json
import statistics
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
from deepagents_mcp.protocol_compliance import MCPProtocolValidator
from deepagents_mcp.jsonrpc_validation import JSONRPCValidator
from deepagents_mcp.tool_output_validation import validate_tool_output


class TestValidationPerformance:
    """Test validation performance under load."""
    
    def test_protocol_validation_speed(self):
        """Test protocol validation performance."""
        validator = MCPProtocolValidator()
        headers = {"MCP-Protocol-Version": "2025-06-18"}
        
        # Warm up
        for _ in range(10):
            validator.validate_http_headers(headers)
        
        # Measure performance
        iterations = 10000
        start = time.time()
        
        for _ in range(iterations):
            result = validator.validate_http_headers(headers)
        
        duration = time.time() - start
        ops_per_second = iterations / duration
        
        print(f"✅ Protocol validation: {ops_per_second:.0f} ops/sec")
        assert ops_per_second > 1000, f"Too slow: {ops_per_second} ops/sec"
        
        return ops_per_second
    
    def test_json_rpc_validation_speed(self):
        """Test JSON-RPC validation performance."""
        validator = JSONRPCValidator()
        message = {
            "jsonrpc": "2.0",
            "method": "tools/execute",
            "params": {"tool": "test", "args": {}},
            "id": 1
        }
        
        # Measure performance
        iterations = 10000
        start = time.time()
        
        for _ in range(iterations):
            result = validator.validate_message(message)
        
        duration = time.time() - start
        ops_per_second = iterations / duration
        
        print(f"✅ JSON-RPC validation: {ops_per_second:.0f} ops/sec")
        assert ops_per_second > 1000, f"Too slow: {ops_per_second} ops/sec"
        
        return ops_per_second
    
    def test_output_validation_speed(self):
        """Test output validation performance."""
        content = [{
            "type": "text",
            "text": "This is a test message with some content to validate"
        }]
        
        # Measure performance
        iterations = 5000
        start = time.time()
        
        for _ in range(iterations):
            result = validate_tool_output(content)
        
        duration = time.time() - start
        ops_per_second = iterations / duration
        
        print(f"✅ Output validation: {ops_per_second:.0f} ops/sec")
        assert ops_per_second > 500, f"Too slow: {ops_per_second} ops/sec"
        
        return ops_per_second


class TestConcurrentLoad:
    """Test behavior under concurrent load."""
    
    async def test_concurrent_validations(self):
        """Test concurrent validation requests."""
        validator = MCPProtocolValidator()
        headers = {"MCP-Protocol-Version": "2025-06-18"}
        
        # Test with multiple concurrent workers
        async def validate_batch():
            results = []
            for _ in range(100):
                result = validator.validate_http_headers(headers)
                results.append(result.compliant)
            return results
        
        # Run concurrent batches
        tasks = [validate_batch() for _ in range(10)]
        start = time.time()
        
        all_results = await asyncio.gather(*tasks)
        
        duration = time.time() - start
        total_validations = sum(len(r) for r in all_results)
        
        print(f"✅ Concurrent validations: {total_validations} in {duration:.2f}s")
        
        # Verify all succeeded
        assert all(all(r) for r in all_results), "Some validations failed"
        
        return total_validations / duration
    
    def test_thread_safety(self):
        """Test thread safety of validators."""
        validator = JSONRPCValidator()
        message = {"jsonrpc": "2.0", "method": "test", "id": 1}
        
        results = []
        errors = []
        
        def validate_in_thread():
            try:
                for _ in range(100):
                    result = validator.validate_message(message)
                    results.append(result.valid)
            except Exception as e:
                errors.append(str(e))
        
        # Run in multiple threads
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(validate_in_thread) for _ in range(10)]
            for future in futures:
                future.result()
        
        print(f"✅ Thread safety test: {len(results)} validations, {len(errors)} errors")
        assert len(errors) == 0, f"Thread safety errors: {errors}"
        
        return len(results)


class TestMemoryEfficiency:
    """Test memory efficiency under load."""
    
    def test_validation_memory_stability(self):
        """Test memory usage remains stable."""
        import gc
        import sys
        
        # Force garbage collection
        gc.collect()
        
        # Get baseline memory
        baseline_objects = len(gc.get_objects())
        
        # Perform many validations
        validator = MCPProtocolValidator()
        for i in range(1000):
            headers = {"MCP-Protocol-Version": "2025-06-18", f"X-Test-{i}": str(i)}
            result = validator.validate_http_headers(headers)
        
        # Force garbage collection again
        gc.collect()
        
        # Check memory growth
        final_objects = len(gc.get_objects())
        growth = final_objects - baseline_objects
        
        print(f"✅ Memory test: {growth} objects growth after 1000 validations")
        assert growth < 1000, f"Excessive memory growth: {growth} objects"
        
        return growth
    
    def test_large_payload_handling(self):
        """Test handling of large payloads."""
        # Create progressively larger payloads
        sizes = [1_000, 10_000, 100_000, 500_000]
        times = []
        
        for size in sizes:
            content = [{
                "type": "text",
                "text": "A" * size
            }]
            
            start = time.time()
            result = validate_tool_output(content)
            duration = time.time() - start
            times.append(duration)
            
            print(f"  - {size:,} bytes: {duration:.3f}s")
        
        # Check for linear scaling
        # Time should not grow exponentially with size
        time_ratio = times[-1] / times[0]
        size_ratio = sizes[-1] / sizes[0]
        
        print(f"✅ Large payload test: time grew {time_ratio:.1f}x for {size_ratio}x size")
        assert time_ratio < size_ratio * 2, "Non-linear performance degradation"
        
        return times


class TestEdgeConditions:
    """Test behavior at edge conditions."""
    
    def test_rapid_protocol_switches(self):
        """Test rapid protocol version switches."""
        validator = MCPProtocolValidator()
        versions = ["2025-06-18", "2025-03-26", "2025-06-18", "2025-03-26"]
        
        switch_times = []
        for _ in range(100):
            for version in versions:
                start = time.time()
                result = validator.validate_http_headers({"MCP-Protocol-Version": version})
                switch_times.append(time.time() - start)
        
        avg_time = statistics.mean(switch_times)
        print(f"✅ Protocol switch test: avg {avg_time*1000:.2f}ms per switch")
        
        return avg_time
    
    async def test_connection_limits(self):
        """Test connection limit handling."""
        from deepagents_mcp.mcp_client import MCPToolProvider
        
        # Try to create many connections
        connection_counts = [1, 5, 10, 20]
        results = []
        
        for count in connection_counts:
            connections = {
                f"echo_{i}": {
                    "command": "echo",
                    "args": [f"server_{i}"],
                    "transport": "stdio"
                }
                for i in range(count)
            }
            
            try:
                start = time.time()
                provider = MCPToolProvider(connections=connections)
                duration = time.time() - start
                results.append((count, duration, "success"))
                print(f"  - {count} connections: {duration:.2f}s")
            except Exception as e:
                results.append((count, 0, str(e)))
                print(f"  - {count} connections: failed - {e}")
        
        print(f"✅ Connection limit test completed")
        return results


def run_performance_tests():
    """Run all performance and stress tests."""
    print("=== Test Round 3: Performance and Stress Testing ===\n")
    
    test_results = {
        "validation_performance": {},
        "concurrent_load": {},
        "memory_efficiency": {},
        "edge_conditions": {}
    }
    
    # Run validation performance tests
    print("Testing Validation Performance:")
    print("-" * 50)
    perf_test = TestValidationPerformance()
    test_results["validation_performance"] = {
        "protocol": perf_test.test_protocol_validation_speed(),
        "json_rpc": perf_test.test_json_rpc_validation_speed(),
        "output": perf_test.test_output_validation_speed()
    }
    
    # Run concurrent load tests
    print("\nTesting Concurrent Load:")
    print("-" * 50)
    load_test = TestConcurrentLoad()
    test_results["concurrent_load"] = {
        "concurrent_validations": asyncio.run(load_test.test_concurrent_validations()),
        "thread_safety": load_test.test_thread_safety()
    }
    
    # Run memory efficiency tests
    print("\nTesting Memory Efficiency:")
    print("-" * 50)
    mem_test = TestMemoryEfficiency()
    test_results["memory_efficiency"] = {
        "stability": mem_test.test_validation_memory_stability(),
        "large_payloads": mem_test.test_large_payload_handling()
    }
    
    # Run edge condition tests
    print("\nTesting Edge Conditions:")
    print("-" * 50)
    edge_test = TestEdgeConditions()
    test_results["edge_conditions"] = {
        "protocol_switches": edge_test.test_rapid_protocol_switches(),
        "connection_limits": asyncio.run(edge_test.test_connection_limits())
    }
    
    # Performance summary
    print("\n" + "="*50)
    print("Performance Test Summary")
    print("="*50)
    
    print("\nValidation Performance:")
    for name, ops in test_results["validation_performance"].items():
        print(f"  - {name}: {ops:,.0f} ops/sec")
    
    print("\nConcurrent Performance:")
    print(f"  - Concurrent validations: {test_results['concurrent_load']['concurrent_validations']:,.0f} ops/sec")
    print(f"  - Thread-safe operations: {test_results['concurrent_load']['thread_safety']}")
    
    print("\nMemory Efficiency:")
    print(f"  - Object growth: {test_results['memory_efficiency']['stability']} objects")
    
    print("\nPerformance Recommendations:")
    print("1. Consider caching validation results for repeated headers")
    print("2. Implement connection pooling for MCP servers")
    print("3. Add rate limiting to prevent resource exhaustion")
    print("4. Monitor memory usage in production environments")
    print("5. Set appropriate timeouts for all operations")
    
    # Save detailed results
    with open("performance_test_results.json", "w") as f:
        json.dump(test_results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: performance_test_results.json")
    
    return test_results


if __name__ == "__main__":
    results = run_performance_tests()