"""
Advanced Fuzzing Example
=========================

Demonstrate advanced fuzzing feature:
- Parallel execution
- Network fuzzing
- Protocol-aware fuzzing
- Distributed fuzzing
"""

import os
import sys
from pathlib import Path

# Add dragonslayer to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dragonslayer.fuzzing import (
    VMFuzzer,
    FuzzingConfig,
    FuzzingStrategy,
    NetworkFuzzer,
    NetworkTarget,
    ProtocolFuzzer,
    DistributedFuzzer,
)


def example_parallel_fuzzing():
    """Example of parallel fuzzing."""
    print("=" * 60)
    print("PARALLEL FUZZING EXAMPLE")
    print("=" * 60)
    
    target_path = "target.exe"  # Replace with real target
    
    if not os.path.exists(target_path):
        print(f"[!] Target not found: {target_path}")
        print("[!] Skipping parallel fuzzing example")
        return
        
    # Configuration with parallel execution
    config = FuzzingConfig(
        max_iterations=5000,
        timeout_seconds=3,
        strategy=FuzzingStrategy.HYBRID,
        enable_coverage=True,
        enable_taint=True,
        enable_symbolic=False,  # Symbolic can be slow in parallel
        parallel_jobs=4,  # Use 4 cores
        crash_dir="output/parallel_crashes",
        corpus_dir="output/parallel_corpus",
        seed=12345
    )
    
    print(f"[*] Parallel fuzzing with {config.parallel_jobs} worker")
    print(f"[*] Iterations: {config.max_iterations}")
    print()
    
    # Create fuzzer
    fuzzer = VMFuzzer(config)
    
    # Initial corpus
    initial_corpus = [
        b"GET / HTTP/1.1\r\n\r\n",
        b"POST /api HTTP/1.1\r\n\r\n",
        b"A" * 100,
        b"\x00\x01\x02\x03",
    ]
    
    print(f"[*] Initial corpus: {len(initial_corpus)} seed")
    print("[*] Press Ctrl+C to stop early")
    print()
    
    try:
        # Use parallel fuzzing
        result = fuzzer.fuzz_parallel(
            target_path=target_path,
            initial_corpus=initial_corpus,
            delivery_method='stdin'
        )
        
        print()
        print("PARALLEL FUZZING RESULTS")
        print("=" * 40)
        print(f"Total iterations:     {result.iterations}")
        print(f"Crashes found:        {result.crashes_found}")
        print(f"Unique crashes:       {result.unique_crashes}")
        print(f"Coverage:             {result.coverage_percentage:.2f}%")
        print(f"Execution time:       {result.execution_time:.2f}s")
        print(f"Exec/sec:             {result.total_executions / result.execution_time:.2f}")
        print(f"Parallel speedup:      ~{config.parallel_jobs}x (theoretical)")
        
    except KeyboardInterrupt:
        print()
        print("[!] Parallel fuzzing interrupted")


def example_network_fuzzing():
    """Example of network fuzzing."""
    print("\n" + "=" * 60)
    print("NETWORK FUZZING EXAMPLE")
    print("=" * 60)
    
    # Target configuration
    target = NetworkTarget(
        host="127.0.0.1",
        port=8080,
        protocol="tcp",
        timeout=2.0
    )
    
    print(f"[*] Target: {target.host}:{target.port} ({target.protocol.upper()})")
    print("[*] This example assume a test server is running")
    print()
    
    # Create network fuzzer
    fuzzer = NetworkFuzzer(target)
    
    # Establish baseline with normal input
    normal_inputs = [
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    ]
    
    fuzzer.establish_baseline(normal_inputs)
    
    # Test some fuzz input
    fuzz_inputs = [
        b"GET /../../../etc/passwd HTTP/1.1\r\n\r\n",
        b"A" * 1000 + b" HTTP/1.1\r\n\r\n",
        b"\x00\x01\x02\x03" * 100,
    ]
    
    print("[*] Testing fuzz input:")
    
    for i, input_data in enumerate(fuzz_inputs, 1):
        result = fuzzer.execute_network_input(input_data)
        
        status = "CRASH" if result.crashed else "OK"
        print(f"  Input {i}: {status} ({result.execution_time:.3f}s)")
        
        if result.crashed:
            print(f"    Crash type: {result.crash_info.get('type', 'unknown')}")


def example_protocol_fuzzing():
    """Example of protocol-aware fuzzing."""
    print("\n" + "=" * 60)
    print("PROTOCOL-AWARE FUZZING EXAMPLE")
    print("=" * 60)
    
    # HTTP target
    target = NetworkTarget("127.0.0.1", 8080)
    fuzzer = ProtocolFuzzer(target, "http")
    
    print("[*] HTTP Protocol Fuzzing")
    print("[*] Generating protocol-aware fuzz input:")
    print()
    
    # Template HTTP request
    template = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    
    # Generate some fuzz input
    for i in range(5):
        fuzz_input = fuzzer.generate_protocol_input(template, mutate=True)
        print(f"Fuzz Input {i+1}:")
        print(fuzz_input.decode('utf-8', errors='replace'))
        print()


def example_distributed_fuzzing():
    """Example of distributed fuzzing setup."""
    print("\n" + "=" * 60)
    print("DISTRIBUTED FUZZING EXAMPLE")
    print("=" * 60)
    
    # Start coordinator
    coordinator = DistributedFuzzer(coordinator_host="0.0.0.0", coordinator_port=9999)
    
    print("[*] Starting distributed fuzzing coordinator")
    print("[*] Workers can connect to share corpus and result")
    print("[*] Press Ctrl+C to stop")
    print()
    
    try:
        coordinator.start_coordinator()
        
        # Keep running
        while True:
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        print()
        print("[!] Coordinator stopped")


def main():
    """Run all advanced examples."""
    print("[*] VMDragonSlayer Advanced Fuzzing Examples")
    print("[*] These demonstrate parallel, network, and distributed fuzzing")
    print()
    
    # Run examples
    example_parallel_fuzzing()
    example_network_fuzzing()
    example_protocol_fuzzing()
    
    # Distributed example (commented out as it run indefinitely)
    # example_distributed_fuzzing()
    
    print("\n[*] All examples completed!")


if __name__ == "__main__":
    main()
