"""
Example Fuzzing Script
=======================

Demonstrate how to use VMDragonSlayer fuzzer.
This show complete workflow from setup to result analysis.
"""

import os
import sys
import argparse
from pathlib import Path

# Add dragonslayer to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dragonslayer.fuzzing import (
    VMFuzzer,
    FuzzingConfig,
    FuzzingStrategy,
)


def main():
    """Main fuzzing example."""
    
    parser = argparse.ArgumentParser(description="VMDragonSlayer EBP Fuzzer")
    parser.add_argument("target", help="Target binary to fuzz")
    parser.add_argument("--iterations", type=int, default=10000, help="Max iterations")
    parser.add_argument("--timeout", type=int, default=5, help="Execution timeout in seconds")
    parser.add_argument("--strategy", choices=["generation", "mutation", "hybrid"], default="hybrid", help="Fuzzing strategy")
    parser.add_argument("--corpus-dir", default="output/corpus", help="Corpus directory")
    parser.add_argument("--crash-dir", default="output/crashes", help="Crash directory")
    parser.add_argument("--seed", type=int, default=12345, help="Random seed")
    parser.add_argument("--enable-taint", action="store_true", help="Enable taint tracking")
    parser.add_argument("--enable-symbolic", action="store_true", help="Enable symbolic execution")
    parser.add_argument("--ebpf", action="store_true", help="Generate eBPF bytecode instead of random data")
    parser.add_argument("--ebpf-instructions", type=int, default=10, help="Number of eBPF instructions to generate")
    
    args = parser.parse_args()
    
    print("[*] VMDragonSlayer EBP Fuzzer")
    print("[*] This demonstrate VM-aware fuzzing capability")
    print()
    
    target_path = args.target
    
    if not os.path.exists(target_path):
        print(f"[!] Target not found: {target_path}")
        print("[!] Please provide valid target binary")
        return
    
    # Create fuzzing configuration
    config = FuzzingConfig(
        max_iterations=args.iterations,
        timeout_seconds=args.timeout,
        strategy=FuzzingStrategy.HYBRID if args.strategy == "hybrid" else FuzzingStrategy.GENERATION if args.strategy == "generation" else FuzzingStrategy.MUTATION,
        enable_coverage=True,
        enable_taint=args.enable_taint,
        enable_symbolic=args.enable_symbolic,
        enable_ebpf=args.ebpf,
        ebpf_instructions=args.ebpf_instructions,
        crash_dir=args.crash_dir,
        corpus_dir=args.corpus_dir,
        seed=args.seed
    )
    
    print(f"[*] Configuration:")
    print(f"    Iterations: {config.max_iterations}")
    print(f"    Timeout: {config.timeout_seconds}s")
    print(f"    Strategy: {config.strategy.value}")
    print(f"    Coverage: {config.enable_coverage}")
    print(f"    Taint: {config.enable_taint}")
    print(f"    Symbolic: {config.enable_symbolic}")
    print(f"    eBPF Mode: {config.enable_ebpf}")
    if config.enable_ebpf:
        print(f"    eBPF Instructions: {config.ebpf_instructions}")
    print(f"    Target: {target_path}")
    print()
    
    # Create fuzzer
    fuzzer = VMFuzzer(config)
    
    # Prepare initial corpus (seed input)
    initial_corpus = []
    if args.ebpf:
        # Generate eBPF bytecode seeds
        for i in range(4):
            ebpf_code = fuzzer.input_generator.generate_ebpf(args.ebpf_instructions + i)
            initial_corpus.append(ebpf_code)
    else:
        initial_corpus = [
            b"GET / HTTP/1.1\r\n\r\n",
            b"POST /api HTTP/1.1\r\n\r\n",
            b"\x00\x01\x02\x03\x04\x05",
            b"A" * 100,
        ]
    
    print(f"[*] Initial corpus: {len(initial_corpus)} seed")
    print()
    
    # Run fuzzing
    print("[*] Starting fuzzing session...")
    print("[*] Press Ctrl+C to stop early")
    print()
    
    try:
        result = fuzzer.fuzz(
            target_path=target_path,
            initial_corpus=initial_corpus,
            delivery_method='stdin'
        )
        
        # Display result
        print()
        print("[+] Fuzzing complete!")
        print()
        print("=" * 60)
        print("RESULTS")
        print("=" * 60)
        print(f"Total iterations:     {result.iterations}")
        print(f"Total executions:     {result.total_executions}")
        print(f"Crashes found:        {result.crashes_found}")
        print(f"Unique crashes:       {result.unique_crashes}")
        print(f"Timeouts:             {result.timeouts}")
        print(f"Coverage:             {result.coverage_percentage:.2f}%")
        print(f"Execution time:       {result.execution_time:.2f}s")
        print(f"Exec/sec:             {result.total_executions / result.execution_time:.2f}")
        print("=" * 60)
        print()
        
        # Get statistics
        stats = fuzzer.get_statistics()
        
        if stats['vm_detected']:
            print("[+] VM Protection Detected!")
            print(f"    VM Handlers: {stats['vm_handlers']}")
            print()
        
        print(f"Corpus size:          {stats['corpus_size']}")
        print()
        
        # Display crash detail if any
        if result.crashes_found > 0:
            print("[+] Crash Details:")
            print()
            
            for i, crash in enumerate(result.crash_details[:5], 1):
                print(f"  Crash #{i}:")
                for key, value in crash.items():
                    print(f"    {key}: {value}")
                print()
            
            if result.crashes_found > 5:
                print(f"  ... and {result.crashes_found - 5} more crash")
                print()
            
            print(f"[+] Crash input saved to: {config.crash_dir}")
            print()
        
        print(f"[+] Corpus saved to: {config.corpus_dir}")
        print()
        print("[*] Done!")
        
    except KeyboardInterrupt:
        print()
        print("[!] Fuzzing interrupted by user")
        print()
        
        # Get partial result
        stats = fuzzer.get_statistics()
        print(f"Partial results:")
        print(f"  Iterations: {stats['iterations']}")
        print(f"  Crashes: {stats['crashes']}")
        print(f"  Unique crashes: {stats['unique_crashes']}")


if __name__ == "__main__":
    main()
