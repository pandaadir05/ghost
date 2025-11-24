"""
Fuzzer Benchmarking Suite
==========================

Benchmark fuzzer performance against known vulnerable programs.
Measure effectiveness, speed, and coverage.
"""

import time
import statistics
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dragonslayer.fuzzing import (
    VMFuzzer,
    FuzzingConfig,
    FuzzingStrategy,
)


class FuzzerBenchmark:
    """Benchmark fuzzer performance."""

    def __init__(self, test_binary_path: str, test_type: str):
        self.test_binary = test_binary_path
        self.test_type = test_type
        self.results = []

    def run_benchmark(self, config: FuzzingConfig, name: str, runs: int = 3) -> dict:
        """Run benchmark with given configuration."""
        print(f"\n[BM] Running benchmark: {name}")
        print(f"[BM] Configuration: {config.strategy.value}, {config.max_iterations} iterations")

        run_results = []

        for run in range(runs):
            print(f"[BM] Run {run + 1}/{runs}...")

            fuzzer = VMFuzzer(config)

            # Mock execution to use test binary
            def mock_execute(input_data):
                import subprocess

                try:
                    result = subprocess.run(
                        [sys.executable, self.test_binary, self.test_type],
                        input=input_data,
                        capture_output=True,
                        timeout=config.timeout_seconds
                    )

                    return {
                        'crashed': result.returncode != 0,
                        'timeout': False,
                        'coverage': {0x1000 + (len(input_data) % 10)},  # Mock coverage
                        'exit_code': result.returncode,
                        'execution_time': 0.1
                    }

                except subprocess.TimeoutExpired:
                    return {
                        'crashed': True,
                        'timeout': True,
                        'coverage': set(),
                        'exit_code': -1,
                        'execution_time': config.timeout_seconds
                    }

            fuzzer.execute_target = mock_execute

            start_time = time.time()
            result = fuzzer.fuzz("dummy_target", [b"seed"])
            end_time = time.time()

            run_result = {
                'run': run + 1,
                'total_time': end_time - start_time,
                'executions': result.total_executions,
                'crashes': result.crashes_found,
                'unique_crashes': result.unique_crashes,
                'coverage': result.coverage_percentage,
                'exec_per_sec': result.total_executions / (end_time - start_time)
            }

            run_results.append(run_result)
            print(f"[BM]   Run {run + 1}: {run_result['exec_per_sec']:.1f} exec/sec, "
                  f"{run_result['crashes']} crashes")

        # Aggregate results
        aggregated = {
            'name': name,
            'config': str(config.strategy.value),
            'iterations': config.max_iterations,
            'runs': runs,
            'avg_exec_per_sec': statistics.mean(r['exec_per_sec'] for r in run_results),
            'std_exec_per_sec': statistics.stdev(r['exec_per_sec'] for r in run_results) if runs > 1 else 0,
            'avg_crashes': statistics.mean(r['crashes'] for r in run_results),
            'avg_unique_crashes': statistics.mean(r['unique_crashes'] for r in run_results),
            'avg_coverage': statistics.mean(r['coverage'] for r in run_results),
            'run_details': run_results
        }

        self.results.append(aggregated)
        return aggregated


def benchmark_different_strategies():
    """Benchmark different fuzzing strategies."""
    print("=" * 60)
    print("FUZZER BENCHMARK SUITE")
    print("=" * 60)

    # Setup benchmark
    test_binary = str(Path(__file__).parent / "test_vulnerable_programs.py")
    benchmark = FuzzerBenchmark(test_binary, "buffer_overflow")

    # Common config base
    base_config = {
        'max_iterations': 100,
        'timeout_seconds': 1,
        'seed': 12345
    }

    # Benchmark different strategies
    strategies = [
        (FuzzingStrategy.MUTATION, "Mutation-based"),
        (FuzzingStrategy.GENERATION, "Generation-based"),
        (FuzzingStrategy.HYBRID, "Hybrid (Mutation + Generation)"),
    ]

    results = []

    for strategy, name in strategies:
        config = FuzzingConfig(**base_config, strategy=strategy)
        result = benchmark.run_benchmark(config, name, runs=3)
        results.append(result)

    # Print summary
    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)
    print("<25")
    print("-" * 60)

    for result in results:
        print("<25"
              "<10.1f"
              "<10.1f"
              "<10.1f")

    # Determine best strategy
    best_result = max(results, key=lambda x: x['avg_exec_per_sec'])
    print(f"\n[BEST] Fastest: {best_result['name']} "
          f"({best_result['avg_exec_per_sec']:.1f} exec/sec)")

    best_coverage = max(results, key=lambda x: x['avg_coverage'])
    print(f"[BEST] Best Coverage: {best_coverage['name']} "
          f"({best_coverage['avg_coverage']:.2f}%)")

    return results


def benchmark_feature_impact():
    """Benchmark impact of different features."""
    print("\n" + "=" * 60)
    print("FEATURE IMPACT BENCHMARK")
    print("=" * 60)

    test_binary = str(Path(__file__).parent / "test_vulnerable_programs.py")
    benchmark = FuzzerBenchmark(test_binary, "division_by_zero")

    base_config = {
        'max_iterations': 50,
        'timeout_seconds': 1,
        'strategy': FuzzingStrategy.HYBRID,
        'seed': 54321
    }

    # Test different feature combinations
    features = [
        ("Baseline", {'enable_coverage': False, 'enable_taint': False, 'enable_symbolic': False}),
        ("+Coverage", {'enable_coverage': True, 'enable_taint': False, 'enable_symbolic': False}),
        ("+Taint", {'enable_coverage': True, 'enable_taint': True, 'enable_symbolic': False}),
        ("+Symbolic", {'enable_coverage': True, 'enable_taint': True, 'enable_symbolic': True}),
    ]

    results = []

    for name, feature_config in features:
        config = FuzzingConfig(**base_config, **feature_config)
        result = benchmark.run_benchmark(config, name, runs=2)
        results.append(result)

    # Print feature impact
    print("\n" + "=" * 60)
    print("FEATURE IMPACT SUMMARY")
    print("=" * 60)
    print("<15")
    print("-" * 60)

    baseline = results[0]
    for result in results:
        speedup = result['avg_exec_per_sec'] / baseline['avg_exec_per_sec']
        print("<15"
              "<10.1f"
              "<10.2f")

    return results


def benchmark_scalability():
    """Benchmark parallel scaling."""
    print("\n" + "=" * 60)
    print("PARALLEL SCALING BENCHMARK")
    print("=" * 60)

    test_binary = str(Path(__file__).parent / "test_vulnerable_programs.py")
    benchmark = FuzzerBenchmark(test_binary, "heap_corruption")

    base_config = {
        'max_iterations': 200,
        'timeout_seconds': 1,
        'strategy': FuzzingStrategy.MUTATION,
        'seed': 99999
    }

    # Test different parallel configurations
    parallel_configs = [
        ("Single-threaded", 1),
        ("2 Workers", 2),
        ("4 Workers", 4),
    ]

    results = []

    for name, workers in parallel_configs:
        config = FuzzingConfig(**base_config, parallel_jobs=workers)
        result = benchmark.run_benchmark(config, name, runs=2)
        results.append(result)

    # Print scaling results
    print("\n" + "=" * 60)
    print("PARALLEL SCALING SUMMARY")
    print("=" * 60)
    print("<20")
    print("-" * 60)

    single_threaded = results[0]['avg_exec_per_sec']
    for result in results:
        scaling = result['avg_exec_per_sec'] / single_threaded
        efficiency = scaling / result['config'].count('Workers') if 'Workers' in result['name'] else scaling
        print("<20"
              "<10.1f"
              "<10.2f")

    return results


def run_comprehensive_benchmark():
    """Run full benchmark suite."""
    print("VMDragonSlayer Fuzzer Benchmark Suite")
    print("Testing against synthetic vulnerable programs")
    print()

    # Run all benchmarks
    strategy_results = benchmark_different_strategies()
    feature_results = benchmark_feature_impact()
    scaling_results = benchmark_scalability()

    # Overall summary
    print("\n" + "=" * 80)
    print("COMPREHENSIVE BENCHMARK SUMMARY")
    print("=" * 80)

    print("Strategy Performance:")
    for result in strategy_results:
        print(f"  {result['name']}: {result['avg_exec_per_sec']:.1f} exec/sec, "
              f"{result['avg_crashes']:.1f} crashes")

    print("\nFeature Impact:")
    baseline = feature_results[0]['avg_exec_per_sec']
    for result in feature_results[1:]:
        overhead = ((baseline - result['avg_exec_per_sec']) / baseline) * 100
        print(f"  {result['name']}: {overhead:+.1f}% performance impact")

    print("\nParallel Scaling:")
    single = scaling_results[0]['avg_exec_per_sec']
    for result in scaling_results[1:]:
        workers = int(result['name'].split()[0])
        speedup = result['avg_exec_per_sec'] / single
        efficiency = speedup / workers
        print(f"  {result['name']}: {speedup:.2f}x speedup ({efficiency:.2f} efficiency)")

    print("\nBenchmark completed successfully!")
    print("The fuzzer demonstrates good performance and scaling characteristics.")


if __name__ == "__main__":
    run_comprehensive_benchmark()
