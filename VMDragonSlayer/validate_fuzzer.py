"""
Fuzzer Validation Runner
=========================

Run complete validation suite for the fuzzing system.
Execute all tests and benchmarks to ensure everything works.
"""

import os
import sys
import subprocess
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

def run_command(cmd, description, cwd=None):
    """Run command and return success status."""
    print(f"\n[RUN] {description}")
    print(f"[CMD] {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        if result.returncode == 0:
            print(f"[OK] {description} completed successfully")
            return True
        else:
            print(f"[FAIL] {description} failed with code {result.returncode}")
            print(f"[STDERR] {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {description} timed out")
        return False
    except Exception as e:
        print(f"[ERROR] {description} error: {e}")
        return False

def run_unit_tests():
    """Run unit tests."""
    print("\n" + "=" * 60)
    print("RUNNING UNIT TESTS")
    print("=" * 60)

    success = True

    # Test fuzzing components
    if not run_command(
        [sys.executable, "-m", "pytest", "tests/unit/test_fuzzing/test_fuzzing_components.py", "-v"],
        "Unit tests for fuzzing components"
    ):
        success = False

    return success

def run_integration_tests():
    """Run integration tests."""
    print("\n" + "=" * 60)
    print("RUNNING INTEGRATION TESTS")
    print("=" * 60)

    success = True

    # Test fuzzer validation
    if not run_command(
        [sys.executable, "tests/integration/test_fuzzer_validation.py"],
        "Fuzzer validation tests"
    ):
        success = False

    return success

def run_benchmarks():
    """Run benchmark suite."""
    print("\n" + "=" * 60)
    print("RUNNING BENCHMARKS")
    print("=" * 60)

    success = True

    # Run benchmark suite
    if not run_command(
        [sys.executable, "tests/benchmark/test_fuzzer_benchmark.py"],
        "Fuzzer benchmark suite"
    ):
        success = False

    return success

def test_example_scripts():
    """Test example scripts."""
    print("\n" + "=" * 60)
    print("TESTING EXAMPLE SCRIPTS")
    print("=" * 60)

    success = True

    examples = [
        "examples/fuzzing_example.py",
        "examples/advanced_fuzzing_example.py"
    ]

    for example in examples:
        if os.path.exists(example):
            # Test import (don't actually run fuzzing)
            if not run_command(
                [sys.executable, "-c", f"import sys; sys.path.insert(0, '.'); import {Path(example).stem}"],
                f"Import test for {example}"
            ):
                success = False
        else:
            print(f"[SKIP] {example} not found")

    return success

def validate_installation():
    """Validate that all dependencies are installed."""
    print("\n" + "=" * 60)
    print("VALIDATING INSTALLATION")
    print("=" * 60)

    success = True

    # Check Python version
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"[FAIL] Python {version.major}.{version.minor} detected, need 3.8+")
        success = False
    else:
        print(f"[OK] Python {version.major}.{version.minor}.{version.micro}")

    # Check required modules
    required_modules = [
        'pathlib',
        'dataclasses',
        'typing',
        'subprocess',
        'multiprocessing',
        'threading',
        'queue',
        'tempfile',
        'hashlib',
        'random',
        'struct',
        'time',
        'os'
    ]

    for module in required_modules:
        try:
            __import__(module)
            print(f"[OK] {module}")
        except ImportError:
            print(f"[FAIL] {module} not available")
            success = False

    # Check optional modules
    optional_modules = [
        ('pytest', 'testing'),
        ('frida', 'instrumentation'),
    ]

    for module, purpose in optional_modules:
        try:
            __import__(module)
            print(f"[OK] {module} ({purpose})")
        except ImportError:
            print(f"[WARN] {module} not available ({purpose} will be limited)")

    return success

def test_basic_functionality():
    """Test basic fuzzer functionality."""
    print("\n" + "=" * 60)
    print("TESTING BASIC FUNCTIONALITY")
    print("=" * 60)

    success = True

    try:
        from dragonslayer.fuzzing import VMFuzzer, FuzzingConfig

        # Test basic initialization
        config = FuzzingConfig(max_iterations=5)
        fuzzer = VMFuzzer(config)

        print("[OK] Fuzzer initialization")

        # Test input generation
        input_data = fuzzer.generate_input()
        if isinstance(input_data, bytes) and len(input_data) > 0:
            print(f"[OK] Input generation: {len(input_data)} bytes")
        else:
            print("[FAIL] Input generation failed")
            success = False

        # Test coverage tracking
        fuzzer.coverage_tracker.record_block(0x1000)
        coverage = fuzzer.coverage_tracker.get_coverage_set()
        if len(coverage) == 1 and 0x1000 in coverage:
            print("[OK] Coverage tracking")
        else:
            print("[FAIL] Coverage tracking failed")
            success = False

        # Test corpus management
        fuzzer.corpus_manager.add_input(b"test", {0x1000}, 0.1)
        stats = fuzzer.corpus_manager.get_stats()
        if stats['total_inputs'] == 1:
            print("[OK] Corpus management")
        else:
            print("[FAIL] Corpus management failed")
            success = False

    except Exception as e:
        print(f"[FAIL] Basic functionality test error: {e}")
        success = False

    return success

def generate_validation_report(results):
    """Generate validation report."""
    print("\n" + "=" * 80)
    print("VALIDATION REPORT")
    print("=" * 80)

    all_passed = all(results.values())

    print("Test Results:")
    for test_name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  {test_name}: {status}")

    print()
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("The VMDragonSlayer EBP fuzzer is fully functional and ready for use.")
    else:
        print("❌ SOME TESTS FAILED")
        print("Please review the errors above and fix any issues.")

    print("\nNext Steps:")
    print("1. Run 'python examples/fuzzing_example.py' to see basic usage")
    print("2. Run 'python examples/advanced_fuzzing_example.py' for advanced features")
    print("3. Check documentation/ for detailed usage guides")
    print("4. Use the fuzzer against real targets for security research")

    return all_passed

def main():
    """Run complete validation suite."""
    print("VMDragonSlayer Fuzzer Validation Suite")
    print("Testing the complete EBP fuzzing implementation")
    print()

    start_time = time.time()

    # Run all validation tests
    results = {}

    results['Installation'] = validate_installation()
    results['Basic Functionality'] = test_basic_functionality()
    results['Unit Tests'] = run_unit_tests()
    results['Integration Tests'] = run_integration_tests()
    results['Example Scripts'] = test_example_scripts()
    results['Benchmarks'] = run_benchmarks()

    end_time = time.time()

    # Generate report
    success = generate_validation_report(results)

    print(f"\nTotal validation time: {end_time - start_time:.1f} seconds")

    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
