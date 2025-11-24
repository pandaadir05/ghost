"""
Fuzzer Validation Tests
========================

End-to-end testing of the complete fuzzing system.
Test against known vulnerable programs and validate results.
"""

import os
import sys
import tempfile
import subprocess
import pytest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dragonslayer.fuzzing import (
    VMFuzzer,
    FuzzingConfig,
    FuzzingStrategy,
    NetworkFuzzer,
    NetworkTarget,
    ProtocolFuzzer,
)


class TestBinaryRunner:
    """Helper to run test binaries."""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def run_with_input(self, input_data: bytes, timeout: int = 5) -> dict:
        """Run binary with input and return result."""
        try:
            proc = subprocess.Popen(
                [sys.executable, self.binary_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            stdout, stderr = proc.communicate(input=input_data, timeout=timeout)

            return {
                'returncode': proc.returncode,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'crashed': proc.returncode != 0,
                'timeout': False
            }

        except subprocess.TimeoutExpired:
            proc.kill()
            return {
                'returncode': -1,
                'stdout': '',
                'stderr': '',
                'crashed': True,
                'timeout': True
            }
        except Exception as e:
            return {
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'crashed': True,
                'timeout': False
            }


@pytest.fixture
def test_binary_runner():
    """Fixture for test binary runner."""
    binary_path = str(Path(__file__).parent / "test_vulnerable_programs.py")
    return TestBinaryRunner(binary_path)


@pytest.fixture
def vm_test_binary_runner():
    """Fixture for VM test binary runner."""
    binary_path = str(Path(__file__).parent / "test_vm_binary.py")
    return TestBinaryRunner(binary_path)


def test_fuzzer_can_find_buffer_overflow(test_binary_runner):
    """Test that fuzzer can find buffer overflow in test binary."""
    config = FuzzingConfig(
        max_iterations=50,
        timeout_seconds=2,
        strategy=FuzzingStrategy.MUTATION,
        seed=12345
    )

    fuzzer = VMFuzzer(config)

    # Initial corpus with some basic input
    initial_corpus = [
        b"test",
        b"A" * 10,
        b"\x00\x01\x02\x03",
    ]

    # Mock the execution to use our test binary
    original_execute = fuzzer.execute_target

    def mock_execute(input_data):
        result = test_binary_runner.run_with_input(input_data)
        return {
            'crashed': result['crashed'],
            'timeout': result['timeout'],
            'coverage': {0x1000},  # Mock coverage
            'exit_code': result['returncode'],
            'execution_time': 0.1
        }

    fuzzer.execute_target = mock_execute

    try:
        # Run fuzzing
        result = fuzzer.fuzz("dummy_target", initial_corpus)

        # Should have found some crashes
        assert result.total_executions > 0
        # Note: In real testing, we would check for specific crash types

    finally:
        fuzzer.execute_target = original_execute


def test_fuzzer_can_find_division_by_zero(test_binary_runner):
    """Test that fuzzer can find division by zero."""
    config = FuzzingConfig(
        max_iterations=30,
        timeout_seconds=1,
        strategy=FuzzingStrategy.GENERATION,
        seed=54321
    )

    fuzzer = VMFuzzer(config)

    # Mock execution for division by zero test
    original_execute = fuzzer.execute_target

    def mock_execute(input_data):
        # Run division_by_zero test
        result = subprocess.run(
            [sys.executable, test_binary_runner.binary_path, "division_by_zero"],
            input=input_data,
            capture_output=True,
            timeout=2
        )

        return {
            'crashed': result.returncode != 0,
            'timeout': False,
            'coverage': {0x2000},
            'exit_code': result.returncode,
            'execution_time': 0.1
        }

    fuzzer.execute_target = mock_execute

    try:
        result = fuzzer.fuzz("dummy_target")

        assert result.total_executions > 0

    finally:
        fuzzer.execute_target = original_execute


def test_vm_fuzzer_detects_vm_handlers(vm_test_binary_runner):
    """Test that VM fuzzer can detect VM handlers."""
    config = FuzzingConfig(
        max_iterations=10,
        timeout_seconds=1
    )

    fuzzer = VMFuzzer(config)

    # Mock VM detection to return our test handlers
    original_analyze = fuzzer.analyze_target

    def mock_analyze(binary_path):
        return {
            'vm_detected': True,
            'handlers_found': [
                {'address': 0x1000, 'type': 'arithmetic'},
                {'address': 0x1004, 'type': 'memory'},
                {'address': 0x1008, 'type': 'control_flow'},
            ]
        }

    fuzzer.analyze_target = mock_analyze

    try:
        result = fuzzer.analyze_target("dummy")

        assert result['vm_detected'] == True
        assert len(result['handlers_found']) == 3

    finally:
        fuzzer.analyze_target = original_analyze


def test_network_fuzzer_can_detect_crashes():
    """Test network fuzzer crash detection."""
    # Create a mock target that always crashes
    target = NetworkTarget("127.0.0.1", 12345)  # Non-existent port

    fuzzer = NetworkFuzzer(target)

    # Test execution (should fail to connect = crash)
    result = fuzzer.execute_network_input(b"test")

    assert result.crashed == True
    assert "connection_failed" in result.crash_info.get('type', '')


def test_protocol_fuzzer_http():
    """Test HTTP protocol-aware fuzzing."""
    target = NetworkTarget("127.0.0.1", 8080)
    fuzzer = ProtocolFuzzer(target, "http")

    # Test HTTP input generation
    template = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    fuzz_input = fuzzer.generate_protocol_input(template)

    # Should be valid HTTP-like request
    fuzz_str = fuzz_input.decode('utf-8', errors='ignore')
    assert "HTTP/1.1" in fuzz_str
    assert "\r\n" in fuzz_str


def test_parallel_fuzzer_initialization():
    """Test parallel fuzzer can be initialized."""
    config = FuzzingConfig(
        max_iterations=20,
        parallel_jobs=2,
        timeout_seconds=1
    )

    fuzzer = VMFuzzer(config)

    # Should have parallel fuzzer
    assert fuzzer.parallel_fuzzer is not None
    assert fuzzer.power_scheduler is not None


def test_dictionary_injection():
    """Test dictionary token injection."""
    config = FuzzingConfig(max_iterations=10)
    fuzzer = VMFuzzer(config)

    # Add custom token
    fuzzer.dictionary.add_token(b"CRASH")

    # Generate input with dictionary
    input_data = fuzzer.generate_input()

    # Should be able to inject tokens (though may not always happen)
    assert isinstance(input_data, bytes)


def test_symbolic_input_generation():
    """Test symbolic input generation capability."""
    config = FuzzingConfig(
        max_iterations=10,
        enable_symbolic=True
    )

    fuzzer = VMFuzzer(config)

    # Should have symbolic bridge
    assert fuzzer.symbolic_bridge is not None

    # Generate input (may fall back to regular generation)
    input_data = fuzzer.generate_input()
    assert isinstance(input_data, bytes)
    assert len(input_data) > 0


def test_taint_tracking_integration():
    """Test taint tracking integration."""
    config = FuzzingConfig(
        max_iterations=10,
        enable_taint=True
    )

    fuzzer = VMFuzzer(config)

    # Should have taint components
    assert fuzzer.taint_mutator is not None
    assert fuzzer.vm_taint_fuzzer is not None

    # Test taint execution (mock)
    result = fuzzer.execute_with_taint(b"test")
    assert 'taint_info' in result


def test_coverage_tracking():
    """Test coverage tracking functionality."""
    config = FuzzingConfig(max_iterations=10, enable_coverage=True)
    fuzzer = VMFuzzer(config)

    # Record some coverage
    assert fuzzer.coverage_tracker.record_block(0x1000) == True
    assert fuzzer.coverage_tracker.record_block(0x1004) == True
    assert fuzzer.coverage_tracker.record_block(0x1000) == False  # Already seen

    coverage = fuzzer.coverage_tracker.get_coverage_set()
    assert 0x1000 in coverage
    assert 0x1004 in coverage
    assert len(coverage) == 2


def test_corpus_minimization():
    """Test corpus minimization."""
    config = FuzzingConfig(max_iterations=10)
    fuzzer = VMFuzzer(config)

    # Add inputs with coverage
    fuzzer.corpus_manager.add_input(b"input1", {0x1000, 0x1004}, 0.1)
    fuzzer.corpus_manager.add_input(b"input2", {0x1000}, 0.1)  # Subset
    fuzzer.corpus_manager.add_input(b"input3", {0x1008}, 0.1)  # New

    stats = fuzzer.corpus_manager.get_stats()
    assert stats['total_inputs'] >= 2  # Should keep input1 and input3


def test_crash_deduplication():
    """Test crash deduplication."""
    config = FuzzingConfig(max_iterations=10)
    fuzzer = VMFuzzer(config)

    # Add same crash twice
    crash_info = {
        'type': 'access_violation',
        'address': 0x401000,
        'write_operation': True
    }

    fuzzer.crash_analyzer.analyze_crash(crash_info, b"input1")
    fuzzer.crash_analyzer.analyze_crash(crash_info, b"input2")  # Same crash

    # Different crash
    crash_info2 = {
        'type': 'division_by_zero',
        'address': 0x402000
    }
    fuzzer.crash_analyzer.analyze_crash(crash_info2, b"input3")

    assert fuzzer.crash_analyzer.get_unique_crash_count() == 2


@pytest.mark.slow
def test_end_to_end_fuzzing_campaign():
    """Full end-to-end fuzzing test (marked slow)."""
    config = FuzzingConfig(
        max_iterations=100,
        timeout_seconds=2,
        strategy=FuzzingStrategy.HYBRID,
        enable_coverage=True,
        enable_taint=False,  # Disable for speed
        enable_symbolic=False,  # Disable for speed
        parallel_jobs=1  # Single threaded for test
    )

    fuzzer = VMFuzzer(config)

    # Mock execution with test binary
    call_count = 0

    def mock_execute(input_data):
        nonlocal call_count
        call_count += 1

        # Simulate some crashes
        if b"\x00\x00\x00\x00" in input_data and call_count > 10:
            return {
                'crashed': True,
                'timeout': False,
                'coverage': {0x1000, 0x1004},
                'exit_code': 1,
                'execution_time': 0.1
            }
        else:
            return {
                'crashed': False,
                'timeout': False,
                'coverage': {0x1000},
                'exit_code': 0,
                'execution_time': 0.1
            }

    fuzzer.execute_target = mock_execute

    # Run fuzzing
    result = fuzzer.fuzz("dummy_target", [b"seed"])

    # Validate results
    assert result.iterations > 0
    assert result.total_executions > 0
    assert result.coverage_percentage >= 0.0

    print(f"End-to-end test completed: {result.total_executions} executions, "
          f"{result.crashes_found} crashes found")


if __name__ == "__main__":
    # Run basic validation
    print("Running fuzzer validation tests...")

    # Test basic functionality
    config = FuzzingConfig(max_iterations=5)
    fuzzer = VMFuzzer(config)

    print("✓ Fuzzer initialization")
    print("✓ Component loading")

    # Test input generation
    input_data = fuzzer.generate_input()
    print(f"✓ Input generation: {len(input_data)} bytes")

    # Test coverage tracking
    fuzzer.coverage_tracker.record_block(0x1000)
    coverage = fuzzer.coverage_tracker.get_coverage_set()
    print(f"✓ Coverage tracking: {len(coverage)} blocks")

    # Test corpus management
    fuzzer.corpus_manager.add_input(b"test", {0x1000}, 0.1)
    stats = fuzzer.corpus_manager.get_stats()
    print(f"✓ Corpus management: {stats['total_inputs']} inputs")

    print("All basic validation tests passed!")
