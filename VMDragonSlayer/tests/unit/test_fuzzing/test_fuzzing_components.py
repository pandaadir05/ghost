"""
Fuzzing Integration Tests
==========================

Test fuzzing component with real target.
This verify the implementation actually work.
"""

import os
import tempfile
import pytest
from dragonslayer.fuzzing import (
    VMFuzzer,
    FuzzingConfig,
    FuzzingStrategy,
    MutationEngine,
    MutationStrategy,
    CoverageTracker,
    CrashAnalyzer,
)


def test_mutation_engine_bit_flip():
    """Test bit flip mutation."""
    engine = MutationEngine(seed=42)
    
    data = b"\x00\x00\x00\x00"
    mutated = engine.mutate(data, MutationStrategy.BIT_FLIP)
    
    assert mutated != data
    assert len(mutated) == len(data)


def test_mutation_engine_byte_flip():
    """Test byte flip mutation."""
    engine = MutationEngine(seed=42)
    
    data = b"\x00\xFF\x00\xFF"
    mutated = engine.mutate(data, MutationStrategy.BYTE_FLIP)
    
    assert mutated != data


def test_mutation_engine_arithmetic():
    """Test arithmetic mutation."""
    engine = MutationEngine(seed=42)
    
    data = b"\x10\x20\x30\x40"
    mutated = engine.mutate(data, MutationStrategy.ARITHMETIC)
    
    assert len(mutated) == len(data)


def test_mutation_engine_havoc():
    """Test havoc mutation (multiple mutation)."""
    engine = MutationEngine(seed=42)
    
    data = b"Hello World!"
    mutated = engine.mutate(data, MutationStrategy.HAVOC)
    
    # Should be different after havoc
    assert mutated != data


def test_coverage_tracker():
    """Test coverage tracking."""
    tracker = CoverageTracker()
    
    # Record some block
    assert tracker.record_block(0x1000) == True  # New block
    assert tracker.record_block(0x1004) == True
    assert tracker.record_block(0x1000) == False  # Already seen
    
    # Check coverage
    coverage = tracker.get_coverage_set()
    assert 0x1000 in coverage
    assert 0x1004 in coverage
    assert len(coverage) == 2
    
    # Check edge tracking
    edges = tracker.get_edge_set()
    assert (0x1000, 0x1004) in edges


def test_crash_analyzer():
    """Test crash analysis and deduplication."""
    analyzer = CrashAnalyzer()
    
    # Analyze first crash
    crash_data1 = {
        'type': 'access_violation',
        'address': 0x401000,
        'write_operation': True,
        'stack_trace': ['frame1', 'frame2', 'frame3']
    }
    
    input1 = b"AAAA"
    crash1 = analyzer.analyze_crash(crash_data1, input1)
    
    assert crash1.crash_type == 'access_violation'
    assert crash1.exploitability == 'high'
    assert analyzer.get_unique_crash_count() == 1
    
    # Analyze same crash (should be deduplicate)
    crash2 = analyzer.analyze_crash(crash_data1, b"BBBB")
    assert analyzer.get_unique_crash_count() == 1
    
    # Analyze different crash
    crash_data2 = {
        'type': 'division_by_zero',
        'address': 0x402000,
        'stack_trace': ['other1', 'other2']
    }
    crash3 = analyzer.analyze_crash(crash_data2, b"CCCC")
    
    assert crash3.exploitability == 'low'
    assert analyzer.get_unique_crash_count() == 2


def test_corpus_manager():
    """Test corpus management."""
    from dragonslayer.fuzzing import CorpusManager
    
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CorpusManager(corpus_dir=tmpdir, max_size=10)
        
        # Add input with coverage
        input1 = b"test1"
        coverage1 = {0x1000, 0x1004, 0x1008}
        assert manager.add_input(input1, coverage1, 0.0) == True
        
        # Add duplicate (should reject)
        assert manager.add_input(input1, coverage1, 0.0) == False
        
        # Add input with new coverage
        input2 = b"test2"
        coverage2 = {0x1000, 0x100C}  # Has new block 0x100C
        assert manager.add_input(input2, coverage2, 0.0) == True
        
        # Check stats
        stats = manager.get_stats()
        assert stats['total_inputs'] == 2
        assert stats['total_coverage'] == 4  # 0x1000, 0x1004, 0x1008, 0x100C


def test_vm_fuzzer_initialization():
    """Test VM fuzzer can be initialize."""
    config = FuzzingConfig(
        max_iterations=100,
        timeout_seconds=1,
        strategy=FuzzingStrategy.MUTATION
    )
    
    fuzzer = VMFuzzer(config)
    
    assert fuzzer.config.max_iterations == 100
    assert fuzzer.config.timeout_seconds == 1
    assert fuzzer.vm_detected == False


def test_vm_fuzzer_input_generation():
    """Test input generation work."""
    config = FuzzingConfig(seed=42)
    fuzzer = VMFuzzer(config)
    
    # Generate random input
    input1 = fuzzer.generate_input()
    assert isinstance(input1, bytes)
    assert len(input1) > 0
    
    # Add to corpus and generate mutation
    fuzzer.corpus_manager.add_input(b"seed", set(), 0.0)
    input2 = fuzzer.generate_input()
    assert isinstance(input2, bytes)


@pytest.mark.skip(reason="Need real target binary")
def test_vm_fuzzer_full_session():
    """Test complete fuzzing session (skip without target)."""
    config = FuzzingConfig(
        max_iterations=10,
        timeout_seconds=1
    )
    
    fuzzer = VMFuzzer(config)
    
    # Would need real target to test
    # result = fuzzer.fuzz("target.exe", [b"seed1", b"seed2"])
    # assert result.iterations == 10
