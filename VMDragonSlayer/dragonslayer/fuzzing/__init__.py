"""
Fuzzing Module
==============

EBP (Emulation-Based Protocol) fuzzer for VM analysis.
This module was missing in original implementation - now is fixed.

Provides comprehensive fuzzing capabilities including:
- Mutation-based fuzzing with many strategy
- Generation-based input synthesis
- Coverage-guided fuzzing with tracking
- VM-aware fuzzing that use taint analysis
- Crash detection and the triage
"""

from .base_fuzzer import (
    BaseFuzzer,
    FuzzingConfig,
    FuzzResult,
    FuzzingStrategy,
)

from .mutation_engine import (
    MutationEngine,
    MutationStrategy,
)

from .coverage_tracker import (
    CoverageTracker,
    CoverageStats,
)

from .crash_analyzer import (
    CrashAnalyzer,
    CrashInfo,
)

from .corpus_manager import (
    CorpusManager,
)

from .vm_fuzzer import (
    VMFuzzer,
)

from .input_generator import (
    InputGenerator,
)

from .execution_engine import (
    ExecutionEngine,
    ExecutionResult,
)

from .symbolic_integration import (
    SymbolicFuzzingBridge,
    SymbolicConstraint,
    SymbolicPath,
)

from .taint_integration import (
    TaintGuidedMutator,
    VMTaintFuzzer,
    TaintInfo,
)

from .parallel_engine import (
    ParallelFuzzer,
    PowerScheduler,
    DictionaryManager,
)

from .network_fuzzer import (
    NetworkFuzzer,
    NetworkTarget,
    ProtocolFuzzer,
    DistributedFuzzer,
)

__all__ = [
    # Core fuzzing
    "BaseFuzzer",
    "FuzzingConfig",
    "FuzzResult",
    "FuzzingStrategy",
    
    # Mutation
    "MutationEngine",
    "MutationStrategy",
    
    # Coverage
    "CoverageTracker",
    "CoverageStats",
    
    # Crash analysis
    "CrashAnalyzer",
    "CrashInfo",
    
    # Corpus
    "CorpusManager",
    
    # VM fuzzer
    "VMFuzzer",
    
    # Input generation
    "InputGenerator",
    
    # Execution
    "ExecutionEngine",
    "ExecutionResult",
    
    # Symbolic integration
    "SymbolicFuzzingBridge",
    "SymbolicConstraint",
    "SymbolicPath",
    
    # Taint integration
    "TaintGuidedMutator",
    "VMTaintFuzzer",
    "TaintInfo",
    
    # Performance optimization
    "ParallelFuzzer",
    "PowerScheduler",
    "DictionaryManager",
    
    # Network fuzzing
    "NetworkFuzzer",
    "NetworkTarget",
    "ProtocolFuzzer",
    "DistributedFuzzer",
]
