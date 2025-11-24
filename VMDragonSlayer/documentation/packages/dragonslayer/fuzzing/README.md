# dragonslayer.fuzzing

**Purpose**: EBP (Emulation-Based Protocol) fuzzer for VM-protected binary analysis. This module was absent in original presentation and is now properly implement.

## Public Modules
- `vm_fuzzer.py` — VM-aware fuzzer with taint guidance
- `base_fuzzer.py` — Abstract base for all fuzzer implementation  
- `mutation_engine.py` — Input mutation strategy (bit flip, arithmetic, etc.)
- `coverage_tracker.py` — Code coverage tracking for guide fuzzing
- `crash_analyzer.py` — Crash detection and triage with exploitability
- `corpus_manager.py` — Test case corpus management

## Quick Usage
```python
from dragonslayer.fuzzing import VMFuzzer, FuzzingConfig, FuzzingStrategy

# Configure fuzzer
config = FuzzingConfig(
    max_iterations=50000,
    timeout_seconds=5,
    strategy=FuzzingStrategy.HYBRID,
    enable_coverage=True,
    enable_taint=True
)

# Create and run fuzzer
fuzzer = VMFuzzer(config)
result = fuzzer.fuzz("protected_binary.exe")

print(f"Crashes found: {result.crashes_found}")
print(f"Unique crashes: {result.unique_crashes}")
print(f"Coverage: {result.coverage_percentage:.2f}%")
```

## Features

### Mutation Strategy
- **Bit Flip**: Flip single bit in input
- **Byte Flip**: Flip entire byte
- **Arithmetic**: Add/subtract small value
- **Interesting Values**: Use value that often cause problem
- **Block Operations**: Delete, duplicate, splice block
- **Havoc**: Apply multiple mutation at once

### Coverage Guidance
- Track basic block coverage
- Track edge coverage (transition between block)
- Prioritize input that give new coverage
- Corpus minimization to keep small

### Crash Analysis
- Detect unique crash by signature
- Classify crash type (access violation, stack overflow, etc.)
- Assess exploitability (high, medium, low, none)
- Generate crash report with detail

### VM-Aware Fuzzing
- Integrate with VM detection engine
- Target VM handler and dispatcher
- Use taint tracking for guide input generation
- Symbolic execution for constraint-based input

## Configuration Option

```python
FuzzingConfig(
    max_iterations=10000,      # Max number of fuzzing iteration
    timeout_seconds=5,          # Timeout for each execution
    max_input_size=4096,        # Maximum size of generated input
    strategy=FuzzingStrategy.MUTATION,  # Fuzzing strategy
    enable_coverage=True,       # Enable coverage tracking
    enable_taint=True,          # Enable taint analysis
    crash_dir="crashes",        # Directory for crash input
    corpus_dir="corpus",        # Directory for corpus
    seed=None,                  # Random seed for reproduce
    parallel_jobs=1             # Number of parallel job
)
```

## Implementation Note

This fuzzer was describe in DefCon presentation but code was not real. The slide show architecture and result but implementation was missing. This is now complete implementation that actually work.

The fuzzer use technique from:
- AFL (American Fuzzy Lop) for mutation strategy
- LibFuzzer for corpus management  
- !exploitable for crash triage
- Custom VM-aware logic for target VM protection

## Related
- Source: `dragonslayer/fuzzing/`
- VM Detection: `dragonslayer/analysis/vm_discovery/`
- Taint Tracking: `dragonslayer/analysis/taint_tracking/`
- See [Modules](../../../03-modules.md)
