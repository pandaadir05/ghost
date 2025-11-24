# dragonslayer.fuzzing.vm_fuzzer

Path: `dragonslayer/fuzzing/vm_fuzzer.py`

## Purpose
VM-aware fuzzer that leverage VM detection and taint tracking for effective fuzzing of protected binary. This was missing component that was claim to exist in DefCon presentation.

## Public API
- Class `VMFuzzer(config: FuzzingConfig)`
  - `analyze_target(binary_path: str) -> Dict` — Analyze target to find VM structure
  - `fuzz(target_path: str, initial_corpus: List[bytes] = None) -> FuzzResult` — Main fuzzing entry
  - `generate_input() -> bytes` — Generate test input using mutation or generation
  - `execute_target(input_data: bytes) -> Dict` — Execute target with monitoring
  - `execute_with_taint(input_data: bytes) -> Dict` — Execute with taint tracking enable
  - `get_statistics() -> Dict` — Get fuzzing statistic

## Usage Example
```python
from dragonslayer.fuzzing import VMFuzzer, FuzzingConfig, FuzzingStrategy

# Create configuration
config = FuzzingConfig(
    max_iterations=100000,
    timeout_seconds=5,
    strategy=FuzzingStrategy.HYBRID,
    enable_coverage=True,
    enable_taint=True,
    crash_dir="output/crashes",
    corpus_dir="output/corpus"
)

# Initialize fuzzer
fuzzer = VMFuzzer(config)

# Analyze target first (optional but recommend)
analysis = fuzzer.analyze_target("protected.exe")
print(f"VM detected: {analysis.get('vm_detected', False)}")
print(f"Handlers: {len(analysis.get('handlers_found', []))}")

# Run fuzzing with initial seed
initial_corpus = [
    b"GET / HTTP/1.1\r\n\r\n",
    b"\x00\x01\x02\x03",
    open("seed1.bin", "rb").read()
]

result = fuzzer.fuzz("protected.exe", initial_corpus)

# Print result
print(f"Iterations: {result.iterations}")
print(f"Crashes found: {result.crashes_found}")
print(f"Unique crashes: {result.unique_crashes}")
print(f"Coverage: {result.coverage_percentage:.2f}%")
print(f"Execution time: {result.execution_time:.2f}s")
print(f"Timeouts: {result.timeouts}")

# Get detailed statistic
stats = fuzzer.get_statistics()
print(f"Corpus size: {stats['corpus_size']}")
print(f"VM handlers found: {stats['vm_handlers']}")
```

## Advanced Usage

### With Taint Tracking
```python
# Configure with taint enable
config = FuzzingConfig(
    enable_taint=True,
    max_iterations=50000
)

fuzzer = VMFuzzer(config)

# Fuzzer will automatically use taint analysis
# to guide input generation toward interesting path
result = fuzzer.fuzz("target.exe")
```

### Custom Corpus
```python
import os

# Load corpus from directory
corpus = []
for file in os.listdir("seeds/"):
    with open(os.path.join("seeds/", file), "rb") as f:
        corpus.append(f.read())

# Run fuzzing
fuzzer = VMFuzzer(config)
result = fuzzer.fuzz("target.exe", corpus)
```

### Parallel Fuzzing
```python
# Configure parallel execution
config = FuzzingConfig(
    parallel_jobs=4,
    max_iterations=1000000
)

# Each job will run in separate process
# and share coverage information
fuzzer = VMFuzzer(config)
result = fuzzer.fuzz("target.exe")
```

## Implementation Detail

### VM Structure Detection
The fuzzer first analyze target to identify:
- VM dispatcher loop
- Handler table location
- Individual VM handler
- Entry and exit point

This information guide fuzzing to target VM-specific code path.

### Mutation Strategy
The fuzzer use multiple mutation strategy:
- **Deterministic**: Bit flip, byte flip, arithmetic
- **Random**: Havoc, splice, block operation
- **Smart**: Interesting value, magic number
- **Grammar**: Protocol-aware generation (if grammar provide)

### Coverage Feedback
Coverage information guide corpus selection:
- Input that reach new block are add to corpus
- Input that reach new edge are prioritize
- Corpus is minimize to keep only interesting input

### Crash Triage
When crash occur, fuzzer:
1. Generate unique signature base on crash type and location
2. Check if crash is duplicate of previous
3. Assess exploitability using heuristic
4. Save crash input and detail to disk
5. Continue fuzzing

## Limitation

Current implementation have some limitation:
- Process execution is stub (need real implementation)
- Coverage collection require instrumentation
- Taint tracking integration is partial
- No distributed fuzzing support yet

These will be address in future update.

## Related
- Base Fuzzer: `dragonslayer/fuzzing/base_fuzzer.py`
- Mutation Engine: `dragonslayer/fuzzing/mutation_engine.py`
- VM Detection: `dragonslayer/analysis/vm_discovery/detector.py`
- Back to [Modules](../../../../03-modules.md)
