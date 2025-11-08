# Detection Methods

This document details the techniques used by Ghost to detect process injection.

## Memory-Based Detection

### RWX Memory Regions

**MITRE ATT&CK**: T1055

Executable memory with write permissions is a strong indicator of code injection. Legitimate processes rarely need RWX pages except during JIT compilation.

**Detection Logic**:
- Enumerate all memory regions in target process
- Flag regions with PAGE_EXECUTE_READWRITE protection
- Confidence increases with number of RWX regions

**False Positives**:
- .NET/Java JIT compiler regions
- V8/SpiderMonkey JavaScript engines
- Legitimate debugging scenarios

### Private Executable Memory

Private memory regions (not backed by files) with execute permissions often contain injected shellcode.

**Detection Logic**:
- Check for MEM_PRIVATE regions with EXECUTE protection
- Correlate with unsigned code patterns
- Higher confidence if multiple regions present

## Thread-Based Detection

### Abnormal Thread Creation

**MITRE ATT&CK**: T1055.001 (DLL Injection), T1055.002 (Portable Executable Injection)

Monitors thread count changes over time. Sudden increases may indicate CreateRemoteThread injection.

**Detection Logic**:
- Baseline thread count for each process
- Alert on new threads created between scans
- Cross-reference with memory analysis

### Remote Thread Detection

Threads created by external processes via CreateRemoteThread or NtCreateThreadEx.

**Detection Logic** (Planned):
- Compare thread creator PID with owner PID
- Check thread start addresses against known modules
- Flag threads starting in private memory regions

## Heuristic Analysis

### Confidence Scoring

Ghost uses weighted confidence scoring:

| Indicator | Weight | Description |
|-----------|--------|-------------|
| RWX regions | 0.3 | Per region detected |
| Private exec | 0.4 | >2 regions |
| New threads | 0.2 | Per thread created |
| Unsigned code | 0.5 | In executable region |

**Thresholds**:
- Clean: < 0.3
- Suspicious: 0.3 - 0.7
- Malicious: >= 0.7

## Technique Coverage

### Windows

- [x] Classic DLL injection detection
- [x] Memory region analysis
- [x] Thread enumeration
- [ ] APC injection detection
- [ ] Process hollowing detection
- [ ] Hook detection (IAT/EAT)
- [ ] Reflective DLL injection

### Linux

- [ ] ptrace injection
- [ ] LD_PRELOAD detection
- [ ] process_vm_writev monitoring
- [ ] Shared memory inspection

### macOS

- [ ] DYLD_INSERT_LIBRARIES
- [ ] task_for_pid monitoring
- [ ] Mach port analysis

## References

- MITRE ATT&CK T1055: Process Injection
- Windows Internals 7th Edition
- "Process Injection Techniques" - Elastic Security
