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

**Detection Logic**:
- Enumerate threads using CreateToolhelp32Snapshot (Windows) or /proc/[pid]/task (Linux)
- Get thread start addresses via NtQueryInformationThread (Windows) or /proc syscall file (Linux)
- Get thread creation times via GetThreadTimes (Windows) or stat parsing (Linux)
- Track thread state (Running, Waiting, Suspended, Terminated)
- Flag threads starting in private memory regions

## Hook Detection

### Inline API Hooks

**MITRE ATT&CK**: T1055.003

Detects JMP patches at the start of critical API functions.

**Detection Logic**:
- Enumerate loaded modules in target process (EnumProcessModulesEx)
- Check entry points of critical APIs (ntdll, kernel32, user32)
- Detect common hook patterns:
  - JMP rel32 (E9 xx xx xx xx)
  - JMP [rip+disp32] (FF 25 xx xx xx xx)
  - MOV RAX, imm64; JMP RAX (48 B8 ... FF E0)
  - PUSH imm32; RET (68 xx xx xx xx C3)

**Critical APIs Monitored**:
- NtCreateThread, NtCreateThreadEx
- NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory
- VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- LoadLibraryA, LoadLibraryW
- SetWindowsHookExA, SetWindowsHookExW

### DYLD_INSERT_LIBRARIES Detection (macOS)

**MITRE ATT&CK**: T1055.001

Detects dynamic library injection on macOS via the DYLD_INSERT_LIBRARIES environment variable.

**Detection Logic**:
- Read process environment variables using ps command
- Parse DYLD_INSERT_LIBRARIES variable
- Report each injected library path
- Flag processes with this variable set

**Platform**: macOS only

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
- [x] Memory region analysis (VirtualQueryEx)
- [x] Memory reading (ReadProcessMemory)
- [x] Thread enumeration (CreateToolhelp32Snapshot)
- [x] Thread start addresses (NtQueryInformationThread)
- [x] Thread creation times (GetThreadTimes)
- [x] Inline hook detection (JMP pattern scanning)
- [x] Process hollowing heuristics
- [ ] APC injection detection
- [ ] SetWindowsHookEx chain enumeration
- [ ] Reflective DLL injection signature matching

### Linux

- [x] Process enumeration (/proc filesystem)
- [x] Memory region analysis (/proc/[pid]/maps)
- [x] Memory reading (/proc/[pid]/mem)
- [x] Thread enumeration (/proc/[pid]/task)
- [x] Thread state detection (stat parsing)
- [x] ptrace injection detection
- [x] LD_PRELOAD detection
- [ ] process_vm_writev monitoring
- [ ] Shared memory inspection

### macOS

- [x] Process enumeration (sysctl KERN_PROC_ALL)
- [x] Process path retrieval (proc_pidpath)
- [x] Memory enumeration (mach_vm_region)
- [x] Memory reading (mach_vm_read_overwrite)
- [x] Thread enumeration (task_threads with thread_basic_info)
- [x] DYLD_INSERT_LIBRARIES detection
- [ ] task_for_pid monitoring
- [ ] Mach port analysis

## References

- MITRE ATT&CK T1055: Process Injection
- Windows Internals 7th Edition
- "Process Injection Techniques" - Elastic Security
