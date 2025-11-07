# Ghost

Cross-platform process injection detection framework.

## Overview

Ghost is a real-time detection system for identifying process injection techniques across Windows, Linux, and macOS platforms. It combines kernel-level monitoring with behavioral analysis to detect advanced injection methods.

## Architecture

- **ghost-core**: Core detection engine and platform abstraction
- **ghost-drivers**: Platform-specific kernel components
- **ghost-tui**: Terminal user interface
- **ghost-lib**: Shared libraries and utilities
- **ghost-rules**: Detection rules and signatures

## Supported Techniques

### Windows
- Classic DLL injection (CreateRemoteThread)
- APC injection (NtQueueApcThread)
- Process hollowing
- Thread hijacking
- SetWindowsHookEx injection
- Reflective DLL injection

### Linux
- ptrace injection
- LD_PRELOAD manipulation
- process_vm_writev injection
- Shared memory injection

### macOS
- DYLD_INSERT_LIBRARIES
- task_for_pid injection
- Mach port manipulation

## Building

```bash
cargo build --release
```

## Status

Early development. Windows support in progress.
