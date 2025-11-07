# Build Instructions

## Prerequisites

### Windows
- Rust toolchain (MSVC target)
- Visual Studio Build Tools with C++ workload
- Windows SDK

Install via:
```powershell
rustup default stable-msvc
```

### Linux
- Rust toolchain
- GCC/Clang
- libelf-dev (for eBPF)

### macOS
- Rust toolchain
- Xcode Command Line Tools

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --bin ghost-cli
```

Note: Requires elevated privileges for full process memory access.
