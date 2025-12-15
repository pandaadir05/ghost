# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Output size control with `--summary`, `--max-indicators`, `--min-threat-level` flags
- OutputFormatter module for result formatting and deduplication
- Indicator deduplication to reduce redundant output
- Summary mode for aggregated scan statistics
- Output configuration section in config file

### Fixed
- TUI not displaying on Windows (blank screen issue)
- Terminal not restoring properly on crash/panic
- Initial scan blocking TUI from rendering
- Replaced println! with log macros for proper verbosity control

### Changed
- Default max indicators per detection is now 10 (was unlimited)
- TUI now draws immediately before background scanning starts
- Scan errors no longer prevent TUI from starting

## [0.1.1] - 2024-12-06

### Added
- ebpf-detection feature flag for optional eBPF support (stub implementation)
- TODO markers throughout codebase for stub implementations
- Comprehensive documentation of limitations and unimplemented features
- Test coverage for shellcode detection (11 unit tests)
- Test coverage for memory protection detection (11 unit tests)
- DYLD_INSERT_LIBRARIES detection for macOS hook detection
- Complete inline hook detection for macOS with x86_64 and ARM64 support
- Function address resolution using nm and vmmap for macOS
- Test coverage for hook detection (6 unit tests)

### Fixed
- Replaced simulated memory reading with real process memory access
- Detection engine now reads actual process memory instead of fake data
- Security vulnerability RUSTSEC-2025-0020 in pyo3 dependency
- Clippy warnings for CI compliance
- Documentation now correctly shows macOS thread enumeration is implemented

### Changed
- Updated README to accurately reflect platform support and limitations
- Documented that ML features require trained models
- Clarified performance metrics are targets, not validated benchmarks
- Updated technical documentation for implementation accuracy
- macOS memory reading and thread enumeration now properly documented as implemented
- macOS hook detection now fully implemented and documented

## [0.1.0] - 2024-11-20

### Added
- Initial release of Ghost process injection detection framework
- Cross-platform process enumeration (Windows, Linux, macOS)
- Memory analysis and RWX region detection
- Shellcode pattern detection with 30+ signatures
- Process hollowing detection with PE header validation
- MITRE ATT&CK technique mapping framework
- Threat intelligence correlation framework (no active feeds)
- Terminal UI (TUI) for interactive monitoring
- Command-line interface (CLI) for automation
- Configuration file support (TOML)
- JSON output format support
- Hook detection (inline hooks, LD_PRELOAD, ptrace)
- Thread analysis and enumeration (Windows, Linux)
- Evasion technique detection framework
- Behavioral anomaly detection (heuristic-based)
- YARA rule engine integration (optional feature)
- Event streaming and correlation system
- CI/CD pipeline with GitHub Actions
- Comprehensive documentation

### Known Limitations
- ML features are simulated without trained models
- eBPF support is stub implementation only
- Threat intelligence has no active feed connections
- Performance claims not validated with benchmarks

[Unreleased]: https://github.com/pandaadir05/ghost/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/pandaadir05/ghost/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/pandaadir05/ghost/releases/tag/v0.1.0
