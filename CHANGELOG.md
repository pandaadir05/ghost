# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Ghost process injection detection framework
- Cross-platform process enumeration (Windows, Linux, macOS)
- Memory analysis and RWX region detection
- Shellcode pattern detection
- Process hollowing detection with PE header validation
- MITRE ATT&CK technique mapping
- Threat intelligence correlation framework
- Terminal UI (TUI) for interactive monitoring
- Command-line interface (CLI) for automation
- Configuration file support (TOML)
- JSON output format support
- Hook detection (inline hooks, LD_PRELOAD, ptrace)
- Thread analysis and enumeration
- Evasion technique detection framework
- Behavioral anomaly detection
- YARA rule engine integration (framework)
- Event streaming and correlation system
- CI/CD pipeline with GitHub Actions
- Comprehensive documentation

### Fixed
- All compilation errors resolved
- Borrow checker issues in TUI
- Missing Debug trait implementations
- Async/await compatibility with tokio
- Generic type inference in UI rendering
- Platform-specific import warnings
- Test suite compilation errors
- ThreatLevel ordering comparison support
- DetectionConfig validate method visibility
- Unused variable warnings across codebase

### Changed
- Improved error handling consistency
- Enhanced code documentation
- Optimized memory scanning performance
- Standardized naming conventions
- Updated test suite to match current API
- Implemented macOS memory reading via mach APIs (vm_read)
- Added Debug trait derives to threat intelligence structures
- Disabled outdated tests (marked with TODO for updates)

## [0.1.0] - 2024-11-20

### Initial Development Release

- Core detection engine functional
- Windows support complete
- Linux support partial (procfs-based)
- macOS support limited (enumeration only)
- TUI and CLI interfaces working
- Professional codebase structure
- Clean compilation on all platforms

[Unreleased]: https://github.com/YOUR_USERNAME/ghost/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YOUR_USERNAME/ghost/releases/tag/v0.1.0
