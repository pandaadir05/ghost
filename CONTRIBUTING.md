# Contributing to Ghost

## Development Setup

### Prerequisites
- Rust 1.70+ (stable)
- Windows SDK for Windows development
- Visual Studio Build Tools

### Building
```bash
git clone https://github.com/pandaadir05/ghost.git
cd ghost
cargo build
```

### Testing
```bash
cargo test
cargo run --bin ghost-cli
```

## Code Style

### Rust Guidelines
- Use `rustfmt` with default settings
- All public APIs must have documentation
- Follow Rust naming conventions
- Prefer explicit error handling over `.unwrap()`

### Commit Messages
Follow conventional commits:
- `feat: add new detection technique`
- `fix: resolve false positive in memory scanning`
- `perf: optimize syscall hook performance`
- `docs: update detection coverage matrix`
- `refactor: extract platform-specific code`

## Detection Development

### Adding New Techniques
1. Research the injection method thoroughly
2. Implement detection in `ghost-core/src/detection.rs`
3. Add tests in `tests/detection/`
4. Update documentation in `docs/DETECTION_METHODS.md`
5. Add benchmark if performance critical

### Platform Support
- Windows: Primary platform, full feature support
- Linux: eBPF-based detection (in progress)
- macOS: Endpoint Security framework (planned)

## Testing

### Unit Tests
Focus on:
- Detection accuracy (no false positives)
- Edge case handling
- Memory safety
- Performance regressions

### Integration Tests
- Real injection techniques (in controlled environment)
- Cross-platform compatibility
- Performance benchmarks

## Documentation

### Code Comments
```rust
/// Detects process hollowing by analyzing memory layout gaps.
/// 
/// This technique monitors for unusual memory allocation patterns
/// where the original executable sections are unmapped and replaced
/// with malicious code while preserving the process structure.
///
/// # Arguments
/// * `regions` - Memory regions from VirtualQueryEx
///
/// # Returns
/// Confidence score 0.0-1.0 indicating hollowing likelihood
```

### Security Considerations
- All detection methods must be documented
- Include MITRE ATT&CK technique mappings
- Reference academic papers where applicable
- Provide reproducible test cases

## Review Process

### Pull Requests
1. All tests must pass
2. Code coverage >85%
3. Documentation updated
4. Performance impact assessed
5. Security review for new detection logic

### Performance Requirements
- Memory enumeration: <100ms per process
- Thread analysis: <50ms per process  
- Detection engine: <10ms per analysis
- Total scan time: <5s for 200 processes

## Architecture

### Core Principles
- Zero false positives
- Minimal performance impact
- Cross-platform compatibility
- Educational value

### Module Structure
```
ghost-core/
├── detection.rs    # Core detection algorithms
├── memory.rs       # Memory enumeration
├── process.rs      # Process management  
├── thread.rs       # Thread analysis
└── platform/       # OS-specific implementations
    ├── windows/
    ├── linux/
    └── macos/
```

## Security Research

### Responsible Disclosure
- Test only on systems you own
- Report bypasses through security contacts
- Include proof-of-concept code
- Coordinate with maintainers

### Research Areas
- Novel injection techniques
- Evasion methods
- Performance optimizations
- Anti-analysis detection

## Questions?

Open an issue for:
- Feature requests
- Bug reports
- Documentation improvements
- Design discussions

For security issues, email: .