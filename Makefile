.PHONY: build test clean install dev-setup check fmt clippy doc

# Default target
all: build

# Build the project
build:
	cargo build --release

# Build for development
dev:
	cargo build

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# Install locally
install: build
	cargo install --path ghost-cli

# Development setup
dev-setup:
	rustup component add clippy rustfmt
	cargo install cargo-audit

# Check code quality
check:
	cargo check
	cargo clippy -- -D warnings
	cargo audit

# Format code
fmt:
	cargo fmt

# Run clippy
clippy:
	cargo clippy -- -D warnings

# Generate documentation
doc:
	cargo doc --open

# Run CLI with default args
run:
	cargo run --bin ghost-cli

# Run CLI with verbose output
run-verbose:
	cargo run --bin ghost-cli -- --verbose

# Run CLI with JSON output
run-json:
	cargo run --bin ghost-cli -- --format json

# Run CLI with CSV output
run-csv:
	cargo run --bin ghost-cli -- --format csv

# Run TUI
run-tui:
	cargo run --bin ghost-tui

# Watch mode for development
watch:
	cargo watch -x check -x test -x "run --bin ghost-cli"

# Profile build size
size: build
	@echo "Binary sizes:"
	@du -h target/release/ghost-cli target/release/ghost-tui 2>/dev/null || true

# Help
help:
	@echo "Available targets:"
	@echo "  build      - Build release version"
	@echo "  dev        - Build development version"
	@echo "  test       - Run tests"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install CLI locally"
	@echo "  dev-setup  - Setup development environment"
	@echo "  check      - Run code quality checks"
	@echo "  fmt        - Format code"
	@echo "  clippy     - Run clippy linter"
	@echo "  doc        - Generate documentation"
	@echo "  run        - Run CLI with default args"
	@echo "  run-verbose- Run CLI with verbose output"
	@echo "  run-json   - Run CLI with JSON output"
	@echo "  run-csv    - Run CLI with CSV output"
	@echo "  run-tui    - Run TUI interface"
	@echo "  watch      - Watch mode for development"
	@echo "  size       - Show binary sizes"
	@echo "  help       - Show this help"