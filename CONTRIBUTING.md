# Contributing

Thanks for wanting to help out.

## Quick start

1. Fork the repo
2. Clone it: `git clone your-fork-url`
3. Make a branch: `git checkout -b your-feature`
4. Code, test, commit
5. Push and open a PR

## Before you commit

Run these:
```bash
cargo fmt --all
cargo clippy --all -- -D warnings
cargo test --all
```

If stuff fails, fix it before pushing.

## Commit messages

Keep them short and clear:
- `feat: add new detection method`
- `fix: crash when scanning process 0`
- `docs: update README examples`

## What needs work

- macOS support is barely there
- Tests could use more coverage
- Documentation always needs updates
- Performance optimizations
- More detection techniques

## Code guidelines

- Write Rust that doesn't suck
- Document weird stuff
- Add tests for new features
- Don't break existing functionality

That's it. Keep it simple.
