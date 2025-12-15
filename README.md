# Ghost

[![CI](https://github.com/pandaadir05/ghost/actions/workflows/ci.yml/badge.svg)](https://github.com/pandaadir05/ghost/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Ghost is a process injection detection tool written in Rust. It watches running processes and tries to catch suspicious stuff like code injection, memory manipulation, and other tricks that malware uses to hide.

## What it does

The main idea is simple: scan processes and look for weird memory patterns, hooked functions, shellcode, and other signs that something's been tampered with. It works on Windows, Linux, and macOS (though Windows support is the most complete right now).

Some of the things it can detect:

- **Memory regions with read-write-execute permissions** - Usually a red flag
- **Shellcode patterns** - Common instruction sequences found in injected code
- **Process hollowing** - When a legit process gets gutted and replaced with malicious code
- **API hooks** - Functions that have been redirected by inline patches or IAT modifications
- **Thread hijacking** - Threads that are redirected to execute shellcode
- **APC injection** - Malicious code queued via Asynchronous Procedure Calls
- **YARA signatures** - Matches against known malware patterns and payloads

It also maps detected behaviors to the MITRE ATT&CK framework, which is helpful if you're documenting threats or writing reports.

## Screenshots

### Detection Dashboard
![Ghost TUI - Detection Overview](assets/screenshot1.png)

### Active Threats
![Detected Malware](assets/screenshot2.png)

### Live Monitoring
![Real-time Process Analysis Logs](assets/screenshot3.png)

## Building it

You'll need Rust installed (1.70 or newer). Then:

```bash
cargo build --release
```

On Windows, you'll also need the MSVC build tools. Linux needs basic dev tools (gcc, etc.). macOS needs Xcode command line tools.

## Running it

There are two interfaces: a command-line tool and an interactive terminal UI.

**CLI:**

```bash
# Scan all processes
cargo run --bin ghost-cli --release

# Target one process
cargo run --bin ghost-cli --release -- --pid 1234

# Output results as JSON
cargo run --bin ghost-cli --release -- --format json

# Use a config file
cargo run --bin ghost-cli --release -- --config ghost.toml

# Continuous monitoring mode
cargo run --bin ghost-cli --release -- --watch

# Watch with custom interval (10 seconds)
cargo run --bin ghost-cli --release -- --watch --interval 10
```

**TUI:**

```bash
cargo run --bin ghost-tui --release
```

The TUI gives you a dashboard with live stats, detection history, and you can navigate around with keyboard shortcuts (Tab to switch views, Q to quit).

## Shell Completions

Ghost supports tab completion for Bash, Zsh, Fish, PowerShell, and Elvish.

```bash
# Generate completions for your shell
ghost completions bash > /etc/bash_completion.d/ghost
ghost completions zsh > ~/.zfunc/_ghost
ghost completions fish > ~/.config/fish/completions/ghost.fish

# Or use the install script
./completions/install.sh
```

See `completions/README.md` for detailed installation instructions.

## Optional Features

Ghost supports optional features that can be enabled during build:

```bash
# YARA rule scanning (requires libyara)
cargo build --features yara-scanning

# Neural ML integration (requires Python and trained models)
cargo build --features neural-ml

# eBPF detection (Linux only, currently stub implementation)
cargo build --features ebpf-detection
```

Note: ML features require trained models to function. See `ghost_ml/README.md` for training instructions.

## Configuration

You can tweak behavior with a TOML config file. Check `examples/ghost.toml` for a starting point. You can enable/disable specific detection methods, set confidence thresholds, skip system processes, and control how often it scans.

Example config snippet:

```toml
shellcode_detection = true
hollowing_detection = true
hook_detection = true
confidence_threshold = 0.3
skip_system_processes = true
scan_interval_ms = 2000
```

## Controlling Output Size

By default, Ghost limits output to 10 indicators per detection and deduplicates similar findings. For large scans, you can further reduce output:

**Command-line options:**

```bash
# Summary mode - outputs statistics instead of full details
ghost-cli --summary

# Limit indicators per detection
ghost-cli --max-indicators 5

# Only report malicious detections
ghost-cli --min-threat-level malicious

# Combine for minimal output
ghost-cli --summary --quiet
```

**Configuration file:**

```toml
[output]
verbosity = "minimal"          # minimal, normal, or verbose
max_indicators_per_detection = 5
min_threat_level = "suspicious"
deduplicate_indicators = true
summary_mode = true
```

This is useful when scanning many processes or running continuous monitoring where output files would otherwise grow too large.

## Watch Mode

Watch mode lets you monitor your system continuously without having to run scans manually. It's useful for catching injection attempts as they happen.

```bash
# Start watching (default: 5 second interval)
ghost-cli --watch

# Custom interval
ghost-cli --watch --interval 10

# Watch specific process
ghost-cli --watch --pid 1234

# Quiet mode - only alerts on new detections
ghost-cli --watch --quiet
```

When running in watch mode, Ghost:
- Shows only **new** detections (ones it hasn't seen before)
- Displays color-coded threat levels (red for malicious, yellow for suspicious)
- Prints timestamps with each scan cycle
- Gracefully shuts down on Ctrl+C

Example output:
```
[14:32:15] Scan #1: clean (142 processes, 89ms)
[14:32:20] Scan #2: 2 NEW detections! (2 total, 142 processes, 91ms)
  [MALICIOUS] suspicious.exe (PID: 4521) - 87% confidence
  [SUSPICIOUS] helper.dll (PID: 2201) - 54% confidence
[14:32:25] Scan #3: 2 known threats (142 processes, 88ms)
```

## Baseline Mode

Baseline mode captures a snapshot of your system's current state. Later scans can compare against this baseline to detect changes - useful for finding new threats without wading through known issues.

```bash
# Save current state as baseline
ghost-cli --save-baseline baseline.json

# Later: compare against baseline
ghost-cli --baseline baseline.json

# Combine with watch mode
ghost-cli --watch --baseline baseline.json
```

When comparing against a baseline, Ghost reports:
- **New threats**: Processes not in the baseline
- **Escalated threats**: Processes whose threat level increased
- **New indicators**: Known processes with new suspicious behaviors

Example output:
```
3 changes from baseline:

  New threats (1):
    injector.exe (PID: 8821) - Malicious

  Escalated threats (1):
    helper.dll (PID: 2201): Suspicious -> Malicious

  New indicators (1):
    svchost.exe (PID: 1024):
      - RWX memory region detected
      - Shellcode pattern match
```

Exit code is 1 if changes are detected, 0 if clean.

## Webhook Alerts

Ghost can send real-time alerts to Slack, Discord, or any HTTP endpoint when threats are detected. Perfect for SOC integration or getting notified on your phone.

```bash
# Slack webhook
ghost-cli --watch --webhook "https://hooks.slack.com/services/XXX/YYY/ZZZ"

# Discord webhook
ghost-cli --watch --webhook "https://discord.com/api/webhooks/123/abc"

# Generic HTTP POST (JSON payload)
ghost-cli --watch --webhook "https://your-siem.example.com/api/alerts"

# Override auto-detected type
ghost-cli --webhook "https://custom.url" --webhook-type slack
```

Ghost auto-detects the webhook type from the URL:
- `hooks.slack.com` → Slack format with attachments
- `discord.com/api/webhooks` → Discord format with embeds
- Everything else → Generic JSON payload

**Slack alerts** include color-coded attachments with threat level, confidence score, and top indicators:

```
🚨 Ghost detected suspicious activity on *prod-server-01*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 suspicious.exe (PID: 4521)
• RWX memory region detected at 0x7ff...
• Shellcode pattern: NOP sled
Threat Level: Malicious | Confidence: 87%
```

**Discord alerts** use rich embeds with the same information in a clean format.

**Generic webhooks** send a JSON payload:
```json
{
  "event": "ghost.detection",
  "timestamp": "2024-12-06T14:32:15Z",
  "hostname": "prod-server-01",
  "process_name": "suspicious.exe",
  "pid": 4521,
  "threat_level": "Malicious",
  "confidence": 0.87,
  "indicators": ["RWX memory region detected", "..."]
}
```

## What the results mean

When Ghost finds something suspicious, it assigns a threat level: Clean, Low, Medium, High, or Critical. This is based on how many indicators it found and how serious they are.

High confidence doesn't always mean malware - some legit software does weird stuff with memory too. Use your judgment and investigate further if needed.

## Platform differences

**Windows:** Fully functional. Process enumeration, memory reading, hook detection, process hollowing detection, PE validation, and thread analysis all work.

**Linux:** Functional core features. Process enumeration via procfs (`/proc`), memory reading, LD_PRELOAD detection, and ptrace-based injection detection work. eBPF support requires `ebpf-detection` feature flag and is currently a stub implementation.

**macOS:** Partial support. Process enumeration, memory region enumeration, memory reading, and thread enumeration work using mach VM APIs. Hook detection includes DYLD_INSERT_LIBRARIES detection and inline hook detection framework.

## Performance

It's designed to be fast enough for continuous monitoring. A full system scan (200 processes) usually takes under 5 seconds. Memory enumeration per process is around 50-100ms. The detection engine itself adds about 5-10ms per analysis.

## YARA rules

The tool includes YARA rule integration. Rules are stored in the `rules/` directory and cover common malware families like Metasploit, Cobalt Strike, generic shellcode patterns, and evasion techniques. You can add your own rules - just drop `.yar` files in that folder.

## Exit codes

- 0 = Everything looks clean
- 1 = Found suspicious processes
- 2 = Something went wrong (error during scan)

## Limitations

This is a userspace tool with the following limitations:

- **Kernel-level threats**: Cannot detect kernel rootkits or kernel-mode injection without kernel-level support (e.g., eBPF on Linux, which is currently a stub implementation)
- **Machine learning features**: Neural network analysis and behavioral ML predictions are simulated and require trained models to be functional
- **Threat intelligence**: The threat intelligence framework exists but has no active feed connections or IOC database
- **False positives**: Legitimate software like game anti-cheat, debuggers, sandboxes, and browsers with JIT compilers may trigger detections due to their memory manipulation techniques
- **macOS**: Hook detection fully implemented with DYLD_INSERT_LIBRARIES and inline hook detection using nm-based function address resolution
- **Performance claims**: Documented performance metrics are targets and have not been validated through comprehensive benchmarks

## Documentation

There's more detail in the `docs/` folder:

- `DETECTION_METHODS.md` - Explains how each detection technique works
- `MITRE_ATTACK_COVERAGE.md` - Lists which ATT&CK techniques are covered
- `PERFORMANCE_GUIDE.md` - Tips for tuning performance

Also check out `CONTRIBUTING.md` if you want to contribute, and `SECURITY.md` for the security policy.

## License

MIT. See the LICENSE file.

## A note on usage

This tool is for security research, testing your own systems, and catching actual threats. Don't use it on systems you don't own or don't have permission to test. Be responsible.

Also, if you're investigating a real incident, remember that malware can detect when it's being analyzed and might behave differently or shut down. Ghost tries to be stealthy but there's no guarantee advanced malware won't notice.
