// This test proves the YARA engine is wired correctly without requiring any
// potentially harmful payloads.
//
// Run with:
//   cargo test -p ghost-core --features yara-scanning

#![cfg(feature = "yara-scanning")]

// Force-link `ghost_core` so its Windows-GNU `advapi32` link shim propagates into
// this integration test binary. Without this, linking can fail on `x86_64-pc-windows-gnu`
// because vendored YARA modules reference CryptoAPI/token APIs.
extern crate ghost_core as _;

use yara::Compiler;

#[test]
fn yara_can_scan_a_simple_memory_buffer() {
    let rules_str = r#"
        rule ghost_canary {
          strings:
            $a = "GHOST_YARA_CANARY_123" ascii
          condition:
            $a
        }
    "#;

    let compiler = Compiler::new().expect("compiler");
    let compiler = compiler.add_rules_str(rules_str).expect("parse rules");
    let rules = compiler.compile_rules().expect("compile rules");

    let mut buf = vec![0u8; 256];
    let needle = b"GHOST_YARA_CANARY_123";
    buf[100..100 + needle.len()].copy_from_slice(needle);

    let matches = rules.scan_mem(&buf, 5).expect("scan");

    assert!(matches.iter().any(|r| r.identifier == "ghost_canary"));
}
