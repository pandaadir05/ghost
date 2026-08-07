//! Integration tests for the shipped YARA ruleset.
//!
//! Only meaningful with the `yara-scanning` feature enabled - without it,
//! `DynamicYaraEngine::compile_rules` is a stub that always errors. This
//! guards against the two failure modes a unit test on `detection.rs` alone
//! cannot see: a rule file that fails to compile, and the real scan pipeline
//! (compile -> read process memory -> match) erroring or panicking.

#![cfg(feature = "yara-scanning")]

use ghost_core::process::ProcessInfo;
use ghost_core::yara_engine::DynamicYaraEngine;

/// Path to the rules shipped in the repository (not an installed copy).
fn rules_dir() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../rules").to_string()
}

#[test]
fn shipped_rules_compile() {
    let mut engine = DynamicYaraEngine::new(Some(&rules_dir())).expect("engine construction");

    let rule_count = engine
        .compile_rules()
        .expect("every file under rules/ should compile");

    // `compile_rules` returns the number of `rule`/`private rule`
    // declarations across all accepted files; `get_rule_count` returns the
    // number of accepted *files* - these are intentionally different units.
    assert!(rule_count > 0, "expected at least one compiled rule");
    assert!(engine.is_compiled());
    assert!(
        engine.get_rule_count() > 0,
        "expected at least one accepted rule file"
    );
}

#[tokio::test]
async fn scanning_the_current_process_does_not_error() {
    let mut engine = DynamicYaraEngine::new(Some(&rules_dir())).expect("engine construction");
    engine.compile_rules().expect("rules should compile");

    let pid = std::process::id();
    let process = ProcessInfo::new(pid, 0, "yara_tests".to_string());
    let regions = ghost_core::memory::enumerate_memory_regions(pid)
        .expect("should be able to enumerate our own process's memory regions");

    let result = engine.scan_process(&process, &regions).await;

    assert!(
        result.is_ok(),
        "scanning a live process with the shipped rules should not error: {:?}",
        result.err()
    );
}
