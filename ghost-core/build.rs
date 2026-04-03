fn main() {
    // When building with the GNU toolchain on Windows, vendored YARA modules
    // use CryptoAPI/token APIs that live in `advapi32`.
    //
    // The upstream crates don't always add this link dependency for Windows-GNU,
    // so we force it whenever the `yara-scanning` feature is enabled.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_YARA_SCANNING");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENV");

    let yara_enabled = std::env::var_os("CARGO_FEATURE_YARA_SCANNING").is_some();

    // NOTE: Build scripts are compiled for the *host*, so `cfg!(target_env = "gnu")` would
    // reflect the host toolchain, not the requested build target. Use Cargo's target cfg env vars.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if yara_enabled && target_os == "windows" && target_env == "gnu" {
        println!("cargo:rustc-link-lib=advapi32");
    }
}
