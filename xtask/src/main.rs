use anyhow::{Context, Result, anyhow, bail, ensure};
use camino::Utf8PathBuf;
use privacy_pools_sdk_artifacts::verify_signed_manifest_artifact_files;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fmt::Write,
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use uniffi::{
    GenerateOptions, SwiftBindingsOptions, TargetLanguage, generate, generate_swift_bindings,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("bindings") => generate_bindings(false),
        Some("bindings-release") => generate_bindings(true),
        Some("preflight") => preflight(),
        Some("react-native-package") => stage_react_native_package(args.collect()),
        Some("react-native-smoke") => react_native_smoke(),
        Some("react-native-app-smoke-ios") => react_native_app_smoke("ios"),
        Some("react-native-app-smoke-android") => react_native_app_smoke("android"),
        Some("mobile-smoke-local") => mobile_smoke_local(args.collect()),
        Some("sdk-web-package") => stage_sdk_web_package(args.collect()),
        Some("sdk-smoke") => sdk_smoke(),
        Some("examples-check") => examples_check(),
        Some("feature-check") => feature_check(),
        Some("package-check") => package_check(),
        Some("dependency-check") => dependency_check(),
        Some("docs-check") => docs_check(),
        Some("action-pins") => action_pins(),
        Some("regenerate-generated") => regenerate_generated(args.collect()),
        Some("check-internal-cycles") => check_internal_cycles(),
        Some("check-binding-parity") => check_binding_parity(),
        Some("ffi-input-bound-lint") => ffi_input_bound_lint(),
        Some("write-cargo-audit-config") => write_cargo_audit_config(),
        Some("artifact-fingerprints") => artifact_fingerprints(args.collect()),
        Some("geiger-delta-check") => geiger_delta_check(),
        Some("signed-manifest-sample-check") => signed_manifest_sample_check(),
        Some("release-check") => release_check(args.collect()),
        Some("evidence-check") => evidence_check(args.collect()),
        Some("mobile-evidence-check") => mobile_evidence_check(args.collect()),
        Some("release-acceptance-check") => release_acceptance_check(args.collect()),
        Some("external-evidence-assemble") => external_evidence_assemble(args.collect()),
        Some("assurance") => assurance(args.collect()),
        Some("assurance-merge") => assurance_merge(args.collect()),
        Some("audit-pack") => audit_pack(args.collect()),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => bail!("unknown xtask command: {other}"),
    }
}

fn print_help() {
    println!("xtask");
    println!();
    println!("commands:");
    println!("  bindings         build the FFI cdylib and generate Swift/Kotlin bindings");
    println!("  bindings-release build release FFI artifacts and generate bindings from them");
    println!("  react-native-package");
    println!("                   stage package-local React Native bindings");
    println!(
        "                   flags: --release --with-ios-native --with-android-native --with-native"
    );
    println!("  react-native-smoke");
    println!(
        "                   install the packed RN package into the sample app and typecheck it"
    );
    println!("  react-native-app-smoke-ios");
    println!("                   run the packed RN package in an iOS Simulator app process");
    println!("  react-native-app-smoke-android");
    println!("                   run the packed RN package in an Android Emulator app process");
    println!("  mobile-smoke-local");
    println!(
        "                   run local mobile smoke orchestration for ios|android|all and native|react-native|all surfaces"
    );
    println!(
        "                   flags: [--platform ios|android|all] [--surface native|react-native|all] [--out-dir <path>] [--evidence-out-dir <path>]"
    );
    println!("  sdk-web-package");
    println!("                   build optimized browser WASM bindings");
    println!("                   flags: --debug --release --experimental-threaded");
    println!("  sdk-smoke");
    println!("                   build the SDK package runtimes and run the JS integration tests");
    println!("  examples-check   run lightweight Rust SDK examples");
    println!("  feature-check    check supported Rust feature and wasm combinations");
    println!("  package-check    run the workspace package dry run");
    println!("  dependency-check validate accepted dependency-risk advisories");
    println!("  docs-check       validate dependency-policy docs stay in sync");
    println!("  preflight        run the local PR preflight assurance subset");
    println!(
        "                   alias for `cargo run -p xtask -- assurance --profile pr --runtime rust`"
    );
    println!("  action-pins      validate GitHub Actions references stay SHA pinned");
    println!("  regenerate-generated");
    println!("                   regenerate checked-in browser and mobile bindings");
    println!("                   flags: [--check]");
    println!("  check-internal-cycles");
    println!(
        "                   fail if the Rust workspace has a non-dev internal dependency cycle"
    );
    println!("  check-binding-parity");
    println!(
        "                   validate safe-surface export parity and structured binding error enums"
    );
    println!("  ffi-input-bound-lint");
    println!(
        "                   require bounded JSON or byte parsing for binding entrypoints that cross the FFI boundary"
    );
    println!("  write-cargo-audit-config");
    println!("                   write ~/.cargo/audit.toml from security/advisories.toml");
    println!("  artifact-fingerprints");
    println!("                   verify or refresh checked-in artifact fingerprint snapshots");
    println!("                   flags: --check | --update");
    println!("  geiger-delta-check");
    println!("                   validate unsafe usage against security/unsafe-allowlist.json");
    println!("  signed-manifest-sample-check");
    println!("                   validate the checked-in signed manifest fixture");
    println!("  release-check    validate release-channel versions across public surfaces");
    println!("                   flags: --channel alpha|beta|rc|stable");
    println!("  evidence-check   compatibility alias for external assurance evidence validation");
    println!(
        "                   flags: --channel alpha|beta|rc|stable --dir <path> [--backend stable] [--signed-manifest-public-key <hex>]"
    );
    println!("  mobile-evidence-check");
    println!("                   validate mobile-smoke.json and mobile-parity.json evidence");
    println!("                   flags: --dir <path>");
    println!("  release-acceptance-check");
    println!("                   validate release evidence against the release assurance policy");
    println!("                   flags: --dir <path> [--backend stable]");
    println!("  external-evidence-assemble");
    println!(
        "                   materialize the shared external evidence layout for nightly or release"
    );
    println!(
        "                   flags: --mode nightly|release --out-dir <path> [--mobile-evidence-dir <path>] [--reference-benchmarks-dir <path>] [--sbom-dir <path>] [--packages-dir <path>] [--attestation-metadata-dir <path>]"
    );
    println!("  assurance        run the shared assurance catalog for one profile/runtime");
    println!(
        "                   flags: --profile pr|nightly|release --runtime rust|node|browser|react-native|all [--report-mode standard|audit] [--out-dir <path>] [--backend stable] [--device-label desktop] [--device-model <model>] [--v1-package-path <path>] [--v1-source-path <path>] [--external-evidence-dir <path>] [--fuzz-runs <n>] [--skip-fuzz] [--only-checks <id,id,...>]"
    );
    println!("  assurance-merge  merge subgroup assurance outputs into one aggregate bundle");
    println!(
        "                   flags: --profile pr|nightly|release --runtime rust|node|browser|react-native|all --inputs <path> [--inputs <path> ...] --out-dir <path>"
    );
    println!("  audit-pack       assemble a one-time Rust SDK audit evidence pack");
    println!(
        "                   flags: [--out-dir <path>] [--backend stable] [--device-label desktop] [--device-model <model>] [--v1-package-path <path>] [--v1-source-path <path>] [--external-evidence-dir <path>] [--fuzz-runs <n>] [--skip-fuzz]"
    );
    println!("                   note: release assurance requires --external-evidence-dir");
}

include!("commands/native_build.rs");
include!("shared/process.rs");
include!("shared/git.rs");
include!("shared/device.rs");
include!("shared/wasm.rs");
include!("commands/bindings.rs");
include!("commands/checks.rs");
include!("commands/release.rs");
include!("commands/assurance_cli.rs");
include!("assurance/merge.rs");
include!("assurance/run.rs");
include!("assurance/catalog.rs");
include!("assurance/findings.rs");
include!("evidence/external.rs");
include!("opts/mod.rs");
include!("policy/mod.rs");

#[cfg(test)]
#[path = "../tests/unit/mod.rs"]
mod tests;
