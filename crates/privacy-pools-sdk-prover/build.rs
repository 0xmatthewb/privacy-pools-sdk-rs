use camino::Utf8PathBuf;
use std::process::Command;

fn main() {
    ensure_apple_sdk_available();

    let circuits_dir = Utf8PathBuf::from_path_buf(
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../../fixtures/circuits"),
    )
    .expect("fixtures/circuits path should be valid utf-8");

    println!(
        "cargo:rerun-if-changed={}",
        circuits_dir.join("withdraw/withdraw.wasm")
    );
    println!(
        "cargo:rerun-if-changed={}",
        circuits_dir.join("commitment/commitment.wasm")
    );

    rust_witness::transpile::transpile_wasm(circuits_dir.into_string());
}

fn ensure_apple_sdk_available() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let sdk = match target.as_str() {
        "aarch64-apple-ios" => Some("iphoneos"),
        "aarch64-apple-ios-sim" | "x86_64-apple-ios" => Some("iphonesimulator"),
        _ => None,
    };

    let Some(sdk) = sdk else {
        return;
    };

    let output = Command::new("xcrun")
        .args(["--show-sdk-path", "--sdk", sdk])
        .output();

    match output {
        Ok(result) if result.status.success() => {}
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr).trim().to_owned();
            fail_missing_apple_sdk(&target, sdk, Some(stderr));
        }
        Err(error) => fail_missing_apple_sdk(&target, sdk, Some(error.to_string())),
    }
}

fn fail_missing_apple_sdk(target: &str, sdk: &str, detail: Option<String>) -> ! {
    let developer_dir = Command::new("xcode-select")
        .arg("-p")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "<unknown>".to_owned());

    let license_blocked = detail
        .as_deref()
        .is_some_and(|value| value.contains("license agreements"));
    let developer_dir_uses_clt = developer_dir.contains("CommandLineTools");

    let mut message = if license_blocked {
        format!(
            "building privacy-pools-sdk-prover for {target} requires the Apple {sdk} SDK, \
and Xcode is installed, but the Apple SDK license has not been accepted yet. Run \
`sudo xcodebuild -license accept` (or open Xcode and complete first launch), then retry.\n\
\nCurrent xcode-select path: {developer_dir}"
        )
    } else if developer_dir_uses_clt {
        format!(
            "building privacy-pools-sdk-prover for {target} requires the Apple {sdk} SDK, \
which is only available from a full Xcode installation. Command Line Tools alone are \
not enough. Install Xcode, then point xcode-select at \
/Applications/Xcode.app/Contents/Developer before retrying.\n\
\nCurrent xcode-select path: {developer_dir}"
        )
    } else {
        format!(
            "building privacy-pools-sdk-prover for {target} requires the Apple {sdk} SDK. \
Make sure full Xcode is installed, its license has been accepted, and `xcode-select` points \
at /Applications/Xcode.app/Contents/Developer before retrying.\n\
\nCurrent xcode-select path: {developer_dir}"
        )
    };

    if let Some(detail) = detail.filter(|value| !value.is_empty()) {
        message.push_str(&format!("\nUnderlying xcrun error: {detail}"));
    }

    panic!("{message}");
}
