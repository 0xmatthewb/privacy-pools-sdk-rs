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

    let mut message = format!(
        "building privacy-pools-sdk-prover for {target} requires the Apple {sdk} SDK, \
which is only available from a full Xcode installation. Command Line Tools alone are \
not enough. Install Xcode, then point xcode-select at \
/Applications/Xcode.app/Contents/Developer before retrying.\n\
\nCurrent xcode-select path: {developer_dir}"
    );

    if let Some(detail) = detail.filter(|value| !value.is_empty()) {
        message.push_str(&format!("\nUnderlying xcrun error: {detail}"));
    }

    panic!("{message}");
}
