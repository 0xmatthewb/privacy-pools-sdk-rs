fn build_ffi_cdylib(workspace_root: &Utf8PathBuf, release: bool) -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .arg("build")
        .arg("-p")
        .arg("privacy-pools-sdk-ffi")
        .arg("--lib")
        .arg("--locked");

    if !release {
        command.arg("--features").arg("dangerous-exports");
    }

    if release {
        command.arg("--release");
    }

    let status = command
        .current_dir(workspace_root)
        .status()
        .context("failed to invoke cargo build for privacy-pools-sdk-ffi")?;

    if !status.success() {
        bail!("cargo build for privacy-pools-sdk-ffi failed");
    }

    Ok(())
}

fn build_ios_native_artifacts(workspace_root: &Utf8PathBuf) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("--with-ios-native requires running on macOS");
    }

    run_shell_script(
        workspace_root,
        &workspace_root.join("bindings/ios/scripts/build-xcframework.sh"),
        "failed to build iOS XCFramework",
    )
}

fn build_android_native_artifacts(workspace_root: &Utf8PathBuf) -> Result<()> {
    run_shell_script(
        workspace_root,
        &workspace_root.join("bindings/android/scripts/build-aar.sh"),
        "failed to build Android native libraries",
    )
}
