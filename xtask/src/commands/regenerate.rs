fn regenerate_generated(args: Vec<String>) -> Result<()> {
    let check = match args.as_slice() {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => bail!("regenerate-generated accepts only an optional --check flag"),
    };

    let workspace_root = workspace_root()?;
    let generated_dirs = [
        workspace_root.join("packages/sdk/src/browser/generated"),
        workspace_root.join("packages/sdk/src/browser/generated-threaded"),
        workspace_root.join("bindings/ios/generated"),
        workspace_root.join("bindings/android/generated/src/main"),
    ];
    for path in &generated_dirs {
        remove_path_if_exists(path)?;
    }

    generate_bindings(true)?;
    stage_sdk_web_package(vec!["--release".to_owned()])?;
    stage_sdk_web_package(vec![
        "--release".to_owned(),
        "--experimental-threaded".to_owned(),
    ])?;

    if check {
        run_command(
            "git",
            &[
                "diff",
                "--exit-code",
                "--",
                "packages/sdk/src/browser/generated",
                "packages/sdk/src/browser/generated-threaded",
                "bindings/ios/generated",
                "bindings/android/generated/src/main",
            ],
            &workspace_root,
            "generated artifacts drifted — run `cargo run -p xtask -- regenerate-generated` and commit the diff",
        )?;
    }

    println!("regenerate-generated ok");
    Ok(())
}
