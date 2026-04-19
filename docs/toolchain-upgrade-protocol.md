# Toolchain Upgrade Protocol

Use a dedicated PR for any Rust, cargo-fuzz, binaryen, or install-rust-ci-tools bump.

Required sequence:

1. Update the pinned tool version in the source-of-truth workflow or action file.
2. Run `cargo run -p xtask -- regenerate-generated` if the change can affect generated browser or native artifacts.
3. Run the normal local Rust gate with `cargo run -p xtask -- preflight`.
4. Run the warn-only sweep when the PR touches toolchain files:
   `RUSTFLAGS="--cap-lints=warn" cargo clippy --workspace --all-targets --all-features --locked --message-format=json`.
5. Wait for the weekly `toolchain-canary` follow-up signal or the PR `toolchain-upgrade-sweep` artifact before merging.

Keep toolchain bumps isolated from product work so lint and artifact drift stay reviewable.
