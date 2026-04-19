# Preflight

Run the local Rust PR preflight before you push:

```sh
cargo run -p xtask -- preflight
```

This is a thin alias for:

```sh
cargo run -p xtask -- assurance --profile pr --runtime rust
```

To install it as an opt-in Git hook:

```sh
ln -s ../../scripts/hooks/pre-push.sh .git/hooks/pre-push
```
