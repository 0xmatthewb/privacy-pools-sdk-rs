# Regeneration

Run:

```sh
cargo run -p xtask -- regenerate-generated
```

This refreshes:

- `packages/sdk/src/browser/generated/`
- `packages/sdk/src/browser/generated-threaded/`
- `bindings/ios/generated/`
- `bindings/android/generated/src/main/`

To assert the checked-in outputs are fresh without keeping the diff:

```sh
cargo run -p xtask -- regenerate-generated --check
```

CI also enforces a schema-aware guard: changes under
`crates/privacy-pools-sdk-{ffi,web,node,core}/src/**` are expected to come with
the matching generated artifact updates.
