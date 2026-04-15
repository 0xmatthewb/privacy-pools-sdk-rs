# @0xmatthewb/privacy-pools-sdk

Unified browser and Node package surface for the Rust-first Privacy Pools SDK.

Current status:

- Node uses a direct Rust native addon built from `crates/privacy-pools-sdk-node`
- React Native remains a separate package at `@0xmatthewb/privacy-pools-sdk-react-native`
- browser uses a Rust/WASM runtime for key derivation, commitments, Merkle
  helpers, withdrawal input shaping, manifest-bound artifact verification, and
  proof verification
- browser proving is still blocked on the Rust web prover backend

This package does not reimplement protocol logic in JavaScript. The Node runtime
delegates to Rust for key derivation, commitments, Merkle helpers, artifact
verification, session preparation, proving, and proof verification. The browser
runtime delegates the currently supported browser-safe APIs to the Rust
`privacy-pools-sdk-web` crate, including proof verification, and leaves
proving-specific methods fail-closed until the wasm prover path is ready.

Useful commands:

- `npm run build:native` builds the Node addon in debug mode
- `npm run build:native:release` builds the Node addon in release mode
- `npm run build:web` builds the browser WASM bundle in release mode
- `npm run build:web:debug` builds the browser WASM bundle in debug mode
- `npm run build:web:release` builds the browser WASM bundle in release mode
- `npm test` builds both runtimes and runs the Node and browser integration tests
