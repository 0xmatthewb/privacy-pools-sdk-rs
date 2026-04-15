# @0xmatthewb/privacy-pools-sdk

Unified browser and Node package surface for the Rust-first Privacy Pools SDK.

Current status:

- Node uses a direct Rust native addon built from `crates/privacy-pools-sdk-node`
- React Native remains a separate package at `@0xmatthewb/privacy-pools-sdk-react-native`
- browser exports and the `./worker` entrypoint are present, but browser proving is
  still blocked on the Rust web prover backend

This package does not reimplement protocol logic in JavaScript. The Node runtime
delegates to Rust for key derivation, commitments, Merkle helpers, artifact
verification, session preparation, proving, and proof verification.

Useful commands:

- `npm run build:native` builds the Node addon in debug mode
- `npm run build:native:release` builds the Node addon in release mode
- `npm test` builds the addon and runs the Node integration tests
