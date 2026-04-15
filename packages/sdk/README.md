# @0xmatthewb/privacy-pools-sdk

Unified browser and Node package surface for the Rust-first Privacy Pools SDK.

Current status:

- Node uses a direct Rust native addon built from `crates/privacy-pools-sdk-node`
- React Native remains a separate package at `@0xmatthewb/privacy-pools-sdk-react-native`
- browser uses a Rust/WASM runtime for key derivation, commitments, Merkle
  helpers, withdrawal input shaping, manifest-bound artifact verification, and
  proof generation and verification
- browser proving runs witnesses from manifest-pinned circuit `.wasm` artifacts
  and passes witness values into the portable Rust/WASM prover with verified
  `zkey` bytes; Rust/WASM owns artifact verification, `zkey` parsing, proof
  construction, manifest-bound `vkey` checks, and final proof verification, and
  the browser build does not compile or link the `rust-witness` generated
  C/native path

This package does not reimplement protocol logic in JavaScript. The Node runtime
delegates to Rust for key derivation, commitments, Merkle helpers, artifact
verification, session preparation, proving, and proof verification. The browser
runtime delegates protocol helpers, artifact verification, session preparation,
proof construction, manifest-bound verification key checks, and proof
verification to the Rust `privacy-pools-sdk-web` crate. Its JavaScript
worker/runtime glue only hosts browser APIs, worker transport, artifact
fetching, status events, and circuit `.wasm` witness execution.

Useful commands:

- `npm run build:native` builds the Node addon in debug mode
- `npm run build:native:release` builds the Node addon in release mode
- `npm run build:web` builds the browser WASM bundle in release mode
- `npm run build:web:debug` builds the browser WASM bundle in debug mode
- `npm run build:web:release` builds the browser WASM bundle in release mode
- `npm test` builds both runtimes and runs the Node and browser integration tests
