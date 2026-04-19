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
- one-shot browser proving first prepares a Rust/WASM-verified session, then
  executes the verified session's circuit `.wasm` for witness generation, so a
  bad artifact hash fails before WebAssembly instantiation
- browser proof-capable session artifacts are kept in an explicit bounded cache
  with a default capacity of four sessions; call `clearCircuitSessionCache()` on
  a client or `clearBrowserCircuitSessionCache()` from the runtime to release
  cached browser session artifacts and their matching Rust/WASM sessions
- browser callers should invoke `proveWithdrawalWithSession()` from a Web
  Worker via `createWorkerClient(...)`; calling it on the main thread will
  freeze the page until proof generation completes
- the v1 facade can fetch public deposit, withdrawal, and ragequit logs through
  caller-provided RPC/client transport, then pass those public event DTOs into
  Rust-backed recovery helpers; mnemonics, nullifier secrets, witnesses, and
  proofs stay local to the caller process

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
- `npm run test:node` runs the Node and Node-worker integration tests
- `npm run test:browser` runs the Chromium module-worker integration tests
- `npm run check:generated` rebuilds browser bindings and enforces deterministic
  JS/TypeScript interface drift plus browser WASM structural invariants
- exact packaged `privacy_pools_sdk_web_bg.wasm` validation happens in the
  canonical Linux release packaging path, not the fast PR drift gate
- `npm test` builds both runtimes and runs the full SDK CI test suite
