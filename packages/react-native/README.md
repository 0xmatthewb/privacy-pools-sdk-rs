# @0xbow/privacy-pools-sdk

Thin React Native delivery surface for the Rust-first Privacy Pools SDK.

The JavaScript layer should stay intentionally small and delegate all proving,
Merkle, recovery, and planning work to native Rust-backed bindings.

Current package status:

- `src/index.ts` is a native-module facade only
- no protocol logic is implemented in JavaScript
- classic iOS/Android bridge modules are scaffolded against the generated Swift/Kotlin bindings
- withdraw proof generation and local proof verification are delegated to native Rust-backed bindings
- prepared withdraw/relay execution preflight is delegated to native Rust-backed bindings
- long-running proof/execution work can be started as native Rust-backed jobs and observed with explicit status polling, typed result retrieval, and best-effort cancellation
- signer registration for `local_dev`, `host_provided`, and `mobile_secure_storage` flows is delegated to native Rust-backed bindings
- signer-aware finalized transaction preparation for host/native signers is delegated to native Rust-backed bindings
- validated signed-transaction submission is delegated to native Rust-backed bindings
- `cargo run -p xtask -- react-native-package` stages package-local generated bindings
- `cargo run -p xtask -- react-native-package --release --with-native` additionally stages release iOS and Android native artifacts for packaging
- `npm run prepare:package-release:ios` stages the publishable iOS package surface, including the XCFramework
- `npm run prepare:package-release:android` stages the publishable Android package surface, including JNI libraries

Release packaging is validated per platform in CI. The iOS and Android release
paths stay split so each runner only builds the native artifacts it can support.
