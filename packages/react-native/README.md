# @0xbow/privacy-pools-sdk

Thin React Native delivery surface for the Rust-first Privacy Pools SDK.

The JavaScript layer should stay intentionally small and delegate all proving,
Merkle, recovery, and planning work to native Rust-backed bindings.

Current package status:

- `src/index.ts` is a native-module facade only
- no protocol logic is implemented in JavaScript
- classic iOS/Android bridge modules are scaffolded against the generated Swift/Kotlin bindings
- the Rust FFI artifacts still need to be built for mobile targets before the package can run in an app
