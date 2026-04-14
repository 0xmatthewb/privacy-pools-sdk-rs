# @0xbow/privacy-pools-sdk

Thin React Native delivery surface for the Rust-first Privacy Pools SDK.

The JavaScript layer should stay intentionally small and delegate all proving,
Merkle, recovery, and planning work to native Rust-backed bindings.

Current package status:

- `src/index.ts` is a native-module facade only
- no protocol logic is implemented in JavaScript
- iOS and Android native packaging still need to be generated and wired
