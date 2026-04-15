# Pinned Circuit Inputs

This directory contains pinned circuit-side inputs used by the Rust SDK build
and test pipeline.

- `withdraw/withdraw.wasm`
  Source: `privacy-pools-core/packages/circuits/build/withdraw/withdraw_js/withdraw.wasm`
  Compatibility target: `@0xbow/privacy-pools-core-sdk@1.2.0`
  SHA-256: `36cda22791def3d520a55c0fc808369cd5849532a75fab65686e666ed3d55c10`
- `commitment/commitment.wasm`
  Source: `privacy-pools-core/packages/circuits/build/commitment/commitment_js/commitment.wasm`
  Compatibility target: `@0xbow/privacy-pools-core-sdk@1.2.0`
  SHA-256: `254d2130607182fd6fd1aee67971526b13cfe178c88e360da96dce92663828d8`
- `../artifacts/withdraw.zkey`
  Source: `privacy-pools-core/packages/circuits/trusted-setup/final-keys/withdraw.zkey`
  Compatibility target: `@0xbow/privacy-pools-core-sdk@1.2.0`
  SHA-256: `2a893b42174c813566e5c40c715a8b90cd49fc4ecf384e3a6024158c3d6de677`
- `../artifacts/withdraw.vkey.json`
  Source: `privacy-pools-core/packages/circuits/trusted-setup/final-keys/withdraw.vkey`
  Compatibility target: `@0xbow/privacy-pools-core-sdk@1.2.0`
  SHA-256: `666bd0983b20c1611543b04f7712e067fbe8cad69f07ada8a310837ff398d21e`
- `../artifacts/commitment.zkey`
  Source: `privacy-pools-core/packages/circuits/trusted-setup/final-keys/commitment.zkey`
  Compatibility target: `@0xbow/privacy-pools-core-sdk@1.2.0`
  SHA-256: `494ae92d64098fda2a5649690ddc5821fcd7449ca5fe8ef99ee7447544d7e1f3`
- `../artifacts/commitment.vkey.json`
  Source: `privacy-pools-core/packages/circuits/trusted-setup/final-keys/commitment.vkey`
  Compatibility target: `@0xbow/privacy-pools-core-sdk@1.2.0`
  SHA-256: `7d48b4eb3dedc12fb774348287b587f0c18c3c7254cd60e9cf0f8b3636a570d8`

The Rust prover crate transpiles the pinned witness generator wasm into native
code so the SDK can own compiled `rust-witness + arkworks` proving paths without
changing contracts or circuits.
