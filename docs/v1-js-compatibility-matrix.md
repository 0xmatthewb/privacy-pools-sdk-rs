# v1 JS Compatibility Matrix

This matrix tracks the `@0xbow/privacy-pools-core-sdk@1.2.0` public JS surface
against this Rust-first SDK package. The goal is source-level familiarity for
website consumers without reintroducing TypeScript protocol, hashing, proving,
verification, or recovery implementations.

## Runtime Boundary

- Protocol helpers, key derivation, commitments, Merkle helpers, circuit input
  shaping, artifact verification, proving, verification, recovery replay, and
  transaction planning are Rust-backed.
- JavaScript may fetch artifacts/events, host browser workers, adapt DTO shapes,
  and expose v1-compatible class/function names.
- Free-floating verification keys are not accepted. `vkey` bytes are only used
  after Rust verifies them as part of a manifest-bound bundle.
- Browser and facade helper functions are async because Rust/WASM initialization
  and native addon calls are async. This is an intentional divergence from v1
  sync crypto helpers.

## Exports

| v1 item | Status | Rust-backed mapping or divergence |
| --- | --- | --- |
| `Circuits` | implemented wrapper | Uses manifest-bound artifacts and `PrivacyPoolsSdkClient.verifyArtifactBytes`; caches only verified bytes. |
| `CircuitName`, `Version`, `circuitToAsset` | implemented wrapper | Constants match v1 names; `merkleTree` remains unsupported unless a manifest is supplied. |
| `PrivacyPoolSDK` | implemented wrapper | Delegates commitment/withdrawal proof methods to service wrappers. |
| `CommitmentService` | implemented wrapper | Uses Rust-backed commitment construction, proving, and verification. |
| `WithdrawalService` | implemented wrapper | Uses Rust-backed withdrawal proving/verification; callers must provide withdrawal data or a prepared Rust-shaped request. |
| `AccountService` | partial wrapper | Exposes Rust-backed recovery checkpointing, recovery keyset derivation, account-state replay, and spendable commitment selection from an explicit recovered-state DTO. Legacy JS account mutation/sync paths still throw `CompatibilityError`. |
| `DataService` | implemented wrapper | Exposes public chain event fetching through caller-provided RPC/client transport, plus Rust-backed recovery checkpointing and account-state replay. Event fetching returns public deposit, withdrawal, and ragequit DTOs only; recovered state and secrets remain caller-owned local data. |
| `ContractInteractionsService` | implemented wrapper | Node and browser expose Rust-backed offline root-read, current-root, proof-formatting, and transaction-planning helpers. RPC preflight/submission remains an app-owned transport concern so the SDK does not take raw private keys or sign transactions. |
| `BlockchainProvider` | implemented wrapper | Constructor validates HTTP(S)-style RPC URLs like v1; `getBalance` reads public balances through caller-provided or lazily created `viem` public-client transport. |
| `DEFAULT_LOG_FETCH_CONFIG` | implemented constant | Matches v1 log-fetch defaults for callers that still import the constant. |
| `generateMasterKeys` | implemented wrapper | Delegates to `deriveMasterKeys`. |
| `generateDepositSecrets` | implemented wrapper | Delegates to Rust-backed deposit secret derivation. |
| `generateWithdrawalSecrets` | implemented wrapper | Delegates to Rust-backed withdrawal secret derivation. |
| `getCommitment` | implemented wrapper | Delegates to Rust and returns v1 nested `preimage` plus flat compatibility fields. |
| `generateMerkleProof` | implemented wrapper | Delegates to Rust-backed Merkle helper. |
| `calculateContext` | implemented wrapper | Delegates to Rust-backed withdrawal context calculation. |
| `bigintToHash`, `bigintToHex` | JS shape helper | Pure representation helpers; no protocol hashing. |
| `hashPrecommitment` | implemented wrapper | Async intentional divergence; delegates through Rust-backed commitment construction and returns the Rust-computed precommitment hash. |
| `checkpointRecovery` | implemented wrapper | Delegates to Rust recovery checkpointing; accepts camelCase and snake_case event/policy DTOs through facade normalization. |
| `deriveRecoveryKeyset`, `recoverAccountState`, `recoverAccountStateWithKeyset` | implemented wrapper | Delegates to Rust recovery replay in Node and browser/WASM. Returned recovered-state DTOs contain spendable nullifier/secret material and are not retained by facade services; callers pass state explicitly to `AccountService.getSpendableCommitments(state)`. |
| `formatGroth16ProofBundle`, transaction/root helpers | implemented wrapper | Node delegates to native Rust bindings, and browser delegates to Rust/WASM bindings. Both surfaces keep proof formatting and transaction calldata planning local. |
| Error classes | implemented wrappers | Export v1 names and `CompatibilityError` with stable `code` values. |

## Intentional Divergences

- `getStateRoot()`/current-root behavior follows the corrected current-root
  semantics documented in the compatibility baseline, not the stale v1 behavior.
- Artifact methods require a manifest-bound trust root. Callers cannot pass an
  arbitrary `vkey` and ask the SDK to trust it.
- Browser proving uses the manifest-pinned circuit `.wasm` only for witness
  execution, then Rust/WASM owns proof construction and verification.
- Unsupported legacy methods fail closed with `CompatibilityError` instead of
  falling back to JS protocol logic.

## Follow-Up Bindings

The next facade pass should focus on app-owned RPC preflight/submission adapters
only if they preserve the current signing boundary: the SDK may plan calldata,
but applications must own wallet transport, user consent, and signing.
