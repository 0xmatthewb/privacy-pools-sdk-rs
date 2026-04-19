# Benchmarking

Use `benchmark-withdraw` to measure the SDK's local `withdraw` proving path.
Benchmark reports are informational performance evidence; they do not block PRs,
release assurance, or promotion.

```sh
cargo run --release -p privacy-pools-sdk-cli -- benchmark-withdraw \
  --manifest /absolute/path/to/artifact-manifest.json \
  --artifacts-root /absolute/path/to/artifacts \
  --backend stable \
  --warmup 1 \
  --iterations 5 \
  --report-json ./dist/desktop-withdraw-stable.json \
  --device-label desktop \
  --device-model "apple-m4-max"
```

The benchmark reports:

- verified bundle loading and hash verification time
- session preload time for parsing and caching proving/verifying artifacts
- aggregate artifact preload time for compatibility with older evidence tooling
- cold first-proof latency for the first end-to-end Rust SDK iteration
- typed withdraw circuit-input preparation from the reference compatibility
  fixtures
- compiled witness generation through the Rust witness adapter
- end-to-end withdraw proof generation through the Rust SDK
- local proof verification through the Rust SDK
- best-effort peak resident memory on supported host platforms
- optional structured JSON benchmark report for trend comparisons or release
  notes
- benchmark fingerprint fields for commit, manifest hash, artifact-bundle hash,
  toolchain, OS, CPU/device class, and scenario id

Notes:

- The benchmark uses the checked-in compatibility fixtures for the withdraw
  witness shape, but it expects a real verified artifact bundle for `withdraw`.
- `fixtures/artifacts/sample-proving-manifest.json` is only a structural sample
  and does not contain a real proving key, so it is not suitable for real
  benchmark runs.
- The benchmark CLI now refuses debug builds by default because they produce
  misleading proving timings. Use `--allow-debug-build` only for diagnostics.
- The benchmark evidence path accepts only the stable `arkworks` backend.
- `--report-json` writes machine-readable timing summaries and per-iteration
  samples, which is the preferred format for release evidence bundles.
- JSON reports include separate cold `bundle_verification_ms` and
  `session_preload_ms` fields, plus warm per-iteration summaries for input
  preparation, witness generation, proof generation, verification, and
  prove+verify end-to-end.
- JSON reports now also include `manifest_sha256`,
  `artifact_bundle_sha256`, `rustc_version_verbose`, `cargo_version`,
  `cpu_model`, `device_class`, and `benchmark_scenario_id` so release evidence
  can be compared against a stable environment fingerprint.
- When writing JSON, pass both `--device-label` and `--device-model`. The
  assurance runner preserves those fields for informational comparison and
  freshness reporting when benchmark evidence is attached to nightly or release
  bundles.
- Peak resident memory is currently a best-effort host metric from the OS; it
  may be unavailable on unsupported platforms.
