# Benchmarking

Use `benchmark-withdraw` to measure the SDK's local `withdraw` proving path.

```sh
cargo run -p privacy-pools-sdk-cli -- benchmark-withdraw \
  --manifest /absolute/path/to/artifact-manifest.json \
  --artifacts-root /absolute/path/to/artifacts \
  --backend stable \
  --warmup 1 \
  --iterations 5 \
  --report-json ./dist/withdraw-benchmark.json
```

The benchmark reports:

- artifact resolution time for the verified withdraw bundle
- cold first-proof latency for the first end-to-end Rust SDK iteration
- typed withdraw circuit-input preparation from the reference compatibility
  fixtures
- compiled witness generation through the Rust witness adapter
- end-to-end withdraw proof generation through the Rust SDK
- local proof verification through the Rust SDK
- best-effort peak resident memory on supported host platforms
- optional structured JSON benchmark report for device-to-device comparisons

Notes:

- The benchmark uses the checked-in compatibility fixtures for the withdraw
  witness shape, but it expects a real verified artifact bundle for `withdraw`.
- `fixtures/artifacts/sample-proving-manifest.json` is only a structural sample
  and does not contain a real proving key, so it is not suitable for real
  benchmark runs.
- `--backend fast` requires a build with the `rapidsnark` feature enabled and a
  supported target; the stable `arkworks` backend remains the default.
- `--report-json` writes machine-readable timing summaries and per-iteration
  samples, which is the preferred format for future mobile-device benchmark
  collection.
- Peak resident memory is currently a best-effort host metric from the OS; it
  may be unavailable on unsupported platforms.
