# Benchmarking

The workspace ships a narrow benchmark entrypoint for the Rust withdraw proving
path:

```sh
cargo run -p privacy-pools-sdk-cli -- benchmark-withdraw \
  --manifest /absolute/path/to/artifact-manifest.json \
  --artifacts-root /absolute/path/to/artifacts \
  --backend stable \
  --warmup 1 \
  --iterations 5
```

What it measures:

- typed withdraw circuit-input preparation from the reference compatibility
  fixtures
- compiled witness generation through the Rust witness adapter
- end-to-end withdraw proof generation through the Rust SDK
- local proof verification through the Rust SDK

Notes:

- The benchmark uses the checked-in compatibility fixtures for the withdraw
  witness shape, but it expects a real verified artifact bundle for the
  `withdraw` circuit.
- `fixtures/artifacts/sample-proving-manifest.json` is only a structural sample
  and does not contain a real proving key, so it is not suitable for real
  benchmark runs.
- `--backend fast` requires a build with the `rapidsnark` feature enabled and a
  supported target; the stable `arkworks` backend remains the default.
