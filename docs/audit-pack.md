# Audit Pack

`xtask audit-pack` is the compatibility alias for the richer assurance audit
mode.

Use:

```sh
cargo run -p xtask -- assurance --profile release --runtime all --report-mode audit --external-evidence-dir /absolute/path/to/external-evidence
```

or the alias:

```sh
cargo run -p xtask -- audit-pack --external-evidence-dir /absolute/path/to/external-evidence
```

Both commands write the same release-grade evidence bundle. The assurance runner
is the preferred entrypoint; the alias remains for existing release notes,
scripts, and external audit references.

`audit` remains a release-only report mode. Nightly runs produce standard-mode
assurance bundles rather than audit bundles, even when they ingest external
mobile evidence or optional benchmark reports.

See [`docs/assurance.md`](./assurance.md) for the active profile model and
output layout, and [`docs/assurance-review-guide.md`](./assurance-review-guide.md)
for the reviewer-facing invariant map.
