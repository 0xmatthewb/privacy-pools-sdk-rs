# Flake Triage

The Rust workspace test lane runs through nextest with bounded retries and
JUnit output under `target/nextest/ci/junit.xml`.

Use this order when a test is flaky:

1. Confirm the first failing test from the JUnit artifact and nextest output.
2. Re-run the narrow test locally before touching unrelated code.
3. If the failure is mobile-only, inspect the `mobile-smoke` evidence bundle.
4. If the test fails only under CI timing, prefer fixing synchronization or
   explicit waits before raising retry counts.

Retries are a visibility tool, not a substitute for root-cause fixes.
