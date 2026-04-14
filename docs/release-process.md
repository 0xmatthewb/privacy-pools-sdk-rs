# Release Process

The repo now has a manual release workflow at `.github/workflows/release.yml`.

It is designed to harden release channels before publish time:

- validates that all Rust crates share one version
- validates that the React Native package and both podspecs share one version
- validates that the selected channel matches the mobile prerelease suffix
- builds release iOS native artifacts on macOS
- builds release Android native artifacts on Linux
- assembles a publishable React Native tarball that includes both native asset sets

## Channel rules

- `alpha`: mobile version must use an `-alpha.N` prerelease suffix
- `beta`: mobile version must use a `-beta.N` prerelease suffix
- `rc`: mobile version must use an `-rc.N` prerelease suffix
- `stable`: mobile version must not use a prerelease suffix

The Rust crate version is validated against the same base version as the mobile
package surface. For example, Rust `0.1.0` is compatible with mobile
`0.1.0-alpha.1`, but not with mobile `0.2.0-alpha.1`.

## Local validation

```sh
cargo run -p xtask -- release-check --channel alpha
```

Local native packaging prerequisites:

- iOS packaging requires a full Xcode install with an active developer
  directory that exposes `iphoneos` and `iphonesimulator` through `xcrun`
- Android packaging requires Java 17, Android SDK/NDK, and `cargo-ndk`

Quick iOS sanity check:

```sh
sudo xcodebuild -license accept
xcrun --sdk iphoneos --show-sdk-path
xcrun --sdk iphonesimulator --show-sdk-path
```

Once benchmark captures and canary notes exist for a candidate release, validate the
evidence bundle too:

```sh
cargo run -p xtask -- evidence-check \
  --channel alpha \
  --dir /absolute/path/to/release-evidence/0.1.0-alpha.1
```

## GitHub workflow

Trigger the `release` workflow manually and choose the target channel. The
workflow uploads:

- iOS XCFramework archive
- Android JNI archive
- fully assembled React Native package tarball

Build artifacts are only part of promotion readiness. Pair them with the device
benchmark captures and rollout notes described in `docs/canary-rollout.md`
before promoting alpha, beta, rc, or stable.
