# React Native App-Process Smoke

This harness runs the packed `@0xmatthewb/privacy-pools-sdk-react-native`
tarball in a real React Native application process.

The repo keeps only the smoke sources here. The platform projects are generated
under `target/react-native-app-smoke` from the pinned React Native 0.79.7
template, then overlaid with this smoke flow, the packed SDK tarball, native
fixture-copy helpers, and the deterministic proving fixtures.

Run the heavy platform smokes with:

```sh
cargo run -p xtask -- react-native-app-smoke-ios
cargo run -p xtask -- react-native-app-smoke-android
```

The existing `cargo run -p xtask -- react-native-smoke` command remains the fast
packaging/typecheck smoke.
