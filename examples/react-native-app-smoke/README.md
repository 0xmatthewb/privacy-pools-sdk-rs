# React Native App-Process Smoke

This harness runs the packed `@0xmatthewb/privacy-pools-sdk-react-native`
tarball in a real React Native application process.

The checked-in app fixture lives under `fixture-template/` and tracks the
pinned React Native 0.79.7 project layout. The smoke runner copies that
template into `target/react-native-app-smoke`, installs JavaScript
dependencies from the checked-in `package-lock.json`, installs the packed SDK
tarball, copies deterministic proving fixtures into the native projects, runs
the platform app, and reads the app-written report file from app storage.

Use the local mobile orchestrator for the normal developer loop:

```sh
cargo run -p xtask -- mobile-smoke-local --platform ios --surface all
cargo run -p xtask -- mobile-smoke-local --platform android --surface all
cargo run -p xtask -- mobile-smoke-local --platform all --surface all
```

The lower-level React Native app-process entrypoints remain available:

```sh
cargo run -p xtask -- react-native-app-smoke-ios
cargo run -p xtask -- react-native-app-smoke-android
```

The existing `cargo run -p xtask -- react-native-smoke` command remains the fast
packaging/typecheck smoke.
