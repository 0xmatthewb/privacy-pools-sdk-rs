# React Native Smoke App

This lightweight sample app exercises the published
`@0xbow/privacy-pools-sdk` package from a consumer-style React Native project.

It is intentionally small:

- installs the packed package tarball produced by `npm pack`
- imports the typed SDK surface from `App.tsx`
- typechecks the consumer app without reusing internal workspace aliases

Run it locally through the workspace helper:

```sh
cargo run -p xtask -- react-native-smoke
```
