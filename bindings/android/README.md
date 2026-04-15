# Android bindings

Generated Kotlin bindings and packaged Android artifacts live here.

Current contents:

- `generated/`: UniFFI-generated Kotlin bindings
- `src/main/kotlin/`: thin Android-friendly wrapper API
- `src/androidTest/`: app-process instrumentation smoke tests for real
  prepare/prove/verify fixtures
- `build.gradle.kts`: Android library module definition
- `scripts/build-aar.sh`: reproducible native library + AAR build script
