# Binding Parity

Binding parity is enforced in two dimensions:

- exported safe-surface names across browser, Node, React Native, Android, and iOS
- generated artifact freshness for browser and native bindings

Intentional surface differences should be rare and documented in the binding
parity allowlist once that check is extended. If a safe export or generated
artifact changes unexpectedly, regenerate first and then confirm each sibling
surface was updated deliberately before merging.
