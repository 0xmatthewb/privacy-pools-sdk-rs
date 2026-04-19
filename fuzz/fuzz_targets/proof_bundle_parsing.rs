#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_core::ProofBundle;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = serde_json::from_slice::<ProofBundle>(data) {
        let encoded = serde_json::to_vec(&bundle).expect("proof bundle should serialize");
        let reparsed: ProofBundle =
            serde_json::from_slice(&encoded).expect("serialized proof bundle should parse");
        assert_eq!(bundle, reparsed);
    }
});
