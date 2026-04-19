#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_core::ProofBundle;
use privacy_pools_sdk_verifier::PreparedVerifier;

const VALID_VKEY_JSON: &[u8] =
    include_bytes!("../../fixtures/artifacts/browser-verification.vkey.json");
const VALID_PROOF_BUNDLE_JSON: &[u8] = br#"{
  "proof": {
    "pi_a": [
      "1807837765049770725519465487433817562187632313275101813501069603482691643692",
      "16871717545070579619448445207827358366494821565773019606940564072946026508334"
    ],
    "pi_b": [
      [
        "8422907526608858108126723557033451966512809070650807035556493325466416295354",
        "18478832655014961328636313175982243342023036290573197754852746685768310310113"
      ],
      [
        "11669121927929985326288670125142631681716281545900846415561250951447861210949",
        "20304589663847288637989013811229846130117082674538591966399325012046243234127"
      ]
    ],
    "pi_c": [
      "16826635674460951374103156975550770450633552930497150683145472565220077349055",
      "11313919133545077647710810585782325403252727524950215451671674036220368349685"
    ],
    "protocol": "groth16",
    "curve": "bn128"
  },
  "public_signals": [
    "14351678597420227042494664083300942856930208098350332162228340709075991369136",
    "20831158926843012288280651858534658290391602917286933054197366234707804188233"
  ]
}"#;

fn mutated_fixture_bytes(seed: &[u8], fixture: &[u8]) -> Vec<u8> {
    if seed.is_empty() {
        return fixture.to_vec();
    }

    let mut bytes = fixture.to_vec();
    for (index, byte) in seed.iter().take(bytes.len().min(512)).enumerate() {
        let slot = (index.wrapping_mul(97)) % bytes.len();
        bytes[slot] ^= *byte;
    }
    bytes
}

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let (vkey_seed, proof_seed) = data.split_at(split);
    let vkey_bytes = mutated_fixture_bytes(vkey_seed, VALID_VKEY_JSON);
    let proof_bytes = mutated_fixture_bytes(proof_seed, VALID_PROOF_BUNDLE_JSON);

    let verifier = PreparedVerifier::from_vkey_bytes(VALID_VKEY_JSON).expect("valid vkey parses");
    let valid_proof =
        serde_json::from_slice::<ProofBundle>(VALID_PROOF_BUNDLE_JSON).expect("valid proof parses");

    if proof_bytes != VALID_PROOF_BUNDLE_JSON
        && let Ok(proof) = serde_json::from_slice::<ProofBundle>(&proof_bytes)
    {
        assert!(!matches!(verifier.verify(&proof), Ok(true)));
    }

    if let Ok(verifier) = PreparedVerifier::from_vkey_bytes(&vkey_bytes) {
        let _ = verifier.verify(&valid_proof);
    }
});
