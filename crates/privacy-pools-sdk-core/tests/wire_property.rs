use alloy_primitives::U256;
use privacy_pools_sdk_core::{
    Commitment, CoreError, field_from_be_bytes, field_to_be_bytes, field_to_decimal,
    parse_decimal_field,
    wire::{
        WireCommitment, WireCommitmentCircuitInput, WireMasterKeys, WireWithdrawalCircuitInput,
    },
};
use proptest::prelude::*;

fn generated_field(seed: u64) -> U256 {
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let mixed = seed
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(index as u32);
        *byte = (mixed >> ((index % 8) * 8)) as u8;
    }
    U256::from_be_slice(&bytes)
}

fn generated_decimal(seed: u64) -> String {
    field_to_decimal(generated_field(seed))
}

fn wire_commitment(seed: u64) -> WireCommitment {
    let precommitment_hash = generated_decimal(seed + 3);
    WireCommitment {
        hash: generated_decimal(seed + 1),
        nullifier_hash: precommitment_hash.clone(),
        precommitment_hash,
        value: generated_decimal(seed + 5),
        label: generated_decimal(seed + 7),
        nullifier: generated_decimal(seed + 11),
        secret: generated_decimal(seed + 13),
    }
}

#[test]
fn generated_wire_commitments_roundtrip_through_domain() {
    for seed in 1..128 {
        let wire = wire_commitment(seed);
        let domain = Commitment::try_from(wire.clone()).expect("generated commitment is valid");
        let exported = WireCommitment::from(&domain);

        assert_eq!(exported.hash, wire.hash);
        assert_eq!(exported.nullifier_hash, wire.nullifier_hash);
        assert_eq!(exported.precommitment_hash, wire.precommitment_hash);
        assert_eq!(exported.value, wire.value);
        assert_eq!(exported.label, wire.label);
        assert_eq!(exported.nullifier, wire.nullifier);
        assert_eq!(exported.secret, wire.secret);

        let encoded = serde_json::to_string(&exported).expect("wire commitment serializes");
        let decoded: WireCommitment =
            serde_json::from_str(&encoded).expect("wire commitment deserializes");
        assert_eq!(decoded, exported);
    }
}

#[test]
fn generated_field_bytes_and_decimal_values_roundtrip() {
    let explicit_cases = [
        U256::ZERO,
        U256::from(1_u64),
        U256::from(u64::MAX),
        U256::from_be_slice(&[0, 0, 0, 1, 2, 3, 4, 5]),
        U256::MAX,
    ];

    for value in explicit_cases
        .into_iter()
        .chain((1..128).map(generated_field))
    {
        let bytes = field_to_be_bytes(value);
        assert_eq!(field_from_be_bytes(bytes), value);

        let decimal = field_to_decimal(value);
        assert_eq!(
            parse_decimal_field(&decimal).expect("decimal field parses"),
            value
        );
    }
}

#[test]
fn malformed_wire_boundaries_fail_closed() {
    let mut mismatched = wire_commitment(42);
    mismatched.nullifier_hash = generated_decimal(999);

    assert!(matches!(
        Commitment::try_from(mismatched),
        Err(CoreError::MismatchedCommitmentCompatibilityHash)
    ));

    for value in [" ", "0xz", "-1", "not-a-number", "1.5"] {
        assert!(
            parse_decimal_field(value).is_err(),
            "malformed decimal field should fail: {value}"
        );
    }
}

#[test]
fn secret_bearing_wire_dtos_keep_v1_json_shapes() {
    let master_keys = WireMasterKeys {
        master_nullifier: "1".to_owned(),
        master_secret: "2".to_owned(),
    };
    assert_eq!(
        serde_json::to_string(&master_keys).expect("master keys serialize"),
        r#"{"masterNullifier":"1","masterSecret":"2"}"#
    );

    let commitment_input = WireCommitmentCircuitInput {
        value: "3".to_owned(),
        label: "4".to_owned(),
        nullifier: "5".to_owned(),
        secret: "6".to_owned(),
    };
    assert_eq!(
        serde_json::to_string(&commitment_input).expect("commitment input serializes"),
        r#"{"value":"3","label":"4","nullifier":"5","secret":"6"}"#
    );

    let withdrawal_input = WireWithdrawalCircuitInput {
        withdrawn_value: "1".to_owned(),
        state_root: "2".to_owned(),
        state_tree_depth: 20,
        asp_root: "3".to_owned(),
        asp_tree_depth: 20,
        context: "4".to_owned(),
        label: "5".to_owned(),
        existing_value: "6".to_owned(),
        existing_nullifier: "7".to_owned(),
        existing_secret: "8".to_owned(),
        new_nullifier: "9".to_owned(),
        new_secret: "10".to_owned(),
        state_siblings: vec!["11".to_owned()],
        state_index: 0,
        asp_siblings: vec!["12".to_owned()],
        asp_index: 1,
    };
    let value = serde_json::to_value(&withdrawal_input).expect("withdrawal input serializes");

    assert!(value.get("withdrawnValue").is_some());
    assert!(value.get("stateRoot").is_some());
    assert!(value.get("aspRoot").is_some());
    assert!(value.get("aspTreeDepth").is_some());
    assert!(value.get("ASPRoot").is_none());
    assert!(value.get("ASPTreeDepth").is_none());
}

proptest! {
    #[test]
    fn decimal_and_big_endian_field_boundaries_roundtrip(bytes in any::<[u8; 32]>()) {
        let value = U256::from_be_slice(&bytes);

        prop_assert_eq!(field_to_be_bytes(value), bytes);
        prop_assert_eq!(field_from_be_bytes(bytes), value);

        let decimal = field_to_decimal(value);
        prop_assert_eq!(parse_decimal_field(&decimal).expect("decimal parses"), value);
    }

    #[test]
    fn wire_commitment_roundtrips_for_generated_seeds(seed in 1_u64..10_000) {
        let wire = wire_commitment(seed);
        let domain = Commitment::try_from(wire.clone()).expect("wire commitment converts");
        let exported = WireCommitment::from(&domain);

        prop_assert_eq!(&exported, &wire);
        prop_assert_eq!(
            serde_json::from_str::<WireCommitment>(
                &serde_json::to_string(&exported).expect("wire serializes")
            )
            .expect("wire deserializes"),
            exported,
        );
    }

    #[test]
    fn malformed_decimal_strings_fail_closed(value in "\\PC{0,64}") {
        prop_assume!(value.parse::<U256>().is_err());
        prop_assert!(parse_decimal_field(&value).is_err());
    }
}
