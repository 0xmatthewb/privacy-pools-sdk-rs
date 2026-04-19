use privacy_pools_sdk_core::{WithdrawalCircuitInput, parse_decimal_field};
use privacy_pools_sdk_prover::serialize_withdrawal_circuit_input;
use serde_json::Value;

fn withdrawal_fixture_input() -> WithdrawalCircuitInput {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/vectors/withdrawal-circuit-input.json"
    ))
    .expect("withdrawal fixture parses");

    WithdrawalCircuitInput {
        withdrawn_value: parse_decimal_field(fixture["withdrawalAmount"].as_str().unwrap())
            .unwrap(),
        state_root: parse_decimal_field(fixture["stateWitness"]["root"].as_str().unwrap()).unwrap(),
        state_tree_depth: fixture["stateWitness"]["depth"].as_u64().unwrap() as usize,
        asp_root: parse_decimal_field(fixture["aspWitness"]["root"].as_str().unwrap()).unwrap(),
        asp_tree_depth: fixture["aspWitness"]["depth"].as_u64().unwrap() as usize,
        context: parse_decimal_field(fixture["expected"]["context"].as_str().unwrap()).unwrap(),
        label: parse_decimal_field(fixture["label"].as_str().unwrap()).unwrap(),
        existing_value: parse_decimal_field(fixture["existingValue"].as_str().unwrap()).unwrap(),
        existing_nullifier: parse_decimal_field(fixture["existingNullifier"].as_str().unwrap())
            .unwrap()
            .into(),
        existing_secret: parse_decimal_field(fixture["existingSecret"].as_str().unwrap())
            .unwrap()
            .into(),
        new_nullifier: parse_decimal_field(fixture["newNullifier"].as_str().unwrap())
            .unwrap()
            .into(),
        new_secret: parse_decimal_field(fixture["newSecret"].as_str().unwrap())
            .unwrap()
            .into(),
        state_siblings: fixture["stateWitness"]["siblings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| parse_decimal_field(value.as_str().unwrap()).unwrap())
            .collect(),
        state_index: fixture["stateWitness"]["index"].as_u64().unwrap() as usize,
        asp_siblings: fixture["aspWitness"]["siblings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| parse_decimal_field(value.as_str().unwrap()).unwrap())
            .collect(),
        asp_index: fixture["aspWitness"]["index"].as_u64().unwrap() as usize,
    }
}

#[test]
fn rust_serialized_withdrawal_input_structurally_matches_ts() {
    let rust_json: serde_json::Value = serde_json::from_str(
        &serialize_withdrawal_circuit_input(&withdrawal_fixture_input()).unwrap(),
    )
    .unwrap();
    let ts_json: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/vectors/withdrawal-input-ts-serialized.json"
    ))
    .unwrap();

    assert_eq!(
        rust_json, ts_json,
        "Rust input structurally diverged from TS serialization"
    );
}

#[test]
fn rust_serialized_withdrawal_input_byte_identical_wire_compat() {
    let rust_bytes = serialize_withdrawal_circuit_input(&withdrawal_fixture_input()).unwrap();
    let golden_bytes =
        include_str!("../../../fixtures/vectors/withdrawal-input-ts-serialized.json");

    assert_eq!(
        rust_bytes.trim_end_matches('\n'),
        golden_bytes.trim_end_matches('\n')
    );
}
