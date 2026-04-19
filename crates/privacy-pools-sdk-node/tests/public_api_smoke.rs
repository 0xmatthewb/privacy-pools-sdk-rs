use napi::bindgen_prelude::Buffer;
use privacy_pools_sdk_node::{
    clear_execution_handles, clear_secret_handles, derive_master_keys_handle_bytes,
    finalize_preflighted_transaction_handle, generate_deposit_secrets_handle,
    generate_merkle_proof, get_commitment_from_handles, remove_secret_handle,
};

const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

#[test]
fn public_secret_handle_lifecycle_round_trips() {
    clear_secret_handles().unwrap();

    let master_handle =
        derive_master_keys_handle_bytes(Buffer::from(TEST_MNEMONIC.as_bytes().to_vec())).unwrap();
    let deposit_handle =
        generate_deposit_secrets_handle(master_handle.clone(), "123".to_owned(), "0".to_owned())
            .unwrap();
    let commitment_handle =
        get_commitment_from_handles("1000".to_owned(), "456".to_owned(), deposit_handle.clone())
            .unwrap();

    assert!(remove_secret_handle(commitment_handle.clone()).unwrap());
    assert!(!remove_secret_handle(commitment_handle).unwrap());
    assert!(remove_secret_handle(deposit_handle).unwrap());
    assert!(remove_secret_handle(master_handle).unwrap());

    clear_secret_handles().unwrap();
}

#[tokio::test]
async fn public_execution_handle_errors_preserve_missing_handle_context() {
    clear_execution_handles().unwrap();

    let error = finalize_preflighted_transaction_handle(
        "http://127.0.0.1:8545".to_owned(),
        "00000000-0000-0000-0000-000000000000".to_owned(),
    )
    .await
    .expect_err("missing execution handle must fail");

    assert!(error.to_string().contains("execution handle not found"));
}

#[test]
fn public_json_errors_preserve_payload_too_large_context() {
    let oversized_json = format!("[{}]", " ".repeat((1024 * 1024) + 1));

    let error = generate_merkle_proof(oversized_json, "1".to_owned())
        .expect_err("oversized JSON must fail");

    assert!(
        error
            .to_string()
            .contains("JSON payload exceeds maximum size")
    );
}
