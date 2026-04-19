#![cfg(feature = "local-signer-client")]

use alloy_primitives::{Address, U256, address, bytes};
use privacy_pools_sdk::{
    PrivacyPoolsSdk, SdkError,
    artifacts::ArtifactManifest,
    chain::{self, ExecutionClient, FinalizationClient},
    core::{self, ExecutionPolicy, ExecutionPolicyMode, ReadConsistency},
    prover::BackendProfile,
    signer::{LocalMnemonicSigner, SignerAdapter},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    str::FromStr,
    thread::sleep,
    time::Duration,
};

const ANVIL_DEFAULT_MNEMONIC: &str = "test test test test test test test test test test test junk";
const ANVIL_DEFAULT_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_CHAIN_ID: u64 = 31_337;

#[derive(Debug)]
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ForgeCreateOutput {
    deployed_to: String,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workspace_path(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

fn read_fixture_json(relative: &str) -> Value {
    serde_json::from_slice(&fs::read(workspace_path(relative)).expect("fixture exists"))
        .expect("fixture parses")
}

fn reference_withdrawal_request(sdk: &PrivacyPoolsSdk) -> core::WithdrawalWitnessRequest {
    let crypto_fixture = read_fixture_json("fixtures/vectors/crypto-compatibility.json");
    let withdrawal_fixture = read_fixture_json("fixtures/vectors/withdrawal-circuit-input.json");
    let keys = sdk
        .generate_master_keys(crypto_fixture["mnemonic"].as_str().expect("mnemonic"))
        .expect("master keys derive");
    let (deposit_nullifier, deposit_secret) = sdk
        .generate_deposit_secrets(
            &keys,
            U256::from_str(crypto_fixture["scope"].as_str().expect("scope")).expect("scope"),
            U256::ZERO,
        )
        .expect("deposit secrets derive");

    core::WithdrawalWitnessRequest {
        commitment: sdk
            .build_commitment(
                U256::from_str(
                    withdrawal_fixture["existingValue"]
                        .as_str()
                        .expect("existing value"),
                )
                .expect("existing value"),
                U256::from_str(withdrawal_fixture["label"].as_str().expect("label"))
                    .expect("label"),
                deposit_nullifier,
                deposit_secret,
            )
            .expect("commitment builds"),
        withdrawal: core::Withdrawal {
            processor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        },
        scope: U256::from_str(crypto_fixture["scope"].as_str().expect("scope")).expect("scope"),
        withdrawal_amount: U256::from_str(
            withdrawal_fixture["withdrawalAmount"]
                .as_str()
                .expect("withdrawal amount"),
        )
        .expect("withdrawal amount"),
        state_witness: witness_from_fixture(&withdrawal_fixture["stateWitness"]),
        asp_witness: witness_from_fixture(&withdrawal_fixture["aspWitness"]),
        new_nullifier: U256::from_str(
            withdrawal_fixture["newNullifier"]
                .as_str()
                .expect("new nullifier"),
        )
        .expect("new nullifier")
        .into(),
        new_secret: U256::from_str(
            withdrawal_fixture["newSecret"]
                .as_str()
                .expect("new secret"),
        )
        .expect("new secret")
        .into(),
    }
}

fn witness_from_fixture(value: &Value) -> core::CircuitMerkleWitness {
    core::CircuitMerkleWitness {
        root: U256::from_str(value["root"].as_str().expect("root")).expect("root"),
        leaf: U256::from_str(value["leaf"].as_str().expect("leaf")).expect("leaf"),
        index: value["index"].as_u64().expect("index") as usize,
        siblings: value["siblings"]
            .as_array()
            .expect("siblings")
            .iter()
            .map(|entry| U256::from_str(entry.as_str().expect("sibling")).expect("sibling"))
            .collect(),
        depth: value["depth"].as_u64().expect("depth") as usize,
    }
}

fn rpc_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn reserve_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("ephemeral port should bind")
        .local_addr()
        .expect("local addr available")
        .port()
}

fn wait_for_anvil(port: u16) {
    for _ in 0..100 {
        if rpc_request(port, "eth_chainId", json!([])).is_ok() {
            return;
        }
        sleep(Duration::from_millis(100));
    }

    panic!("anvil did not start listening on port {port}");
}

fn start_anvil(port: u16) -> ChildGuard {
    let child = Command::new("anvil")
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--chain-id",
            &ANVIL_CHAIN_ID.to_string(),
            "--mnemonic",
            ANVIL_DEFAULT_MNEMONIC,
            "--accounts",
            "1",
            "--silent",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("anvil should be installed for the ignored reorg test");
    let guard = ChildGuard(child);
    wait_for_anvil(port);
    guard
}

fn rpc_request(port: u16, method: &str, params: Value) -> Result<Value, String> {
    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }))
    .map_err(|error| error.to_string())?;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    let (_, response_body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("malformed HTTP response: {response}"))?;
    let payload: Value =
        serde_json::from_str(response_body.trim()).map_err(|error| error.to_string())?;
    if let Some(error) = payload.get("error") {
        return Err(format!("rpc {method} failed: {error}"));
    }

    payload
        .get("result")
        .cloned()
        .ok_or_else(|| format!("rpc {method} returned no result: {payload}"))
}

fn run_command(program: &str, args: &[String], cwd: PathBuf) -> String {
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|error| panic!("failed to launch {program}: {error}"));
    if !output.status.success() {
        panic!(
            "{program} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    String::from_utf8(output.stdout).expect("command output should be utf8")
}

fn deploy_contract(port: u16, contract: &str, constructor_args: &[String]) -> Address {
    let mut args = vec![
        "create".to_owned(),
        contract.to_owned(),
        "--rpc-url".to_owned(),
        rpc_url(port),
        "--private-key".to_owned(),
        ANVIL_DEFAULT_PRIVATE_KEY.to_owned(),
        "--broadcast".to_owned(),
        "--json".to_owned(),
    ];
    if !constructor_args.is_empty() {
        args.push("--constructor-args".to_owned());
        args.extend(constructor_args.iter().cloned());
    }

    let output = run_command("forge", &args, workspace_path("solidity-verifier"));
    let trimmed = output.trim();
    if let Ok(deployed) = serde_json::from_str::<ForgeCreateOutput>(trimmed) {
        return Address::from_str(&deployed.deployed_to).expect("deployed contract address parses");
    }

    if let Some(address) = trimmed
        .lines()
        .find_map(|line| line.trim().strip_prefix("\"deployedTo\":"))
        .map(|value| value.trim().trim_matches(',').trim_matches('"'))
    {
        return Address::from_str(address).expect("deployed contract address parses");
    }

    if let Some(address) = trimmed
        .lines()
        .find_map(|line| line.trim().strip_prefix("Deployed to:"))
        .map(str::trim)
    {
        return Address::from_str(address).expect("deployed contract address parses");
    }

    panic!("forge create did not emit a deployable address:\n{trimmed}")
}

fn cast_send(port: u16, target: Address, signature: &str, values: &[String]) {
    let mut args = vec![
        "send".to_owned(),
        "--rpc-url".to_owned(),
        rpc_url(port),
        "--private-key".to_owned(),
        ANVIL_DEFAULT_PRIVATE_KEY.to_owned(),
        target.to_string(),
        signature.to_owned(),
    ];
    args.extend(values.iter().cloned());
    let _ = run_command("cast", &args, workspace_root());
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires anvil and forge to simulate a preflight-to-submit reorg against a live chain"]
async fn submit_rechecks_roots_after_anvil_reorg() {
    let sdk = PrivacyPoolsSdk::default();
    let request = reference_withdrawal_request(&sdk);
    let manifest: ArtifactManifest = serde_json::from_str(include_str!(
        "../../../fixtures/artifacts/withdrawal-proving-manifest.json"
    ))
    .expect("withdrawal manifest parses");
    let artifacts_root = workspace_path("fixtures/artifacts");
    let session = sdk
        .prepare_withdrawal_circuit_session(&manifest, &artifacts_root)
        .expect("withdrawal session prepares");
    let proving = sdk
        .prove_withdrawal_with_session(BackendProfile::Stable, &session, &request)
        .expect("withdrawal proof generates");
    let verified = sdk
        .verify_withdrawal_proof_for_request_with_session(
            BackendProfile::Stable,
            &session,
            &request,
            &proving.proof,
        )
        .expect("withdrawal proof verifies against request");

    let port = reserve_port();
    let _anvil = start_anvil(port);
    let entrypoint = deploy_contract(port, "src/ReorgHarness.sol:MockEntrypointHarness", &[]);
    let pool = deploy_contract(
        port,
        "src/ReorgHarness.sol:MockPrivacyPoolHarness",
        &[entrypoint.to_string()],
    );
    let snapshot_id = rpc_request(port, "evm_snapshot", json!([])).expect("snapshot succeeds");

    let expected_state_root = request.state_witness.root;
    let expected_asp_root = request.asp_witness.root;
    cast_send(
        port,
        entrypoint,
        "setLatestRoot(uint256)",
        &[expected_asp_root.to_string()],
    );
    cast_send(
        port,
        pool,
        "setCurrentRoot(uint256,uint32)",
        &[expected_state_root.to_string(), "0".to_owned()],
    );

    let signer = LocalMnemonicSigner::from_phrase_nth(ANVIL_DEFAULT_MNEMONIC, 0)
        .expect("anvil mnemonic should derive");
    let client =
        chain::LocalSignerExecutionClient::new(&rpc_url(port), &signer).expect("client builds");
    let pool_code_hash = client
        .code_hash(pool, ReadConsistency::Latest)
        .await
        .expect("pool code hash loads");
    let entrypoint_code_hash = client
        .code_hash(entrypoint, ReadConsistency::Latest)
        .await
        .expect("entrypoint code hash loads");

    let config = core::WithdrawalExecutionConfig {
        chain_id: ANVIL_CHAIN_ID,
        pool_address: pool,
        policy: ExecutionPolicy {
            expected_chain_id: ANVIL_CHAIN_ID,
            caller: signer.address(),
            expected_pool_code_hash: Some(pool_code_hash),
            expected_entrypoint_code_hash: Some(entrypoint_code_hash),
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
            mode: ExecutionPolicyMode::Strict,
        },
    };
    let preflighted = sdk
        .preflight_verified_withdrawal_transaction_with_client(&config, &verified, &client)
        .await
        .expect("preflight succeeds before the reorg");

    let nonce_before_submit = client
        .next_nonce(signer.address())
        .await
        .expect("nonce reads before submit");

    let reverted = rpc_request(port, "evm_revert", json!([snapshot_id])).expect("revert succeeds");
    assert_eq!(
        reverted,
        Value::Bool(true),
        "anvil should accept the revert"
    );

    let reorganized_state_root = expected_state_root + U256::from(1_u64);
    let reorganized_asp_root = expected_asp_root + U256::from(1_u64);
    cast_send(
        port,
        entrypoint,
        "setLatestRoot(uint256)",
        &[reorganized_asp_root.to_string()],
    );
    cast_send(
        port,
        pool,
        "setCurrentRoot(uint256,uint32)",
        &[reorganized_state_root.to_string(), "0".to_owned()],
    );

    let error = sdk
        .submit_preflighted_transaction_with_client(preflighted, &client)
        .await
        .expect_err("submission should fail after a reorg invalidates the preflight roots");
    match error {
        SdkError::Chain(chain::ChainError::StateRootMismatch { expected, actual }) => {
            assert_eq!(expected, expected_state_root);
            assert_eq!(actual, reorganized_state_root);
        }
        other => panic!("unexpected submission error after reorg: {other:?}"),
    }

    assert_eq!(
        client
            .next_nonce(signer.address())
            .await
            .expect("nonce reads after failed submit"),
        nonce_before_submit,
        "reconfirm_preflight should fail before any transaction reaches the chain"
    );
}
