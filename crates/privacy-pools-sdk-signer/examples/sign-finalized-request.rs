#![cfg(feature = "local-mnemonic")]

use alloy_primitives::{Address, Bytes, U256, hex};
use privacy_pools_sdk_core::{FinalizedTransactionRequest, TransactionKind};
use privacy_pools_sdk_signer::LocalMnemonicSigner;
use serde::Deserialize;
use std::{env, process::ExitCode, str::FromStr};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonFinalizedTransactionRequest {
    kind: String,
    chain_id: u64,
    from: String,
    to: String,
    nonce: u64,
    gas_limit: u64,
    value: String,
    data: String,
    gas_price: Option<String>,
    max_fee_per_gas: Option<String>,
    max_priority_fee_per_gas: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let mut args = env::args().skip(1);
    let mnemonic = args.next().ok_or_else(|| "missing mnemonic argument".to_owned())?;
    let request_json = args
        .next()
        .ok_or_else(|| "missing finalized request JSON argument".to_owned())?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".to_owned());
    }

    let request = parse_request(&request_json)?;
    let signer = LocalMnemonicSigner::from_phrase_nth(&mnemonic, 0).map_err(|error| error.to_string())?;
    let signed = signer
        .sign_transaction_request(&request)
        .map_err(|error| error.to_string())?;
    Ok(format!("0x{}", hex::encode(signed)))
}

fn parse_request(input: &str) -> Result<FinalizedTransactionRequest, String> {
    let request: JsonFinalizedTransactionRequest =
        serde_json::from_str(input).map_err(|error| error.to_string())?;
    Ok(FinalizedTransactionRequest {
        kind: parse_transaction_kind(&request.kind)?,
        chain_id: request.chain_id,
        from: parse_address(&request.from)?,
        to: parse_address(&request.to)?,
        nonce: request.nonce,
        gas_limit: request.gas_limit,
        value: parse_u256(&request.value)?,
        data: parse_bytes(&request.data)?,
        gas_price: parse_optional_u128(request.gas_price)?,
        max_fee_per_gas: parse_optional_u128(request.max_fee_per_gas)?,
        max_priority_fee_per_gas: parse_optional_u128(request.max_priority_fee_per_gas)?,
    })
}

fn parse_transaction_kind(value: &str) -> Result<TransactionKind, String> {
    match value {
        "withdraw" => Ok(TransactionKind::Withdraw),
        "relay" => Ok(TransactionKind::Relay),
        "ragequit" => Ok(TransactionKind::Ragequit),
        other => Err(format!("unsupported transaction kind: {other}")),
    }
}

fn parse_address(value: &str) -> Result<Address, String> {
    Address::from_str(value).map_err(|error| error.to_string())
}

fn parse_bytes(value: &str) -> Result<Bytes, String> {
    let decoded = hex::decode(value.trim_start_matches("0x")).map_err(|error| error.to_string())?;
    Ok(Bytes::from(decoded))
}

fn parse_u256(value: &str) -> Result<U256, String> {
    U256::from_str(value).map_err(|error| error.to_string())
}

fn parse_optional_u128(value: Option<String>) -> Result<Option<u128>, String> {
    value
        .map(|entry| entry.parse::<u128>().map_err(|error| error.to_string()))
        .transpose()
}
