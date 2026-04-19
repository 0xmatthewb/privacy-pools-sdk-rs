use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolValue, sol};
use std::{env, fs, path::PathBuf, str::FromStr};

sol! {
    struct RelayDataAbiWithChainId {
        address recipient;
        address feeRecipient;
        uint256 relayFeeBPS;
        uint256 chainId;
    }
}

fn main() {
    let output_path = env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/relay_data_abi_fuzz/wrong-chain.bin")
    });

    let bytes = RelayDataAbiWithChainId {
        recipient: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        feeRecipient: Address::from_str("0x2222222222222222222222222222222222222222").unwrap(),
        relayFeeBPS: U256::from(25_u64),
        chainId: U256::from(999_999_u64),
    }
    .abi_encode();

    fs::write(&output_path, bytes).unwrap();
    println!("{}", output_path.display());
}
