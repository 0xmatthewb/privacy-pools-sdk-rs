use alloy_primitives::{U256, keccak256};
use alloy_signer_local::{LocalSignerError, MnemonicBuilder};
use alloy_sol_types::{SolValue, sol};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use privacy_pools_sdk_core::{
    Commitment, CommitmentPreimage, CoreError, FieldElement, MasterKeys, Nullifier, Precommitment,
    Scope, Secret, Withdrawal, field_to_hex_32,
};
use pso_poseidon::{Poseidon, PoseidonError, PoseidonHasher};
use std::str::FromStr;
use thiserror::Error;

sol! {
    struct WithdrawalAbi {
        address processooor;
        bytes data;
    }

    struct WithdrawalContextAbi {
        WithdrawalAbi withdrawal;
        uint256 scope;
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Poseidon(#[from] PoseidonError),
    #[error(transparent)]
    Signer(#[from] LocalSignerError),
}

pub fn poseidon_hash(inputs: &[FieldElement]) -> Result<FieldElement, CryptoError> {
    let mut poseidon = Poseidon::<Fr>::new_circom(inputs.len())?;
    let fr_inputs = inputs.iter().copied().map(u256_to_fr).collect::<Vec<_>>();
    let hash = poseidon.hash(&fr_inputs)?;
    Ok(fr_to_u256(hash))
}

pub fn generate_master_keys(mnemonic: &str) -> Result<MasterKeys, CryptoError> {
    let key1 = derive_account_private_key(mnemonic, 0)?;
    let key2 = derive_account_private_key(mnemonic, 1)?;

    master_keys_from_seeds(key1, key2)
}

pub fn generate_legacy_master_keys(mnemonic: &str) -> Result<MasterKeys, CryptoError> {
    let key1 = legacy_seed_from_private_key(derive_account_private_key(mnemonic, 0)?);
    let key2 = legacy_seed_from_private_key(derive_account_private_key(mnemonic, 1)?);
    master_keys_from_seeds(key1, key2)
}

pub fn generate_deposit_secrets(
    keys: &MasterKeys,
    scope: Scope,
    index: FieldElement,
) -> Result<(Nullifier, Secret), CryptoError> {
    Ok((
        Nullifier::new(poseidon_hash(&[
            keys.master_nullifier.expose_secret(),
            scope,
            index,
        ])?),
        Secret::new(poseidon_hash(&[
            keys.master_secret.expose_secret(),
            scope,
            index,
        ])?),
    ))
}

pub fn generate_withdrawal_secrets(
    keys: &MasterKeys,
    label: FieldElement,
    index: FieldElement,
) -> Result<(Nullifier, Secret), CryptoError> {
    Ok((
        Nullifier::new(poseidon_hash(&[
            keys.master_nullifier.expose_secret(),
            label,
            index,
        ])?),
        Secret::new(poseidon_hash(&[
            keys.master_secret.expose_secret(),
            label,
            index,
        ])?),
    ))
}

pub fn hash_precommitment(
    nullifier: impl Into<Nullifier>,
    secret: impl Into<Secret>,
) -> Result<FieldElement, CryptoError> {
    let nullifier = nullifier.into();
    let secret = secret.into();
    poseidon_hash(&[nullifier.expose_secret(), secret.expose_secret()])
}

pub fn hash_nullifier(nullifier: impl Into<Nullifier>) -> Result<FieldElement, CryptoError> {
    let nullifier = nullifier.into();
    poseidon_hash(&[nullifier.expose_secret()])
}

pub fn build_commitment(
    value: FieldElement,
    label: FieldElement,
    nullifier: impl Into<Nullifier>,
    secret: impl Into<Secret>,
) -> Result<Commitment, CryptoError> {
    let nullifier = nullifier.into();
    let secret = secret.into();
    validate_non_zero(nullifier.expose_secret(), "nullifier")?;
    validate_non_zero(label, "label")?;
    validate_non_zero(secret.expose_secret(), "secret")?;

    let precommitment_hash = hash_precommitment(nullifier.clone(), secret.clone())?;
    let hash = poseidon_hash(&[value, label, precommitment_hash])?;
    Ok(Commitment {
        hash,
        precommitment_hash,
        preimage: CommitmentPreimage {
            value,
            label,
            precommitment: Precommitment {
                hash: precommitment_hash,
                nullifier,
                secret,
            },
        },
    })
}

pub fn calculate_withdrawal_context(
    withdrawal: &Withdrawal,
    scope: Scope,
) -> Result<String, CryptoError> {
    Ok(field_to_hex_32(calculate_withdrawal_context_field(
        withdrawal, scope,
    )?))
}

pub fn calculate_withdrawal_context_field(
    withdrawal: &Withdrawal,
    scope: Scope,
) -> Result<FieldElement, CryptoError> {
    let encoded = (
        WithdrawalAbi {
            processooor: withdrawal.processor,
            data: withdrawal.data.clone(),
        },
        scope,
    )
        .abi_encode_params();

    let keccak = U256::from_be_slice(keccak256(encoded).as_slice());
    Ok(keccak % snark_scalar_field())
}

fn derive_account_private_key(mnemonic: &str, account_index: u32) -> Result<U256, CryptoError> {
    let derivation_path = format!("m/44'/60'/{account_index}'/0/0");
    let signer = MnemonicBuilder::english()
        .phrase(mnemonic)
        .derivation_path(&derivation_path)?
        .build()?;
    Ok(U256::from_be_slice(signer.to_bytes().as_slice()))
}

fn master_keys_from_seeds(key1: U256, key2: U256) -> Result<MasterKeys, CryptoError> {
    Ok(MasterKeys {
        master_nullifier: Secret::new(poseidon_hash(&[key1])?),
        master_secret: Secret::new(poseidon_hash(&[key2])?),
    })
}

fn legacy_seed_from_private_key(private_key: U256) -> U256 {
    // Match the shipped TS legacy recovery path exactly:
    // bytesToNumber(privateKey) -> BigInt(number), where `number` is an IEEE-754
    // double rounded to nearest, ties-to-even.
    if private_key.is_zero() {
        return U256::ZERO;
    }

    let bit_len = 256usize.saturating_sub(private_key.leading_zeros());
    if bit_len <= 53 {
        return private_key;
    }

    let shift = bit_len - 53;
    let mut mantissa = private_key >> shift;
    let remainder_mask = (U256::from(1_u8) << shift) - U256::from(1_u8);
    let remainder = private_key & remainder_mask;
    let half = U256::from(1_u8) << (shift - 1);

    if remainder > half || (remainder == half && (mantissa & U256::from(1_u8)) == U256::from(1_u8))
    {
        mantissa += U256::from(1_u8);

        if mantissa == (U256::from(1_u8) << 53) {
            mantissa >>= 1;
            return mantissa << (shift + 1);
        }
    }

    mantissa << shift
}

pub fn u256_to_fr(value: U256) -> Fr {
    Fr::from_le_bytes_mod_order(&value.to_le_bytes::<32>())
}

pub fn fr_to_u256(value: Fr) -> U256 {
    U256::from_le_slice(&value.into_bigint().to_bytes_le())
}

fn validate_non_zero(value: U256, name: &'static str) -> Result<(), CryptoError> {
    if value.is_zero() {
        return Err(CoreError::ZeroValue(name).into());
    }
    Ok(())
}

fn snark_scalar_field() -> U256 {
    U256::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617")
        .expect("valid snark scalar field")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes};
    use serde_json::Value;

    fn vector() -> Value {
        serde_json::from_str(include_str!(
            "../../../fixtures/vectors/crypto-compatibility.json"
        ))
        .expect("valid crypto fixture")
    }

    fn legacy_vector() -> Value {
        serde_json::from_str(include_str!(
            "../../../fixtures/vectors/legacy-crypto-compatibility.json"
        ))
        .expect("valid legacy crypto fixture")
    }

    #[test]
    fn matches_current_sdk_key_and_commitment_vectors() {
        let fixture = vector();
        let mnemonic = fixture["mnemonic"].as_str().unwrap();
        let keys = generate_master_keys(mnemonic).unwrap();

        assert_eq!(
            keys.master_nullifier,
            U256::from_str(fixture["keys"]["masterNullifier"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            keys.master_secret,
            U256::from_str(fixture["keys"]["masterSecret"].as_str().unwrap()).unwrap()
        );

        let scope = U256::from_str(fixture["scope"].as_str().unwrap()).unwrap();
        let label = U256::from_str(fixture["label"].as_str().unwrap()).unwrap();

        let (deposit_nullifier, deposit_secret) =
            generate_deposit_secrets(&keys, scope, U256::ZERO).unwrap();
        assert_eq!(
            deposit_nullifier,
            U256::from_str(fixture["depositSecrets"]["nullifier"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            deposit_secret,
            U256::from_str(fixture["depositSecrets"]["secret"].as_str().unwrap()).unwrap()
        );

        let (withdraw_nullifier, withdraw_secret) =
            generate_withdrawal_secrets(&keys, label, U256::from(1)).unwrap();
        assert_eq!(
            withdraw_nullifier,
            U256::from_str(fixture["withdrawalSecrets"]["nullifier"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            withdraw_secret,
            U256::from_str(fixture["withdrawalSecrets"]["secret"].as_str().unwrap()).unwrap()
        );

        let commitment =
            build_commitment(U256::from(1000), label, deposit_nullifier, deposit_secret).unwrap();
        assert_eq!(
            commitment.hash,
            U256::from_str(fixture["commitment"]["hash"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            commitment.precommitment_hash,
            U256::from_str(fixture["commitment"]["nullifierHash"].as_str().unwrap()).unwrap()
        );
    }

    #[test]
    fn distinguishes_circuit_nullifier_hash_from_precommitment_hash() {
        let fixture = vector();
        let mnemonic = fixture["mnemonic"].as_str().unwrap();
        let keys = generate_master_keys(mnemonic).unwrap();
        let scope = U256::from_str(fixture["scope"].as_str().unwrap()).unwrap();
        let (deposit_nullifier, deposit_secret) =
            generate_deposit_secrets(&keys, scope, U256::ZERO).unwrap();
        let commitment = build_commitment(
            U256::from(1000),
            U256::from(456_u64),
            deposit_nullifier.clone(),
            deposit_secret,
        )
        .unwrap();
        let circuit_nullifier_hash = hash_nullifier(deposit_nullifier).unwrap();

        assert_ne!(circuit_nullifier_hash, commitment.precommitment_hash);
    }

    #[test]
    fn matches_current_sdk_context_hashing() {
        let fixture = vector();
        let withdrawal = Withdrawal {
            processor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        };

        let context = calculate_withdrawal_context(&withdrawal, U256::from(123)).unwrap();
        assert_eq!(context, fixture["context"].as_str().unwrap());
    }

    #[test]
    fn matches_legacy_account_derivation_vector() {
        let fixture = legacy_vector();
        let mnemonic = fixture["mnemonic"].as_str().unwrap();
        let safe_keys = generate_master_keys(mnemonic).unwrap();
        let legacy_keys = generate_legacy_master_keys(mnemonic).unwrap();

        assert_eq!(
            legacy_keys.master_nullifier,
            U256::from_str(fixture["keys"]["masterNullifier"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            legacy_keys.master_secret,
            U256::from_str(fixture["keys"]["masterSecret"].as_str().unwrap()).unwrap()
        );
        assert_ne!(legacy_keys.master_nullifier, safe_keys.master_nullifier);
        assert_ne!(legacy_keys.master_secret, safe_keys.master_secret);
    }

    #[test]
    fn matches_current_sdk_legacy_number_rounding() {
        let private_key = U256::from_str(
            "77814517325470205911140941194401928579557062014761831930645393041380819009408",
        )
        .unwrap();
        let rounded = legacy_seed_from_private_key(private_key);

        assert_eq!(
            rounded,
            U256::from_str(
                "77814517325470206090537488703115359743174939106526186048988649279981784924160"
            )
            .unwrap()
        );

        let half_even = (U256::from(1_u8) << 53) + U256::from(1_u8);
        assert_eq!(
            legacy_seed_from_private_key(half_even),
            U256::from(1_u8) << 53
        );

        let half_odd = (U256::from(1_u8) << 53) + U256::from(3_u8);
        assert_eq!(
            legacy_seed_from_private_key(half_odd),
            (U256::from(1_u8) << 53) + U256::from(4_u8)
        );
    }
}
