use alloy_primitives::{Address, U256};
use anyhow::{Context, Result, bail};
use base64::Engine;
use privacy_pools_sdk_artifacts::{
    ArtifactKind, ArtifactManifest, ArtifactStatus, ResolvedArtifactBundle,
};
use privacy_pools_sdk_core::{
    CircuitMerkleWitness, Commitment, MasterKeys, MerkleProof, Withdrawal,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::str::FromStr;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsMasterKeys {
    master_nullifier: String,
    master_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsSecrets {
    nullifier: String,
    secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsCommitment {
    hash: String,
    nullifier_hash: String,
    precommitment_hash: String,
    value: String,
    label: String,
    nullifier: String,
    secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsWithdrawal {
    processooor: String,
    data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsMerkleProof {
    root: String,
    leaf: String,
    index: u64,
    siblings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsCircuitMerkleWitness {
    root: String,
    leaf: String,
    index: u64,
    siblings: Vec<String>,
    depth: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsArtifactBytes {
    kind: String,
    bytes_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsArtifactStatus {
    version: String,
    circuit: String,
    kind: String,
    filename: String,
    path: String,
    exists: bool,
    verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsResolvedArtifact {
    circuit: String,
    kind: String,
    filename: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsResolvedArtifactBundle {
    version: String,
    circuit: String,
    artifacts: Vec<JsResolvedArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsVerifiedArtifactDescriptor {
    circuit: String,
    kind: String,
    filename: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsVerifiedArtifactBundle {
    version: String,
    circuit: String,
    artifacts: Vec<JsVerifiedArtifactDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSupportStatus {
    pub runtime: String,
    pub proving_available: bool,
    pub verification_available: bool,
    pub reason: String,
}

#[must_use]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[must_use]
pub fn get_browser_support_status() -> BrowserSupportStatus {
    BrowserSupportStatus {
        runtime: "web".to_owned(),
        proving_available: false,
        verification_available: false,
        reason: "browser proving support is still blocked on a wasm-capable prover backend"
            .to_owned(),
    }
}

pub fn derive_master_keys_json(mnemonic: &str) -> Result<String> {
    let keys = privacy_pools_sdk_crypto::generate_master_keys(mnemonic)?;
    to_json_string(&to_js_master_keys(&keys))
}

pub fn derive_deposit_secrets_json(
    master_keys_json: &str,
    scope: &str,
    index: &str,
) -> Result<String> {
    let master_keys = parse_json::<JsMasterKeys>(master_keys_json)?;
    let master_keys = to_master_keys(&master_keys)?;
    let secrets = privacy_pools_sdk_crypto::generate_deposit_secrets(
        &master_keys,
        parse_field(scope)?,
        parse_field(index)?,
    )?;
    to_json_string(&JsSecrets {
        nullifier: field_label(secrets.0),
        secret: field_label(secrets.1),
    })
}

pub fn derive_withdrawal_secrets_json(
    master_keys_json: &str,
    label: &str,
    index: &str,
) -> Result<String> {
    let master_keys = parse_json::<JsMasterKeys>(master_keys_json)?;
    let master_keys = to_master_keys(&master_keys)?;
    let secrets = privacy_pools_sdk_crypto::generate_withdrawal_secrets(
        &master_keys,
        parse_field(label)?,
        parse_field(index)?,
    )?;
    to_json_string(&JsSecrets {
        nullifier: field_label(secrets.0),
        secret: field_label(secrets.1),
    })
}

pub fn get_commitment_json(
    value: &str,
    label: &str,
    nullifier: &str,
    secret: &str,
) -> Result<String> {
    let commitment = privacy_pools_sdk_crypto::get_commitment(
        parse_field(value)?,
        parse_field(label)?,
        parse_field(nullifier)?,
        parse_field(secret)?,
    )?;
    to_json_string(&to_js_commitment(&commitment))
}

pub fn calculate_withdrawal_context_json(withdrawal_json: &str, scope: &str) -> Result<String> {
    let withdrawal = parse_json::<JsWithdrawal>(withdrawal_json)?;
    let withdrawal = from_js_withdrawal(&withdrawal)?;
    privacy_pools_sdk_crypto::calculate_context(&withdrawal, parse_field(scope)?)
        .map_err(Into::into)
}

pub fn generate_merkle_proof_json(leaves_json: &str, leaf: &str) -> Result<String> {
    let leaves = parse_json::<Vec<String>>(leaves_json)?;
    let leaves = leaves
        .iter()
        .map(|value| parse_field(value))
        .collect::<Result<Vec<_>>>()?;
    let proof = privacy_pools_sdk_tree::generate_merkle_proof(&leaves, parse_field(leaf)?)?;
    let proof = to_js_merkle_proof(proof)?;
    to_json_string(&proof)
}

pub fn build_circuit_merkle_witness_json(proof_json: &str, depth: u32) -> Result<String> {
    let proof = parse_json::<JsMerkleProof>(proof_json)?;
    let proof = from_js_merkle_proof(&proof)?;
    let witness = privacy_pools_sdk_tree::to_circuit_witness(
        &proof,
        usize::try_from(depth).context("merkle witness depth does not fit into usize")?,
    )?;
    let witness = to_js_circuit_merkle_witness(witness)?;
    to_json_string(&witness)
}

pub fn verify_artifact_bytes_json(
    manifest_json: &str,
    circuit: &str,
    artifacts_json: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts =
        parse_json::<Vec<JsArtifactBytes>>(artifacts_json).and_then(from_js_artifact_bytes)?;
    let bundle = manifest.verify_bundle_bytes(circuit, artifacts)?;
    to_json_string(&to_js_verified_artifact_bundle(bundle))
}

pub fn get_artifact_statuses_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let statuses =
        privacy_pools_sdk_artifacts::artifact_statuses(&manifest, artifacts_root, circuit)
            .into_iter()
            .map(|status| to_js_artifact_status(&manifest.version, status))
            .collect::<Vec<_>>();
    to_json_string(&statuses)
}

pub fn resolve_verified_artifact_bundle_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let bundle = manifest.resolve_verified_bundle(artifacts_root, circuit)?;
    to_json_string(&to_js_resolved_artifact_bundle(bundle))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getVersion)]
pub fn wasm_get_version() -> String {
    get_version()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getBrowserSupportStatusJson)]
pub fn wasm_get_browser_support_status_json() -> String {
    to_json_string(&get_browser_support_status()).expect("browser support status must serialize")
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveMasterKeysJson)]
pub fn wasm_derive_master_keys_json(mnemonic: &str) -> std::result::Result<String, JsValue> {
    derive_master_keys_json(mnemonic).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveDepositSecretsJson)]
pub fn wasm_derive_deposit_secrets_json(
    master_keys_json: &str,
    scope: &str,
    index: &str,
) -> std::result::Result<String, JsValue> {
    derive_deposit_secrets_json(master_keys_json, scope, index).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveWithdrawalSecretsJson)]
pub fn wasm_derive_withdrawal_secrets_json(
    master_keys_json: &str,
    label: &str,
    index: &str,
) -> std::result::Result<String, JsValue> {
    derive_withdrawal_secrets_json(master_keys_json, label, index).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getCommitmentJson)]
pub fn wasm_get_commitment_json(
    value: &str,
    label: &str,
    nullifier: &str,
    secret: &str,
) -> std::result::Result<String, JsValue> {
    get_commitment_json(value, label, nullifier, secret).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = calculateWithdrawalContextJson)]
pub fn wasm_calculate_withdrawal_context_json(
    withdrawal_json: &str,
    scope: &str,
) -> std::result::Result<String, JsValue> {
    calculate_withdrawal_context_json(withdrawal_json, scope).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = generateMerkleProofJson)]
pub fn wasm_generate_merkle_proof_json(
    leaves_json: &str,
    leaf: &str,
) -> std::result::Result<String, JsValue> {
    generate_merkle_proof_json(leaves_json, leaf).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildCircuitMerkleWitnessJson)]
pub fn wasm_build_circuit_merkle_witness_json(
    proof_json: &str,
    depth: u32,
) -> std::result::Result<String, JsValue> {
    build_circuit_merkle_witness_json(proof_json, depth).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyArtifactBytesJson)]
pub fn wasm_verify_artifact_bytes_json(
    manifest_json: &str,
    circuit: &str,
    artifacts_json: &str,
) -> std::result::Result<String, JsValue> {
    verify_artifact_bytes_json(manifest_json, circuit, artifacts_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getArtifactStatusesJson)]
pub fn wasm_get_artifact_statuses_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> std::result::Result<String, JsValue> {
    get_artifact_statuses_json(manifest_json, artifacts_root, circuit).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = resolveVerifiedArtifactBundleJson)]
pub fn wasm_resolve_verified_artifact_bundle_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> std::result::Result<String, JsValue> {
    resolve_verified_artifact_bundle_json(manifest_json, artifacts_root, circuit).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: anyhow::Error) -> JsValue {
    JsValue::from_str(&error.to_string())
}

fn parse_json<T>(value: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    serde_json::from_str(value).context("failed to parse JSON payload")
}

fn to_json_string(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).context("failed to serialize JSON payload")
}

fn parse_manifest(manifest_json: &str) -> Result<ArtifactManifest> {
    serde_json::from_str(manifest_json).context("failed to parse artifact manifest JSON")
}

fn parse_address(value: &str) -> Result<Address> {
    Address::from_str(value).with_context(|| format!("invalid address `{value}`"))
}

fn parse_field(value: &str) -> Result<U256> {
    U256::from_str(value).with_context(|| format!("invalid field element `{value}`"))
}

fn parse_artifact_kind(value: &str) -> Result<ArtifactKind> {
    match value {
        "wasm" => Ok(ArtifactKind::Wasm),
        "zkey" => Ok(ArtifactKind::Zkey),
        "vkey" => Ok(ArtifactKind::Vkey),
        _ => bail!("invalid artifact kind: {value}"),
    }
}

fn artifact_kind_label(kind: ArtifactKind) -> String {
    match kind {
        ArtifactKind::Wasm => "wasm".to_owned(),
        ArtifactKind::Zkey => "zkey".to_owned(),
        ArtifactKind::Vkey => "vkey".to_owned(),
    }
}

fn field_label(value: U256) -> String {
    value.to_string()
}

fn to_master_keys(keys: &JsMasterKeys) -> Result<MasterKeys> {
    Ok(MasterKeys {
        master_nullifier: parse_field(&keys.master_nullifier)?,
        master_secret: parse_field(&keys.master_secret)?,
    })
}

fn to_js_master_keys(keys: &MasterKeys) -> JsMasterKeys {
    JsMasterKeys {
        master_nullifier: field_label(keys.master_nullifier),
        master_secret: field_label(keys.master_secret),
    }
}

fn to_js_commitment(commitment: &Commitment) -> JsCommitment {
    JsCommitment {
        hash: field_label(commitment.hash),
        nullifier_hash: field_label(commitment.nullifier_hash),
        precommitment_hash: field_label(commitment.preimage.precommitment.hash),
        value: field_label(commitment.preimage.value),
        label: field_label(commitment.preimage.label),
        nullifier: field_label(commitment.preimage.precommitment.nullifier),
        secret: field_label(commitment.preimage.precommitment.secret),
    }
}

fn from_js_withdrawal(withdrawal: &JsWithdrawal) -> Result<Withdrawal> {
    let data = hex::decode(withdrawal.data.trim_start_matches("0x"))
        .with_context(|| format!("invalid hex withdrawal data `{}`", withdrawal.data))?;
    Ok(Withdrawal {
        processooor: parse_address(&withdrawal.processooor)?,
        data: data.into(),
    })
}

fn to_js_merkle_proof(proof: MerkleProof) -> Result<JsMerkleProof> {
    Ok(JsMerkleProof {
        root: field_label(proof.root),
        leaf: field_label(proof.leaf),
        index: u64::try_from(proof.index).context("merkle proof index does not fit into u64")?,
        siblings: proof.siblings.into_iter().map(field_label).collect(),
    })
}

fn from_js_merkle_proof(proof: &JsMerkleProof) -> Result<MerkleProof> {
    Ok(MerkleProof {
        root: parse_field(&proof.root)?,
        leaf: parse_field(&proof.leaf)?,
        index: usize::try_from(proof.index)
            .context("merkle proof index does not fit into usize")?,
        siblings: proof
            .siblings
            .iter()
            .map(|value| parse_field(value))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn to_js_circuit_merkle_witness(witness: CircuitMerkleWitness) -> Result<JsCircuitMerkleWitness> {
    Ok(JsCircuitMerkleWitness {
        root: field_label(witness.root),
        leaf: field_label(witness.leaf),
        index: u64::try_from(witness.index)
            .context("circuit witness index does not fit into u64")?,
        siblings: witness.siblings.into_iter().map(field_label).collect(),
        depth: u64::try_from(witness.depth)
            .context("circuit witness depth does not fit into u64")?,
    })
}

fn from_js_artifact_bytes(
    artifacts: Vec<JsArtifactBytes>,
) -> Result<Vec<privacy_pools_sdk_artifacts::ArtifactBytes>> {
    let engine = base64::engine::general_purpose::STANDARD;
    artifacts
        .into_iter()
        .map(|artifact| {
            Ok(privacy_pools_sdk_artifacts::ArtifactBytes {
                kind: parse_artifact_kind(&artifact.kind)?,
                bytes: engine
                    .decode(artifact.bytes_base64)
                    .context("failed to decode base64 artifact bytes")?,
            })
        })
        .collect()
}

fn to_js_artifact_status(version: &str, status: ArtifactStatus) -> JsArtifactStatus {
    JsArtifactStatus {
        version: version.to_owned(),
        circuit: status.descriptor.circuit,
        kind: artifact_kind_label(status.descriptor.kind),
        filename: status.descriptor.filename,
        path: status.path.to_string_lossy().into_owned(),
        exists: status.exists,
        verified: status.verified,
    }
}

fn to_js_resolved_artifact_bundle(bundle: ResolvedArtifactBundle) -> JsResolvedArtifactBundle {
    JsResolvedArtifactBundle {
        version: bundle.version,
        circuit: bundle.circuit,
        artifacts: bundle
            .artifacts
            .into_iter()
            .map(|artifact| JsResolvedArtifact {
                circuit: artifact.descriptor.circuit,
                kind: artifact_kind_label(artifact.descriptor.kind),
                filename: artifact.descriptor.filename,
                path: artifact.path.to_string_lossy().into_owned(),
            })
            .collect(),
    }
}

fn to_js_verified_artifact_bundle(
    bundle: privacy_pools_sdk_artifacts::VerifiedArtifactBundle,
) -> JsVerifiedArtifactBundle {
    JsVerifiedArtifactBundle {
        version: bundle.version,
        circuit: bundle.circuit,
        artifacts: bundle
            .artifacts
            .into_iter()
            .map(|artifact| JsVerifiedArtifactDescriptor {
                circuit: artifact.descriptor.circuit,
                kind: artifact_kind_label(artifact.descriptor.kind),
                filename: artifact.descriptor.filename,
                sha256: artifact.descriptor.sha256,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_status_reports_proving_blocker() {
        let status = get_browser_support_status();
        assert_eq!(status.runtime, "web");
        assert!(!status.proving_available);
        assert!(status.reason.contains("wasm-capable prover backend"));
    }

    #[test]
    fn derives_reference_keys() {
        let json =
            derive_master_keys_json("test test test test test test test test test test test junk")
                .expect("keys should derive");
        let keys: JsMasterKeys = parse_json(&json).expect("json should parse");
        assert_eq!(
            keys.master_nullifier,
            "20068762160393292801596226195912281868434195939362930533775271887246872084568"
        );
    }
}
