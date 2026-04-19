use ark_bls12_381::{Bls12_381, Fq as Bls12_381Fq, Fq2 as Bls12_381Fq2, Fr as Bls12_381Fr};
use ark_bn254::{
    Bn254, Fq as Bn254Fq, Fq2 as Bn254Fq2, Fr as Bn254Fr, G1Projective as Bn254G1Projective,
    G2Projective as Bn254G2Projective,
};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, VerifyingKey, prepare_verifying_key};
use ark_snark::SNARK;
use num_bigint::BigUint;
use privacy_pools_sdk_core::ProofBundle;
use serde_json::Value;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum PreparedVerifier {
    Bn254(Box<PreparedVerifyingKey<Bn254>>),
    Bls12_381(Box<PreparedVerifyingKey<Bls12_381>>),
}

#[derive(Debug, Clone)]
pub enum ParsedVerificationKey {
    Bn254(Box<VerifyingKey<Bn254>>),
    Bls12_381(Box<VerifyingKey<Bls12_381>>),
}

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("invalid verification key: {0}")]
    InvalidVerificationKey(String),
    #[error("invalid proof: {0}")]
    InvalidProof(String),
}

#[derive(Clone, Copy)]
enum FieldContext {
    VerificationKey,
    Proof,
}

impl PreparedVerifier {
    pub fn from_vkey_bytes(vkey_bytes: &[u8]) -> Result<Self, VerifierError> {
        Ok(ParsedVerificationKey::from_vkey_bytes(vkey_bytes)?.prepare())
    }

    pub fn verify(&self, proof: &ProofBundle) -> Result<bool, VerifierError> {
        match self {
            Self::Bn254(verifier) => verify_with_prepared_bn254_verifier(verifier, proof),
            Self::Bls12_381(verifier) => verify_with_prepared_bls12_381_verifier(verifier, proof),
        }
    }
}

impl ParsedVerificationKey {
    pub fn from_vkey_bytes(vkey_bytes: &[u8]) -> Result<Self, VerifierError> {
        let json: Value = serde_json::from_slice(vkey_bytes)
            .map_err(|error| VerifierError::InvalidVerificationKey(error.to_string()))?;
        let curve = json.get("curve").and_then(Value::as_str).unwrap_or("bn128");

        match curve {
            "bn128" | "bn254" => Ok(Self::Bn254(Box::new(parse_bn254_verifying_key(&json)?))),
            "bls12_381" => Ok(Self::Bls12_381(Box::new(parse_bls12_381_verifying_key(
                &json,
            )?))),
            other => Err(VerifierError::InvalidVerificationKey(format!(
                "unsupported verification-key curve `{other}`"
            ))),
        }
    }

    pub fn from_bn254_verifying_key(vkey: VerifyingKey<Bn254>) -> Self {
        Self::Bn254(Box::new(vkey))
    }

    pub fn from_bls12_381_verifying_key(vkey: VerifyingKey<Bls12_381>) -> Self {
        Self::Bls12_381(Box::new(vkey))
    }

    pub fn prepare(&self) -> PreparedVerifier {
        match self {
            Self::Bn254(vkey) => {
                PreparedVerifier::Bn254(Box::new(prepare_verifying_key(vkey.as_ref())))
            }
            Self::Bls12_381(vkey) => {
                PreparedVerifier::Bls12_381(Box::new(prepare_verifying_key(vkey.as_ref())))
            }
        }
    }

    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bn254(left), Self::Bn254(right)) => left == right,
            (Self::Bls12_381(left), Self::Bls12_381(right)) => left == right,
            _ => false,
        }
    }
}

fn parse_bn254_verifying_key(
    json: &Value,
) -> Result<ark_groth16::VerifyingKey<Bn254>, VerifierError> {
    Ok(ark_groth16::VerifyingKey {
        alpha_g1: parse_bn254_g1(
            json.get("vk_alpha_1")
                .ok_or_else(|| missing_vkey_field("vk_alpha_1"))?,
        )?,
        beta_g2: parse_bn254_g2(
            json.get("vk_beta_2")
                .ok_or_else(|| missing_vkey_field("vk_beta_2"))?,
        )?,
        gamma_g2: parse_bn254_g2(
            json.get("vk_gamma_2")
                .ok_or_else(|| missing_vkey_field("vk_gamma_2"))?,
        )?,
        delta_g2: parse_bn254_g2(
            json.get("vk_delta_2")
                .ok_or_else(|| missing_vkey_field("vk_delta_2"))?,
        )?,
        gamma_abc_g1: json
            .get("IC")
            .and_then(Value::as_array)
            .ok_or_else(|| missing_vkey_field("IC"))?
            .iter()
            .map(parse_bn254_g1)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_bls12_381_verifying_key(
    json: &Value,
) -> Result<ark_groth16::VerifyingKey<Bls12_381>, VerifierError> {
    Ok(ark_groth16::VerifyingKey {
        alpha_g1: parse_bls12_381_g1(
            json.get("vk_alpha_1")
                .ok_or_else(|| missing_vkey_field("vk_alpha_1"))?,
        )?,
        beta_g2: parse_bls12_381_g2(
            json.get("vk_beta_2")
                .ok_or_else(|| missing_vkey_field("vk_beta_2"))?,
        )?,
        gamma_g2: parse_bls12_381_g2(
            json.get("vk_gamma_2")
                .ok_or_else(|| missing_vkey_field("vk_gamma_2"))?,
        )?,
        delta_g2: parse_bls12_381_g2(
            json.get("vk_delta_2")
                .ok_or_else(|| missing_vkey_field("vk_delta_2"))?,
        )?,
        gamma_abc_g1: json
            .get("IC")
            .and_then(Value::as_array)
            .ok_or_else(|| missing_vkey_field("IC"))?
            .iter()
            .map(parse_bls12_381_g1)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn verify_with_prepared_bn254_verifier(
    verifier: &PreparedVerifyingKey<Bn254>,
    bundle: &ProofBundle,
) -> Result<bool, VerifierError> {
    validate_proof_metadata(bundle, &["bn128", "bn254"])?;
    let public_inputs = bundle
        .public_signals
        .iter()
        .map(|value| parse_bn254_fr(value, "public signal"))
        .collect::<Result<Vec<_>, _>>()?;
    let proof = parse_bn254_proof(bundle)?;

    Groth16::<Bn254>::verify_with_processed_vk(verifier, &public_inputs, &proof)
        .map_err(|error| VerifierError::InvalidProof(error.to_string()))
}

fn verify_with_prepared_bls12_381_verifier(
    verifier: &PreparedVerifyingKey<Bls12_381>,
    bundle: &ProofBundle,
) -> Result<bool, VerifierError> {
    validate_proof_metadata(bundle, &["bls12_381"])?;
    let public_inputs = bundle
        .public_signals
        .iter()
        .map(|value| parse_bls12_381_fr(value, "public signal"))
        .collect::<Result<Vec<_>, _>>()?;
    let proof = parse_bls12_381_proof(bundle)?;

    Groth16::<Bls12_381>::verify_with_processed_vk(verifier, &public_inputs, &proof)
        .map_err(|error| VerifierError::InvalidProof(error.to_string()))
}

fn validate_proof_metadata(
    bundle: &ProofBundle,
    allowed_curves: &[&str],
) -> Result<(), VerifierError> {
    if bundle.proof.protocol != "groth16" {
        return Err(VerifierError::InvalidProof(format!(
            "unsupported proof protocol `{}`",
            bundle.proof.protocol
        )));
    }

    if !allowed_curves
        .iter()
        .any(|curve| *curve == bundle.proof.curve)
    {
        return Err(VerifierError::InvalidProof(format!(
            "unsupported proof curve `{}`",
            bundle.proof.curve
        )));
    }

    Ok(())
}

fn parse_bn254_proof(bundle: &ProofBundle) -> Result<ark_groth16::Proof<Bn254>, VerifierError> {
    Ok(ark_groth16::Proof {
        a: parse_bn254_g1_from_pair(&bundle.proof.pi_a, "pi_a")?,
        b: parse_bn254_g2_from_rows(&bundle.proof.pi_b, "pi_b")?,
        c: parse_bn254_g1_from_pair(&bundle.proof.pi_c, "pi_c")?,
    })
}

fn parse_bls12_381_proof(
    bundle: &ProofBundle,
) -> Result<ark_groth16::Proof<Bls12_381>, VerifierError> {
    Ok(ark_groth16::Proof {
        a: parse_bls12_381_g1_from_pair(&bundle.proof.pi_a, "pi_a")?,
        b: parse_bls12_381_g2_from_rows(&bundle.proof.pi_b, "pi_b")?,
        c: parse_bls12_381_g1_from_pair(&bundle.proof.pi_c, "pi_c")?,
    })
}

fn parse_bn254_g1_from_pair(
    coordinates: &[String; 2],
    label: &str,
) -> Result<ark_bn254::G1Affine, VerifierError> {
    let x = parse_bn254_proof_fq(&coordinates[0], label)?;
    let y = parse_bn254_proof_fq(&coordinates[1], label)?;
    validate_bn254_g1(
        ark_bn254::G1Affine::new_unchecked(x, y),
        label,
        FieldContext::Proof,
    )
}

fn parse_bls12_381_g1_from_pair(
    coordinates: &[String; 2],
    label: &str,
) -> Result<ark_bls12_381::G1Affine, VerifierError> {
    let x = parse_bls12_381_proof_fq(&coordinates[0], label)?;
    let y = parse_bls12_381_proof_fq(&coordinates[1], label)?;
    validate_bls12_381_g1(
        ark_bls12_381::G1Affine::new_unchecked(x, y),
        label,
        FieldContext::Proof,
    )
}

fn parse_bn254_g2_from_rows(
    coordinates: &[[String; 2]; 2],
    label: &str,
) -> Result<ark_bn254::G2Affine, VerifierError> {
    let x = Bn254Fq2::new(
        parse_bn254_proof_fq(&coordinates[0][0], label)?,
        parse_bn254_proof_fq(&coordinates[0][1], label)?,
    );
    let y = Bn254Fq2::new(
        parse_bn254_proof_fq(&coordinates[1][0], label)?,
        parse_bn254_proof_fq(&coordinates[1][1], label)?,
    );
    validate_bn254_g2(
        ark_bn254::G2Affine::new_unchecked(x, y),
        label,
        FieldContext::Proof,
    )
}

fn parse_bls12_381_g2_from_rows(
    coordinates: &[[String; 2]; 2],
    label: &str,
) -> Result<ark_bls12_381::G2Affine, VerifierError> {
    let x = Bls12_381Fq2::new(
        parse_bls12_381_proof_fq(&coordinates[0][0], label)?,
        parse_bls12_381_proof_fq(&coordinates[0][1], label)?,
    );
    let y = Bls12_381Fq2::new(
        parse_bls12_381_proof_fq(&coordinates[1][0], label)?,
        parse_bls12_381_proof_fq(&coordinates[1][1], label)?,
    );
    validate_bls12_381_g2(
        ark_bls12_381::G2Affine::new_unchecked(x, y),
        label,
        FieldContext::Proof,
    )
}

fn parse_bn254_g1(value: &Value) -> Result<ark_bn254::G1Affine, VerifierError> {
    let coordinates = value.as_array().ok_or_else(|| {
        VerifierError::InvalidVerificationKey("expected G1 point array".to_owned())
    })?;
    let x = parse_bn254_value(coordinates.first(), "missing G1 x")?;
    let y = parse_bn254_value(coordinates.get(1), "missing G1 y")?;
    let z = parse_optional_bn254_value(coordinates.get(2), "missing G1 z")?;

    validate_bn254_g1(
        Bn254G1Projective::new_unchecked(x, y, z).into(),
        "verification key G1 point",
        FieldContext::VerificationKey,
    )
}

fn parse_bls12_381_g1(value: &Value) -> Result<ark_bls12_381::G1Affine, VerifierError> {
    let coordinates = value.as_array().ok_or_else(|| {
        VerifierError::InvalidVerificationKey("expected G1 point array".to_owned())
    })?;
    let x = parse_bls12_381_value(coordinates.first(), "missing G1 x")?;
    let y = parse_bls12_381_value(coordinates.get(1), "missing G1 y")?;
    let z = parse_optional_bls12_381_value(coordinates.get(2), "missing G1 z")?;

    validate_bls12_381_g1(
        ark_bls12_381::G1Projective::new_unchecked(x, y, z).into(),
        "verification key G1 point",
        FieldContext::VerificationKey,
    )
}

fn parse_bn254_g2(value: &Value) -> Result<ark_bn254::G2Affine, VerifierError> {
    let coordinates = value.as_array().ok_or_else(|| {
        VerifierError::InvalidVerificationKey("expected G2 point array".to_owned())
    })?;
    let x = parse_bn254_fq2(
        coordinates
            .first()
            .ok_or_else(|| VerifierError::InvalidVerificationKey("missing G2 x".to_owned()))?,
    )?;
    let y = parse_bn254_fq2(
        coordinates
            .get(1)
            .ok_or_else(|| VerifierError::InvalidVerificationKey("missing G2 y".to_owned()))?,
    )?;
    let z = parse_optional_bn254_fq2(coordinates.get(2), "missing G2 z")?;

    validate_bn254_g2(
        Bn254G2Projective::new_unchecked(x, y, z).into(),
        "verification key G2 point",
        FieldContext::VerificationKey,
    )
}

fn parse_bls12_381_g2(value: &Value) -> Result<ark_bls12_381::G2Affine, VerifierError> {
    let coordinates = value.as_array().ok_or_else(|| {
        VerifierError::InvalidVerificationKey("expected G2 point array".to_owned())
    })?;
    let x = parse_bls12_381_fq2(
        coordinates
            .first()
            .ok_or_else(|| VerifierError::InvalidVerificationKey("missing G2 x".to_owned()))?,
    )?;
    let y = parse_bls12_381_fq2(
        coordinates
            .get(1)
            .ok_or_else(|| VerifierError::InvalidVerificationKey("missing G2 y".to_owned()))?,
    )?;
    let z = parse_optional_bls12_381_fq2(coordinates.get(2), "missing G2 z")?;

    validate_bls12_381_g2(
        ark_bls12_381::G2Projective::new_unchecked(x, y, z).into(),
        "verification key G2 point",
        FieldContext::VerificationKey,
    )
}

fn parse_bn254_fq2(value: &Value) -> Result<Bn254Fq2, VerifierError> {
    let coordinates = value.as_array().ok_or_else(|| {
        VerifierError::InvalidVerificationKey("expected Fq2 coordinate array".to_owned())
    })?;
    Ok(Bn254Fq2::new(
        parse_bn254_value(coordinates.first(), "missing Fq2 c0")?,
        parse_bn254_value(coordinates.get(1), "missing Fq2 c1")?,
    ))
}

fn parse_bls12_381_fq2(value: &Value) -> Result<Bls12_381Fq2, VerifierError> {
    let coordinates = value.as_array().ok_or_else(|| {
        VerifierError::InvalidVerificationKey("expected Fq2 coordinate array".to_owned())
    })?;
    Ok(Bls12_381Fq2::new(
        parse_bls12_381_value(coordinates.first(), "missing Fq2 c0")?,
        parse_bls12_381_value(coordinates.get(1), "missing Fq2 c1")?,
    ))
}

fn parse_bn254_value(
    value: Option<&Value>,
    missing_message: &str,
) -> Result<Bn254Fq, VerifierError> {
    match value {
        Some(value) => parse_bn254_fq(
            value.as_str().ok_or_else(|| {
                VerifierError::InvalidVerificationKey("expected decimal string".to_owned())
            })?,
            "verification key",
        ),
        None => Err(VerifierError::InvalidVerificationKey(
            missing_message.to_owned(),
        )),
    }
}

fn parse_bls12_381_value(
    value: Option<&Value>,
    missing_message: &str,
) -> Result<Bls12_381Fq, VerifierError> {
    match value {
        Some(value) => parse_bls12_381_fq(
            value.as_str().ok_or_else(|| {
                VerifierError::InvalidVerificationKey("expected decimal string".to_owned())
            })?,
            "verification key",
        ),
        None => Err(VerifierError::InvalidVerificationKey(
            missing_message.to_owned(),
        )),
    }
}

fn parse_optional_bn254_value(
    value: Option<&Value>,
    missing_message: &str,
) -> Result<Bn254Fq, VerifierError> {
    match value {
        Some(value) => {
            let parsed = parse_bn254_value(Some(value), missing_message)?;
            if parsed == Bn254Fq::from(0u64) {
                return Err(VerifierError::InvalidVerificationKey(
                    "verification key G1 z must not be zero".to_owned(),
                ));
            }
            Ok(parsed)
        }
        None => {
            let _ = missing_message;
            Ok(Bn254Fq::from(1u64))
        }
    }
}

fn parse_optional_bls12_381_value(
    value: Option<&Value>,
    missing_message: &str,
) -> Result<Bls12_381Fq, VerifierError> {
    match value {
        Some(value) => {
            let parsed = parse_bls12_381_value(Some(value), missing_message)?;
            if parsed == Bls12_381Fq::from(0u64) {
                return Err(VerifierError::InvalidVerificationKey(
                    "verification key G1 z must not be zero".to_owned(),
                ));
            }
            Ok(parsed)
        }
        None => {
            let _ = missing_message;
            Ok(Bls12_381Fq::from(1u64))
        }
    }
}

fn parse_optional_bn254_fq2(
    value: Option<&Value>,
    missing_message: &str,
) -> Result<Bn254Fq2, VerifierError> {
    match value {
        Some(value) => {
            let parsed = parse_bn254_fq2(value)?;
            if parsed == Bn254Fq2::new(Bn254Fq::from(0u64), Bn254Fq::from(0u64)) {
                return Err(VerifierError::InvalidVerificationKey(
                    "verification key G2 z must not be zero".to_owned(),
                ));
            }
            Ok(parsed)
        }
        None => {
            let _ = missing_message;
            Ok(Bn254Fq2::new(Bn254Fq::from(1u64), Bn254Fq::from(0u64)))
        }
    }
}

fn parse_optional_bls12_381_fq2(
    value: Option<&Value>,
    missing_message: &str,
) -> Result<Bls12_381Fq2, VerifierError> {
    match value {
        Some(value) => {
            let parsed = parse_bls12_381_fq2(value)?;
            if parsed == Bls12_381Fq2::new(Bls12_381Fq::from(0u64), Bls12_381Fq::from(0u64)) {
                return Err(VerifierError::InvalidVerificationKey(
                    "verification key G2 z must not be zero".to_owned(),
                ));
            }
            Ok(parsed)
        }
        None => {
            let _ = missing_message;
            Ok(Bls12_381Fq2::new(
                Bls12_381Fq::from(1u64),
                Bls12_381Fq::from(0u64),
            ))
        }
    }
}

fn parse_bn254_fq(value: &str, label: &str) -> Result<Bn254Fq, VerifierError> {
    parse_prime_field(value, label, FieldContext::VerificationKey)
}

fn parse_bls12_381_fq(value: &str, label: &str) -> Result<Bls12_381Fq, VerifierError> {
    parse_prime_field(value, label, FieldContext::VerificationKey)
}

fn parse_bn254_proof_fq(value: &str, label: &str) -> Result<Bn254Fq, VerifierError> {
    parse_prime_field(value, label, FieldContext::Proof)
}

fn parse_bls12_381_proof_fq(value: &str, label: &str) -> Result<Bls12_381Fq, VerifierError> {
    parse_prime_field(value, label, FieldContext::Proof)
}

fn parse_bn254_fr(value: &str, label: &str) -> Result<Bn254Fr, VerifierError> {
    parse_prime_field(value, label, FieldContext::Proof)
}

fn parse_bls12_381_fr(value: &str, label: &str) -> Result<Bls12_381Fr, VerifierError> {
    parse_prime_field(value, label, FieldContext::Proof)
}

fn parse_prime_field<F: PrimeField>(
    value: &str,
    label: &str,
    context: FieldContext,
) -> Result<F, VerifierError>
where
    <F as PrimeField>::BigInt: TryFrom<BigUint>,
    BigUint: From<<F as PrimeField>::BigInt>,
{
    let integer = BigUint::from_str(value)
        .map_err(|_| invalid_field_element(context, label, value, "expected unsigned decimal"))?;
    if integer >= BigUint::from(F::MODULUS) {
        return Err(invalid_field_element(
            context,
            label,
            value,
            "field element is not canonical",
        ));
    }

    let bigint = <F as PrimeField>::BigInt::try_from(integer)
        .map_err(|_| invalid_field_element(context, label, value, "field element is too large"))?;
    F::from_bigint(bigint)
        .ok_or_else(|| invalid_field_element(context, label, value, "invalid field element"))
}

fn validate_bn254_g1(
    point: ark_bn254::G1Affine,
    label: &str,
    context: FieldContext,
) -> Result<ark_bn254::G1Affine, VerifierError> {
    if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
        Ok(point)
    } else {
        Err(invalid_curve_point(context, label))
    }
}

fn validate_bn254_g2(
    point: ark_bn254::G2Affine,
    label: &str,
    context: FieldContext,
) -> Result<ark_bn254::G2Affine, VerifierError> {
    if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
        Ok(point)
    } else {
        Err(invalid_curve_point(context, label))
    }
}

fn validate_bls12_381_g1(
    point: ark_bls12_381::G1Affine,
    label: &str,
    context: FieldContext,
) -> Result<ark_bls12_381::G1Affine, VerifierError> {
    if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
        Ok(point)
    } else {
        Err(invalid_curve_point(context, label))
    }
}

fn validate_bls12_381_g2(
    point: ark_bls12_381::G2Affine,
    label: &str,
    context: FieldContext,
) -> Result<ark_bls12_381::G2Affine, VerifierError> {
    if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
        Ok(point)
    } else {
        Err(invalid_curve_point(context, label))
    }
}

fn invalid_field_element(
    context: FieldContext,
    label: &str,
    value: &str,
    reason: &str,
) -> VerifierError {
    match context {
        FieldContext::VerificationKey => VerifierError::InvalidVerificationKey(format!(
            "invalid {label} field element `{value}`: {reason}"
        )),
        FieldContext::Proof => VerifierError::InvalidProof(format!(
            "invalid {label} field element `{value}`: {reason}"
        )),
    }
}

fn invalid_curve_point(context: FieldContext, label: &str) -> VerifierError {
    match context {
        FieldContext::VerificationKey => {
            VerifierError::InvalidVerificationKey(format!("invalid {label} curve point"))
        }
        FieldContext::Proof => VerifierError::InvalidProof(format!("invalid {label} curve point")),
    }
}

fn missing_vkey_field(field: &str) -> VerifierError {
    VerifierError::InvalidVerificationKey(format!("missing verification-key field `{field}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_snark::SNARK;
    use ark_std::{
        UniformRand,
        rand::{SeedableRng, rngs::StdRng},
    };
    use privacy_pools_sdk_core::{ProofBundle, SnarkJsProof};
    use proptest::prelude::*;
    use serde_json::json;

    #[derive(Clone)]
    struct MultiplyCircuit {
        x: Option<Bn254Fr>,
        y: Option<Bn254Fr>,
        z: Option<Bn254Fr>,
    }

    impl ConstraintSynthesizer<Bn254Fr> for MultiplyCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<Bn254Fr>,
        ) -> Result<(), SynthesisError> {
            let x = cs.new_input_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let y = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
            let z = cs.new_witness_variable(|| self.z.ok_or(SynthesisError::AssignmentMissing))?;

            cs.enforce_constraint(lc!() + x, lc!() + y, lc!() + z)?;
            Ok(())
        }
    }

    #[test]
    fn verifies_generated_bn254_proof() {
        let fixture = generate_bn254_fixture();
        let verifier =
            PreparedVerifier::from_vkey_bytes(fixture.vkey_json.as_bytes()).expect("vkey parses");
        assert!(verifier.verify(&fixture.proof).expect("proof verifies"));
    }

    #[test]
    fn rejects_tampered_public_signal() {
        let fixture = generate_bn254_fixture();
        let verifier =
            PreparedVerifier::from_vkey_bytes(fixture.vkey_json.as_bytes()).expect("vkey parses");
        let mut tampered = fixture.proof.clone();
        tampered.public_signals[0] = "9".to_owned();
        assert!(!verifier.verify(&tampered).expect("verification completes"));
    }

    #[test]
    fn rejects_noncanonical_public_signal() {
        let fixture = generate_bn254_fixture();
        let verifier =
            PreparedVerifier::from_vkey_bytes(fixture.vkey_json.as_bytes()).expect("vkey parses");
        let mut tampered = fixture.proof.clone();
        tampered.public_signals[0] = add_field_modulus::<Bn254Fr>(&tampered.public_signals[0]);

        let error = verifier
            .verify(&tampered)
            .expect_err("non-canonical public signal should fail before verification");
        assert!(matches!(error, VerifierError::InvalidProof(_)));
    }

    #[test]
    fn rejects_noncanonical_proof_coordinate() {
        let fixture = generate_bn254_fixture();
        let verifier =
            PreparedVerifier::from_vkey_bytes(fixture.vkey_json.as_bytes()).expect("vkey parses");
        let mut tampered = fixture.proof.clone();
        tampered.proof.pi_a[0] = add_field_modulus::<Bn254Fq>(&tampered.proof.pi_a[0]);

        let error = verifier
            .verify(&tampered)
            .expect_err("non-canonical proof coordinate should fail before verification");
        assert!(matches!(error, VerifierError::InvalidProof(_)));
    }

    #[test]
    fn rejects_invalid_proof_curve_point_without_panicking() {
        let fixture = generate_bn254_fixture();
        let verifier =
            PreparedVerifier::from_vkey_bytes(fixture.vkey_json.as_bytes()).expect("vkey parses");
        let mut tampered = fixture.proof.clone();
        tampered.proof.pi_a = ["0".to_owned(), "0".to_owned()];

        let error = verifier
            .verify(&tampered)
            .expect_err("invalid proof point should fail without panicking");
        assert!(matches!(error, VerifierError::InvalidProof(_)));
    }

    #[test]
    fn rejects_noncanonical_verification_key_coordinate() {
        let fixture = generate_bn254_fixture();
        let mut vkey: Value =
            serde_json::from_str(&fixture.vkey_json).expect("vkey fixture parses");
        let alpha_x = vkey["vk_alpha_1"][0]
            .as_str()
            .expect("alpha x is a decimal string");
        vkey["vk_alpha_1"][0] = json!(add_field_modulus::<Bn254Fq>(alpha_x));
        let vkey_json = serde_json::to_vec(&vkey).expect("vkey serializes");

        let error = PreparedVerifier::from_vkey_bytes(&vkey_json)
            .expect_err("non-canonical vkey coordinate should fail");
        assert!(matches!(error, VerifierError::InvalidVerificationKey(_)));
    }

    #[test]
    fn rejects_verification_key_projective_zero_z_coordinate() {
        let fixture = generate_bn254_fixture();
        let mut vkey: Value =
            serde_json::from_str(&fixture.vkey_json).expect("vkey fixture parses");
        let alpha_x = vkey["vk_alpha_1"][0].clone();
        let alpha_y = vkey["vk_alpha_1"][1].clone();
        vkey["vk_alpha_1"] = json!([alpha_x, alpha_y, "0"]);
        let vkey_json = serde_json::to_vec(&vkey).expect("vkey serializes");

        let error = PreparedVerifier::from_vkey_bytes(&vkey_json)
            .expect_err("verification key z = 0 should fail");
        assert!(matches!(error, VerifierError::InvalidVerificationKey(message) if message.contains("z must not be zero")));
    }

    #[test]
    fn rejects_wrong_curve_metadata() {
        let fixture = generate_bn254_fixture();
        let verifier =
            PreparedVerifier::from_vkey_bytes(fixture.vkey_json.as_bytes()).expect("vkey parses");
        let mut tampered = fixture.proof.clone();
        tampered.proof.curve = "bls12_381".to_owned();
        let error = verifier
            .verify(&tampered)
            .expect_err("curve mismatch should fail");
        assert!(matches!(error, VerifierError::InvalidProof(_)));
    }

    #[test]
    fn parsed_verification_keys_detect_mismatches() {
        let first = generate_bn254_fixture_with_seed(7);
        let second = generate_bn254_fixture_with_seed(8);

        let first_vkey = ParsedVerificationKey::from_vkey_bytes(first.vkey_json.as_bytes())
            .expect("first vkey parses");
        let first_vkey_again = ParsedVerificationKey::from_vkey_bytes(first.vkey_json.as_bytes())
            .expect("first vkey parses again");
        let second_vkey = ParsedVerificationKey::from_vkey_bytes(second.vkey_json.as_bytes())
            .expect("second vkey parses");

        assert!(first_vkey.matches(&first_vkey_again));
        assert!(!first_vkey.matches(&second_vkey));
    }

    proptest! {
        #[test]
        fn malformed_public_signal_strings_fail_closed(value in "[a-zA-Z][a-zA-Z0-9]{0,16}") {
            prop_assert!(parse_bn254_fr(&value, "public signal").is_err());
        }

        #[test]
        fn noncanonical_proof_coordinates_fail_closed(value in 0_u64..u64::MAX) {
            let noncanonical = add_field_modulus::<Bn254Fq>(&value.to_string());
            let proof = ProofBundle {
                proof: SnarkJsProof {
                    pi_a: [noncanonical, "1".to_owned()],
                    pi_b: [
                        ["1".to_owned(), "2".to_owned()],
                        ["3".to_owned(), "4".to_owned()],
                    ],
                    pi_c: ["5".to_owned(), "6".to_owned()],
                    protocol: "groth16".to_owned(),
                    curve: "bn128".to_owned(),
                },
                public_signals: vec!["1".to_owned()],
            };

            prop_assert!(matches!(
                parse_bn254_proof(&proof),
                Err(VerifierError::InvalidProof(_))
            ));
        }
    }

    #[test]
    #[ignore = "utility for regenerating browser verification fixtures"]
    fn emit_bn254_fixture_json() {
        let fixture = generate_bn254_fixture();
        println!("VKEY_JSON_START");
        println!("{}", fixture.vkey_json);
        println!("VKEY_JSON_END");
        println!("PROOF_JSON_START");
        println!(
            "{}",
            serde_json::to_string_pretty(&to_browser_proof_bundle(&fixture.proof))
                .expect("proof fixture should serialize")
        );
        println!("PROOF_JSON_END");
    }

    struct TestFixture {
        vkey_json: String,
        proof: ProofBundle,
    }

    fn generate_bn254_fixture() -> TestFixture {
        generate_bn254_fixture_with_seed(7)
    }

    fn generate_bn254_fixture_with_seed(seed: u64) -> TestFixture {
        let mut rng = StdRng::seed_from_u64(seed);
        let empty_circuit = MultiplyCircuit {
            x: None,
            y: None,
            z: None,
        };
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(empty_circuit, &mut rng).expect("setup");

        let x = Bn254Fr::rand(&mut rng);
        let y = Bn254Fr::rand(&mut rng);
        let z = x * y;
        let circuit = MultiplyCircuit {
            x: Some(x),
            y: Some(y),
            z: Some(z),
        };
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("proof");

        TestFixture {
            vkey_json: serde_json::to_string_pretty(&json!({
                "protocol": "groth16",
                "curve": "bn128",
                "vk_alpha_1": g1_json(vk.alpha_g1),
                "vk_beta_2": g2_json(vk.beta_g2),
                "vk_gamma_2": g2_json(vk.gamma_g2),
                "vk_delta_2": g2_json(vk.delta_g2),
                "IC": vk.gamma_abc_g1.into_iter().map(g1_json).collect::<Vec<_>>(),
            }))
            .expect("vkey fixture should serialize"),
            proof: ProofBundle {
                proof: SnarkJsProof {
                    pi_a: [proof.a.x.to_string(), proof.a.y.to_string()],
                    pi_b: [
                        [proof.b.x.c0.to_string(), proof.b.x.c1.to_string()],
                        [proof.b.y.c0.to_string(), proof.b.y.c1.to_string()],
                    ],
                    pi_c: [proof.c.x.to_string(), proof.c.y.to_string()],
                    protocol: "groth16".to_owned(),
                    curve: "bn128".to_owned(),
                },
                public_signals: vec![x.to_string(), y.to_string()],
            },
        }
    }

    fn g1_json(point: ark_bn254::G1Affine) -> Vec<String> {
        vec![point.x.to_string(), point.y.to_string()]
    }

    fn g2_json(point: ark_bn254::G2Affine) -> Vec<Vec<String>> {
        vec![
            vec![point.x.c0.to_string(), point.x.c1.to_string()],
            vec![point.y.c0.to_string(), point.y.c1.to_string()],
        ]
    }

    fn add_field_modulus<F: PrimeField>(value: &str) -> String
    where
        BigUint: From<<F as PrimeField>::BigInt>,
    {
        (BigUint::from_str(value).expect("decimal field element parses")
            + BigUint::from(F::MODULUS))
        .to_string()
    }

    fn to_browser_proof_bundle(proof: &ProofBundle) -> Value {
        json!({
            "proof": {
                "piA": proof.proof.pi_a,
                "piB": proof.proof.pi_b,
                "piC": proof.proof.pi_c,
                "protocol": proof.proof.protocol,
                "curve": proof.proof.curve,
            },
            "publicSignals": proof.public_signals,
        })
    }
}
