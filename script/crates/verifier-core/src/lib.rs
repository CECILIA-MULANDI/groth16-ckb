#![no_std]

//! Groth16 verifier for CKB-VM.
//!
//! Curve:   BN254
//! Encoding: arkworks compressed serialization
//!
//! Wire formats accepted by [`verify`] (Phase 0 — placeholder; Phase 1 finalises
//! a versioned, curve-tagged Molecule schema):
//!
//! * `vk_bytes`      — `arkworks::VerifyingKey<Bn254>` compressed
//! * `proof_bytes`   — `arkworks::Proof<Bn254>` compressed (always 128 bytes)
//! * `public_inputs_bytes` — `u32` LE length prefix, then `count` × `Fr` compressed (32 bytes each)

extern crate alloc;

use alloc::vec::Vec;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// VK bytes failed to parse (bad encoding, off-curve point, or non-subgroup point).
    InvalidVk,
    /// Proof bytes failed to parse.
    InvalidProof,
    /// Public-input bytes failed to parse.
    InvalidPublicInputs,
    /// Number of public inputs disagrees with `vk.gamma_abc_g1.len() - 1`.
    PublicInputCountMismatch,
    /// Pairing check rejected the proof.
    VerificationFailed,
}
/// Verify a Groth16 proof on BN254.
///
/// Returns `Ok(())` only if the proof is valid for the given verification key
/// and public inputs. Every other outcome — malformed inputs, count mismatch,
/// invalid pairing — is a distinct `VerifyError` variant.
///
/// Never panics. Suitable for adversarial input.
pub fn verify(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<(), VerifyError> {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .map_err(|_| VerifyError::InvalidVk)?;

    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|_| VerifyError::InvalidProof)?;

    let mut cursor: &[u8] = public_inputs_bytes;
    let count =
        u32::deserialize_compressed(&mut cursor).map_err(|_| VerifyError::InvalidPublicInputs)?;

    if (count as usize) + 1 != vk.gamma_abc_g1.len() {
        return Err(VerifyError::PublicInputCountMismatch);
    }

    let mut public_inputs: Vec<Fr> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let fe = Fr::deserialize_compressed(&mut cursor)
            .map_err(|_| VerifyError::InvalidPublicInputs)?;
        public_inputs.push(fe);
    }

    match Groth16::<Bn254>::verify(&vk, &public_inputs, &proof) {
        Ok(true) => Ok(()),
        _ => Err(VerifyError::VerificationFailed),
    }
}
