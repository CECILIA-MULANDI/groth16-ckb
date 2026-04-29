#![no_std]

//! Groth16 verifier for CKB-VM.
//!
//! Curve:   BN254
//! Encoding: arkworks compressed serialization
//!
//! Wire formats accepted by [`verify`] (Phase 0 — placeholder; Phase 1 finalises
//! a versioned, curve-tagged Molecule schema):
//!
//! * `vk_bytes`      — `arkworks::VerifyingKey<Bn254>` compressed.
//!   Layout: 224 B fixed header (alpha_g1 ‖ beta_g2 ‖ gamma_g2 ‖ delta_g2)
//!   ‖ 8 B `u64` LE length prefix `ic_len` ‖ `ic_len × 32 B` for `gamma_abc_g1`.
//! * `proof_bytes`   — `arkworks::Proof<Bn254>` compressed, always 128 bytes.
//! * `public_inputs_bytes` — `u32` LE length prefix, then `count × 32 B` `Fr` elements.
//!
//! All three lengths are pre-checked exactly before any allocation or
//! deserialization. arkworks' `Vec::deserialize_compressed` allocates from the
//! embedded length prefix without bounding against the buffer, which would
//! otherwise let an attacker trigger a multi-GB allocation by flipping a bit
//! in `ic_len` or `count`. The explicit checks below close that gap.

extern crate alloc;

use alloc::vec::Vec;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;

const G1_AFFINE_LEN: usize = 32;
const G2_AFFINE_LEN: usize = 64;
const FR_LEN: usize = 32;

const VK_FIXED_HEADER_LEN: usize = G1_AFFINE_LEN + 3 * G2_AFFINE_LEN; // 224
const VK_VEC_PREFIX_LEN: usize = 8; // u64
const VK_PRELUDE_LEN: usize = VK_FIXED_HEADER_LEN + VK_VEC_PREFIX_LEN; // 232

const PROOF_LEN: usize = G1_AFFINE_LEN + G2_AFFINE_LEN + G1_AFFINE_LEN; // 128

const PI_PREFIX_LEN: usize = 4; // u32

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// VK bytes failed length validation, parsing, or contained invalid points.
    InvalidVk,
    /// Proof bytes failed length validation or parsing.
    InvalidProof,
    /// Public-input bytes failed length validation or parsing.
    InvalidPublicInputs,
    /// `count + 1` disagrees with `vk.gamma_abc_g1.len()`.
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
    // ---- Length pre-checks: bound every attacker-controlled length prefix
    // against the actual buffer before any allocation or deserialization.

    if proof_bytes.len() != PROOF_LEN {
        return Err(VerifyError::InvalidProof);
    }

    if vk_bytes.len() < VK_PRELUDE_LEN {
        return Err(VerifyError::InvalidVk);
    }
    let ic_len_bytes: [u8; 8] = vk_bytes[VK_FIXED_HEADER_LEN..VK_PRELUDE_LEN]
        .try_into()
        .map_err(|_| VerifyError::InvalidVk)?;
    let ic_len = u64::from_le_bytes(ic_len_bytes);
    // Groth16 requires at least one IC entry (the constant term).
    if ic_len == 0 {
        return Err(VerifyError::InvalidVk);
    }
    let ic_body_len = (ic_len as usize)
        .checked_mul(G1_AFFINE_LEN)
        .ok_or(VerifyError::InvalidVk)?;
    let vk_expected_len = VK_PRELUDE_LEN
        .checked_add(ic_body_len)
        .ok_or(VerifyError::InvalidVk)?;
    if vk_bytes.len() != vk_expected_len {
        return Err(VerifyError::InvalidVk);
    }

    if public_inputs_bytes.len() < PI_PREFIX_LEN {
        return Err(VerifyError::InvalidPublicInputs);
    }
    let count_bytes: [u8; 4] = public_inputs_bytes[..PI_PREFIX_LEN]
        .try_into()
        .map_err(|_| VerifyError::InvalidPublicInputs)?;
    let count = u32::from_le_bytes(count_bytes);
    let pi_body_len = (count as usize)
        .checked_mul(FR_LEN)
        .ok_or(VerifyError::InvalidPublicInputs)?;
    let pi_expected_len = PI_PREFIX_LEN
        .checked_add(pi_body_len)
        .ok_or(VerifyError::InvalidPublicInputs)?;
    if public_inputs_bytes.len() != pi_expected_len {
        return Err(VerifyError::InvalidPublicInputs);
    }

    // Cross-check: public-input count must match VK's IC length.
    // (Catches a flip in either prefix without paying for VK deserialization.)
    if (count as u64) + 1 != ic_len {
        return Err(VerifyError::PublicInputCountMismatch);
    }

    // ---- Safe to delegate: every internal length is bounded by the input buffer.

    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .map_err(|_| VerifyError::InvalidVk)?;

    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|_| VerifyError::InvalidProof)?;

    let mut cursor: &[u8] = &public_inputs_bytes[PI_PREFIX_LEN..];
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
