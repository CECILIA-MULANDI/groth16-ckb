#![no_std]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]

//! Bridge between the on-chain Molecule wire format and the arkworks-shaped
//! byte buffers `verifier-core::verify` consumes.
//!
//! Two entry points:
//! * [`decode_vk_to_arkworks`] turns a `Groth16VerifyingKey` Molecule blob
//!   into the arkworks VK serialization
//!   (`alpha_g1 ‖ beta_g2 ‖ gamma_g2 ‖ delta_g2 ‖ u64_le ic_len ‖ ic_len × 32 B`).
//! * [`decode_witness_to_arkworks`] turns a `Groth16Witness` Molecule blob
//!   into `(proof_bytes, public_inputs_bytes)`.
//!
//! Both functions are total: they return `Err(DecodeError)` for any malformed
//! input and never panic. Suitable for adversarial bytes, which is why they
//! are pulled out of the on-chain binary into their own crate — the fuzz
//! harness in `fuzz/` exercises the same code that ships on chain.

extern crate alloc;

use alloc::vec::Vec;

use groth16_schema::{
    Groth16VerifyingKeyReader, Groth16WitnessReader, VerifyingKeyContentUnionReader,
    WitnessContentUnionReader,
};
use molecule::prelude::Reader;

// Wire-format constants (must agree with the schema in `schemas/groth16.mol`
// and the layout `verifier-core::verify` expects).
pub const VERSION_V1: u16 = 1;

const G1_LEN: usize = 32;
const G2_LEN: usize = 64;
const FR_LEN: usize = 32;

const PROOF_LEN: usize = G1_LEN + G2_LEN + G1_LEN; // 128
const VK_FIXED_HEADER_LEN: usize = G1_LEN + 3 * G2_LEN; // 224
const VK_VEC_PREFIX_LEN: usize = 8; // u64 ic_len
const PI_PREFIX_LEN: usize = 4; // u32 count

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    /// Molecule structural validation failed (bad offsets, item counts,
    /// fixed-array sizes, or union tag).
    Molecule,
    /// Wire-format `version` field did not match [`VERSION_V1`].
    Version,
}

/// Decode `Groth16VerifyingKey` and rebuild the arkworks VK buffer:
///
/// ```text
///   alpha_g1 (32) ‖ beta_g2 (64) ‖ gamma_g2 (64) ‖ delta_g2 (64)
///     ‖ u64_le ic_len ‖ ic_len × 32 B (gamma_abc_g1 entries)
/// ```
///
/// `Reader::from_slice` recursively validates structure, so once we hold a
/// Reader every `as_slice()` returns a correctly-sized byte string.
pub fn decode_vk_to_arkworks(molecule_bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let r = Groth16VerifyingKeyReader::from_slice(molecule_bytes).map_err(|_| DecodeError::Molecule)?;

    let version_bytes: [u8; 2] = r
        .version()
        .as_slice()
        .try_into()
        .map_err(|_| DecodeError::Molecule)?;
    if u16::from_le_bytes(version_bytes) != VERSION_V1 {
        return Err(DecodeError::Version);
    }

    // Single union variant today; when the schema gains curves the compiler
    // will require a new arm here.
    let bn254 = match r.content().to_enum() {
        VerifyingKeyContentUnionReader::VerifyingKeyBn254(v) => v,
    };

    let ic = bn254.gamma_abc_g1();
    let ic_len = ic.item_count();

    let mut buf = Vec::with_capacity(VK_FIXED_HEADER_LEN + VK_VEC_PREFIX_LEN + ic_len * G1_LEN);
    buf.extend_from_slice(bn254.alpha_g1().as_slice());
    buf.extend_from_slice(bn254.beta_g2().as_slice());
    buf.extend_from_slice(bn254.gamma_g2().as_slice());
    buf.extend_from_slice(bn254.delta_g2().as_slice());
    buf.extend_from_slice(&(ic_len as u64).to_le_bytes());
    for i in 0..ic_len {
        buf.extend_from_slice(ic.get_unchecked(i).as_slice());
    }
    Ok(buf)
}

/// Decode `Groth16Witness` and produce arkworks-shaped `(proof, public_inputs)`:
///
/// ```text
///   proof: a (32) ‖ b (64) ‖ c (32)                   — fixed 128 bytes
///   pi:    u32_le count ‖ count × 32 B (Fr elements)
/// ```
pub fn decode_witness_to_arkworks(
    molecule_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), DecodeError> {
    let r = Groth16WitnessReader::from_slice(molecule_bytes).map_err(|_| DecodeError::Molecule)?;

    let version_bytes: [u8; 2] = r
        .version()
        .as_slice()
        .try_into()
        .map_err(|_| DecodeError::Molecule)?;
    if u16::from_le_bytes(version_bytes) != VERSION_V1 {
        return Err(DecodeError::Version);
    }

    let bn254 = match r.content().to_enum() {
        WitnessContentUnionReader::Bn254Witness(v) => v,
    };

    let proof = bn254.proof();
    let mut proof_buf = Vec::with_capacity(PROOF_LEN);
    proof_buf.extend_from_slice(proof.a().as_slice());
    proof_buf.extend_from_slice(proof.b().as_slice());
    proof_buf.extend_from_slice(proof.c().as_slice());

    let pi = bn254.public_inputs();
    let count = pi.item_count();
    let mut pi_buf = Vec::with_capacity(PI_PREFIX_LEN + count * FR_LEN);
    pi_buf.extend_from_slice(&(count as u32).to_le_bytes());
    for i in 0..count {
        pi_buf.extend_from_slice(pi.get_unchecked(i).as_slice());
    }

    Ok((proof_buf, pi_buf))
}
