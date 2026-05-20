#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!();

use alloc::vec::Vec;

use ckb_std::{
    ckb_constants::Source,
    error::SysError,
    high_level::{load_cell_data, load_script, load_witness_args, look_for_dep_with_data_hash},
};
use verifier_core::VerifyError;
use wire_decode::{decode_vk_to_arkworks, decode_witness_to_arkworks, DecodeError};

const ARGS_LEN: usize = 32;

// ---- Exit codes

const ERROR_INVALID_VK: i8 = 1;
const ERROR_INVALID_PROOF: i8 = 2;
const ERROR_INVALID_PUBLIC_INPUTS: i8 = 3;
const ERROR_PUBLIC_INPUT_COUNT_MISMATCH: i8 = 4;
const ERROR_VERIFICATION_FAILED: i8 = 5;

const ERROR_SCRIPT_LOAD_FAILED: i8 = 10;
const ERROR_BAD_ARGS_LENGTH: i8 = 11;
const ERROR_VK_CELL_NOT_FOUND: i8 = 12;
const ERROR_VK_LOAD_FAILED: i8 = 13;
const ERROR_VK_MOLECULE_DECODE: i8 = 14;
const ERROR_WITNESS_LOAD_FAILED: i8 = 15;
const ERROR_WITNESS_MISSING_INPUT_TYPE: i8 = 16;
const ERROR_WITNESS_MOLECULE_DECODE: i8 = 17;
const ERROR_VERSION_MISMATCH: i8 = 18;
// Reserved for when `VerifyingKeyContent` / `WitnessContent` gain non-BN254
// variants. Today the union has a single curve so the match in wire-decode is
// exhaustive without producing this code.
#[allow(dead_code)]
const ERROR_UNSUPPORTED_CURVE: i8 = 19;

// Helpers

/// Find the cell_dep whose data_hash equals `args` and return its raw bytes.
///
/// `args` is the script's arguments (32 bytes = blake2b256 of the intended
/// VK cell's data); `look_for_dep_with_data_hash` walks `Source::CellDep`
/// and returns the index of the first match — sufficient here, since two
/// cell_deps with the same `data_hash` carry identical bytes.
fn load_bound_vk_bytes(args: &[u8]) -> Result<Vec<u8>, i8> {
    let idx = look_for_dep_with_data_hash(args).map_err(|e| match e {
        SysError::IndexOutOfBound => ERROR_VK_CELL_NOT_FOUND,
        _ => ERROR_VK_LOAD_FAILED,
    })?;
    load_cell_data(idx, Source::CellDep).map_err(|_| ERROR_VK_LOAD_FAILED)
}

/// Load this script's witness from the script-group input slot 0, decoded as
/// `WitnessArgs`. Returns:
///   - `Ok(Some(bytes))` — `input_type` bytes (molecule-encoded `Groth16Witness`),
///   - `Ok(None)` — no script-group input exists (the script is running on the
///     output side at cell creation; there is no proof to verify),
///   - `Err(code)` — load or shape failure to surface as a verifier exit code.
fn load_proof_witness_bytes() -> Result<Option<Vec<u8>>, i8> {
    let wa = match load_witness_args(0, Source::GroupInput) {
        Ok(w) => w,
        Err(SysError::IndexOutOfBound) => return Ok(None),
        Err(_) => return Err(ERROR_WITNESS_LOAD_FAILED),
    };
    let input_type = wa
        .input_type()
        .to_opt()
        .ok_or(ERROR_WITNESS_MISSING_INPUT_TYPE)?;
    Ok(Some(input_type.raw_data().to_vec()))
}

fn vk_decode_err(e: DecodeError) -> i8 {
    match e {
        DecodeError::Molecule => ERROR_VK_MOLECULE_DECODE,
        DecodeError::Version => ERROR_VERSION_MISMATCH,
    }
}

fn witness_decode_err(e: DecodeError) -> i8 {
    match e {
        DecodeError::Molecule => ERROR_WITNESS_MOLECULE_DECODE,
        DecodeError::Version => ERROR_VERSION_MISMATCH,
    }
}

// Entry

pub fn program_entry() -> i8 {
    let script = match load_script() {
        Ok(s) => s,
        Err(_) => return ERROR_SCRIPT_LOAD_FAILED,
    };
    let args = script.args().raw_data();
    if args.len() != ARGS_LEN {
        return ERROR_BAD_ARGS_LENGTH;
    }

    // Probe the script-group input first: an empty group means we are running
    // on the output side at cell creation, where there is no proof to verify.
    // Permit creation freely — verification only runs when the cell is spent.
    // This matches the prevailing CKB type-script pattern (SUDT, xUDT, etc.).
    let witness_molecule = match load_proof_witness_bytes() {
        Ok(Some(b)) => b,
        Ok(None) => return 0,
        Err(code) => return code,
    };

    let vk_molecule = match load_bound_vk_bytes(&args) {
        Ok(b) => b,
        Err(code) => return code,
    };

    let vk_bytes = match decode_vk_to_arkworks(&vk_molecule) {
        Ok(b) => b,
        Err(e) => return vk_decode_err(e),
    };
    let (proof_bytes, pi_bytes) = match decode_witness_to_arkworks(&witness_molecule) {
        Ok(pair) => pair,
        Err(e) => return witness_decode_err(e),
    };

    match verifier_core::verify(&vk_bytes, &proof_bytes, &pi_bytes) {
        Ok(()) => 0,
        Err(VerifyError::InvalidVk) => ERROR_INVALID_VK,
        Err(VerifyError::InvalidProof) => ERROR_INVALID_PROOF,
        Err(VerifyError::InvalidPublicInputs) => ERROR_INVALID_PUBLIC_INPUTS,
        Err(VerifyError::PublicInputCountMismatch) => ERROR_PUBLIC_INPUT_COUNT_MISMATCH,
        Err(VerifyError::VerificationFailed) => ERROR_VERIFICATION_FAILED,
    }
}
