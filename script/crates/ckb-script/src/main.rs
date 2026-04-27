#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!();

use verifier_core::VerifyError;

// Phase 0 spike: hardcode the test vectors via include_bytes!.
// In production the script will load these from witness / cell-data.
// Path is relative to this file: script/crates/ckb-script/src/main.rs → repo root.
const VK_BYTES: &[u8] = include_bytes!("../../../../test_vectors/vk.bin");
const PROOF_BYTES: &[u8] = include_bytes!("../../../../test_vectors/proof.bin");
const PI_BYTES: &[u8] = include_bytes!("../../../../test_vectors/public_inputs.bin");

const ERROR_INVALID_VK: i8 = 1;
const ERROR_INVALID_PROOF: i8 = 2;
const ERROR_INVALID_PUBLIC_INPUTS: i8 = 3;
const ERROR_PUBLIC_INPUT_COUNT_MISMATCH: i8 = 4;
const ERROR_VERIFICATION_FAILED: i8 = 5;

pub fn program_entry() -> i8 {
    match verifier_core::verify(VK_BYTES, PROOF_BYTES, PI_BYTES) {
        Ok(()) => 0,
        Err(VerifyError::InvalidVk) => ERROR_INVALID_VK,
        Err(VerifyError::InvalidProof) => ERROR_INVALID_PROOF,
        Err(VerifyError::InvalidPublicInputs) => ERROR_INVALID_PUBLIC_INPUTS,
        Err(VerifyError::PublicInputCountMismatch) => ERROR_PUBLIC_INPUT_COUNT_MISMATCH,
        Err(VerifyError::VerificationFailed) => ERROR_VERIFICATION_FAILED,
    }
}
