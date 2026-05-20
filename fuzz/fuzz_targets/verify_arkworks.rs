#![no_main]

//! Fuzz target for `verifier_core::verify` at the arkworks-bytes layer.
//!
//! Input framing:
//!   bytes 0..2  : LE u16 `vk_len`,    clamped via `%` to fit the body
//!   bytes 2..4  : LE u16 `proof_len`, clamped to remaining body
//!   bytes 4..   : body, partitioned as `vk || proof || public_inputs`
//!
//! Explicit framing (instead of `arbitrary` derive) lets a seed corpus encode
//! a known-valid split while still letting the fuzzer mutate the lengths.
//! `verifier_core::verify` promises `Result<(), VerifyError>` for any input;
//! the harness simply asks libFuzzer to find a panic, OOM, or hang.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let body = &data[4..];
    let vk_len = (u16::from_le_bytes([data[0], data[1]]) as usize) % (body.len() + 1);
    let remaining = body.len() - vk_len;
    let proof_len = (u16::from_le_bytes([data[2], data[3]]) as usize) % (remaining + 1);
    let vk = &body[..vk_len];
    let proof = &body[vk_len..vk_len + proof_len];
    let public_inputs = &body[vk_len + proof_len..];
    let _ = verifier_core::verify(vk, proof, public_inputs);
});
