#![no_main]

//! Fuzz target for `verifier_core::verify` at the arkworks-bytes layer.
//!
//! Feeds three independent byte slices as (vk, proof, public_inputs). The
//! verifier promises `Result<(), VerifyError>` for any input; this harness
//! asserts that holds by simply asking the fuzzer to find a panic, OOM, or
//! hang. Catches regressions in arkworks deserialization and in the length
//! pre-checks that guard against `Vec::deserialize_compressed` allocating
//! from an attacker-controlled length prefix.

use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input<'a> {
    vk: &'a [u8],
    proof: &'a [u8],
    public_inputs: &'a [u8],
}

fuzz_target!(|input: Input| {
    let _ = verifier_core::verify(input.vk, input.proof, input.public_inputs);
});
