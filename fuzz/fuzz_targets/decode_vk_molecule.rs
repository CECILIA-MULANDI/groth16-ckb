#![no_main]

//! Fuzz target for `wire_decode::decode_vk_to_arkworks`.
//!
//! Feeds arbitrary bytes as a candidate `Groth16VerifyingKey` Molecule blob.
//! Catches panics in the Molecule offset/length arithmetic, version check,
//! or the union-variant dispatch. Same `&[u8]` shape as the underlying
//! function so the test_vectors/vk.mol.bin file can drop in as a seed.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = wire_decode::decode_vk_to_arkworks(data);
});
