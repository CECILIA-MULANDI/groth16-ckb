#![no_main]

//! Fuzz target for `wire_decode::decode_witness_to_arkworks`.
//!
//! Feeds arbitrary bytes as a candidate `Groth16Witness` Molecule blob.
//! Catches panics in Molecule decode, version check, or the union dispatch.
//! Same `&[u8]` shape as the underlying function so test_vectors/witness.mol.bin
//! can drop in as a seed.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = wire_decode::decode_witness_to_arkworks(data);
});
