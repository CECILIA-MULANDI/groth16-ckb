//! Property-based tests for `verifier_core::verify`.
//!
//! These complement the hand-crafted adversarial cases in `differential.rs`
//! and the libFuzzer harness in `fuzz/`: they encode invariants the verifier
//! must satisfy and exercise them with randomized inputs that proptest can
//! shrink to a minimal counter-example if anything fails.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use host::SquareCircuit;
use proptest::prelude::*;

struct Sample {
    vk_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    pi_bytes: Vec<u8>,
    public_inputs: Vec<Fr>,
}

fn valid_sample(x_value: u64, rng_seed: u64) -> Sample {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(rng_seed);
    let x = Fr::from(x_value);
    let y = x * x;
    let circuit = SquareCircuit {
        x: Some(x),
        y: Some(y),
    };
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).expect("setup");
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("prove");
    let public_inputs = vec![y];

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).expect("vk serialize");
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("proof serialize");
    let mut pi_bytes = Vec::new();
    (public_inputs.len() as u32)
        .serialize_compressed(&mut pi_bytes)
        .expect("pi count serialize");
    for fe in &public_inputs {
        fe.serialize_compressed(&mut pi_bytes)
            .expect("pi serialize");
    }
    Sample {
        vk_bytes,
        proof_bytes,
        pi_bytes,
        public_inputs,
    }
}

/// Encode a single-Fr public-input buffer with the wire-format `u32 LE count`
/// prefix that `verifier_core::verify` expects.
fn encode_single_pi(fe: Fr) -> Vec<u8> {
    let mut buf = Vec::new();
    1u32.serialize_compressed(&mut buf).expect("count");
    fe.serialize_compressed(&mut buf).expect("fe");
    buf
}

/// Soundness probe: a valid proof must NOT verify against any public-input
/// value other than the one it was generated for. If it does, the proof is
/// not binding to the public inputs and the verifier is broken.
#[test]
fn proof_against_random_public_input_is_rejected() {
    let sample = valid_sample(3, 42);
    let true_y = sample.public_inputs[0];

    proptest!(|(forged_y: u64)| {
        let forged = Fr::from(forged_y);
        prop_assume!(forged != true_y);

        let bad_pi = encode_single_pi(forged);
        let result =
            verifier_core::verify(&sample.vk_bytes, &sample.proof_bytes, &bad_pi);
        prop_assert!(
            result.is_err(),
            "verifier accepted proof against forged public input {forged_y}: {result:?}",
        );
    });
}

/// `verify` is pure: calling it twice on the same bytes returns the same
/// `Result`. Catches accidental introduction of internal state or caching.
#[test]
fn verify_is_deterministic() {
    let sample = valid_sample(7, 0xD37);
    let a = verifier_core::verify(&sample.vk_bytes, &sample.proof_bytes, &sample.pi_bytes);
    let b = verifier_core::verify(&sample.vk_bytes, &sample.proof_bytes, &sample.pi_bytes);
    assert_eq!(a, b);
    assert!(a.is_ok(), "baseline sample failed to verify: {a:?}");
}
