//! Differential test: assert verifier-core::verify agrees with
//! ark_groth16::Groth16::verify on freshly-generated proofs.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;

use ark_groth16::{Proof, VerifyingKey};
use host::SquareCircuit;
struct Sample {
    vk: VerifyingKey<Bn254>,
    proof: Proof<Bn254>,
    public_inputs: Vec<Fr>,
    vk_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    pi_bytes: Vec<u8>,
}
fn sample(x_value: u64, rng_seed: u64) -> Sample {
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
    vk.serialize_compressed(&mut vk_bytes).expect("serialize");
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
        vk,
        proof,
        public_inputs,
        vk_bytes,
        proof_bytes,
        pi_bytes,
    }
}
fn with_flipped_bit(bytes: &[u8], byte_idx: usize, bit_idx: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[byte_idx] ^= 1 << bit_idx;
    out
}
#[test]
fn differential_x_squared_100_samples() {
    for i in 0..100u64 {
        // any non-zero u64 works
        let x_value = i + 1;
        // distinct seed per iteration
        let rng_seed = 0xC0FFEE ^ i;

        let s = sample(x_value, rng_seed);

        // Path A - our verifier, bytes in.
        let ours = verifier_core::verify(&s.vk_bytes, &s.proof_bytes, &s.pi_bytes);
        assert!(
            ours.is_ok(),
            "iter {i}: verifier-core rejected a valid proof: {:?}",
            ours.err()
        );

        // Path B-the arkworks reference verifier, objects in.
        let theirs = Groth16::<Bn254>::verify(&s.vk, &s.public_inputs, &s.proof);
        assert!(
            matches!(theirs, Ok(true)),
            "iter {i}: ark_groth16::verify rejected a valid proof: {:?}",
            theirs
        );
    }
}

#[test]
fn differential_proof_bit_flip_always_rejects() {
    let s = sample(7, 0xC0FFEE);

    for byte_idx in 0..s.proof_bytes.len() {
        for bit_idx in 0..8u8 {
            let mutated = with_flipped_bit(&s.proof_bytes, byte_idx, bit_idx);
            let result = verifier_core::verify(&s.vk_bytes, &mutated, &s.pi_bytes);
            assert!(
                result.is_err(),
                "bit flip at proof byte {byte_idx} bit {bit_idx} was ACCEPTED — soundness bug",
            );
        }
    }
}

#[test]
fn differential_vk_bit_flip_always_rejects() {
    let s = sample(7, 0xC0FFEE);

    for byte_idx in 0..s.vk_bytes.len() {
        for bit_idx in 0..8u8 {
            let mutated = with_flipped_bit(&s.vk_bytes, byte_idx, bit_idx);
            let result = verifier_core::verify(&mutated, &s.proof_bytes, &s.pi_bytes);
            assert!(
                result.is_err(),
                "bit flip at vk byte {byte_idx} bit {bit_idx} was ACCEPTED — soundness bug",
            );
        }
    }
}

#[test]
fn differential_public_inputs_bit_flip_always_rejects() {
    let s = sample(7, 0xC0FFEE);

    for byte_idx in 0..s.pi_bytes.len() {
        for bit_idx in 0..8u8 {
            let mutated = with_flipped_bit(&s.pi_bytes, byte_idx, bit_idx);
            let result = verifier_core::verify(&s.vk_bytes, &s.proof_bytes, &mutated);
            assert!(
                result.is_err(),
                "bit flip at pi byte {byte_idx} bit {bit_idx} was ACCEPTED — soundness bug",
            );
        }
    }
}
