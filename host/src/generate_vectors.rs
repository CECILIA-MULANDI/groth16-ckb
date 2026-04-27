/**
 *  Produces a Groth16 proof, it should serialize it in a stable format
 * Generates a real Groth16 test vector for the Phase 0 spike:
 * circuit: x * x = y   (x private witness, y public input)
 *  curve:   BN254
 * format:  arkworks compressed serialization
 * Output: ../test_vectors/{vk,proof,public_inputs}.bin
 *  
 */
use std::fs;
use std::path::PathBuf;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;

#[derive(Clone)]
struct SquareCircuit<F: PrimeField> {
    x: Option<F>,
    y: Option<F>,
}
impl<F: PrimeField> ConstraintSynthesizer<F> for SquareCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;

        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + y)?;
        Ok(())
    }
}
fn main() {
    // Deterministic RNG so vectors are reproducible across runs.
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0x6770_7468_3136);
    let x = Fr::from(7u64);
    let y = x * x;
    let circuit = SquareCircuit {
        x: Some(x),
        y: Some(y),
    };

    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).expect("setup");
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("prove");
    let public_inputs = vec![y];
    assert!(
        Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).expect("verify"),
        "host verify failed — generated vector is invalid"
    );
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .expect("vk serialize");
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("proof serialize");

    // public_inputs format: u32 length prefix, then each Fr compressed.
    // Length prefix lets the verifier validate count vs vk.gamma_abc_g1.len()-1.
    let mut pi_bytes = Vec::new();
    (public_inputs.len() as u32)
        .serialize_compressed(&mut pi_bytes)
        .expect("pi count serialize");
    for fe in &public_inputs {
        fe.serialize_compressed(&mut pi_bytes)
            .expect("pi serialize");
    }

    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .join("test_vectors");
    fs::create_dir_all(&out_dir).expect("mkdir");

    fs::write(out_dir.join("vk.bin"), &vk_bytes).expect("write vk");
    fs::write(out_dir.join("proof.bin"), &proof_bytes).expect("write proof");
    fs::write(out_dir.join("public_inputs.bin"), &pi_bytes).expect("write pi");

    println!(
        "wrote test_vectors:\n  vk.bin            {} bytes\n  proof.bin         {} bytes\n  public_inputs.bin {} bytes",
        vk_bytes.len(),
        proof_bytes.len(),
        pi_bytes.len()
    );
}
