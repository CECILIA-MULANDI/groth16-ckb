//! Host-side helpers for groth16-ckb: sample circuits, test-vector tooling,
//! and Molecule encoders that turn arkworks types into the on-chain wire
//! format consumed by `ckb-script`.

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use groth16_schema::{
    Bn254Witness, Byte32, FrVec, G1Compressed, G1Vec, G2Compressed, Groth16VerifyingKey,
    Groth16Witness, ProofBn254, Uint16, VerifyingKeyBn254, VerifyingKeyContent, WitnessContent,
};
use molecule::prelude::{Builder, Entity};

const WIRE_VERSION: u16 = 1;

// I know x s.t x^2 = y
#[derive(Clone)]
pub struct SquareCircuit<F: PrimeField> {
    // Private witness
    pub x: Option<F>,
    // public input
    pub y: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SquareCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + y)?;
        Ok(())
    }
}

fn ark_to_bytes<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::with_capacity(value.compressed_size());
    value
        .serialize_compressed(&mut buf)
        .expect("serialize never fails for in-memory writer");
    buf
}

/// Encode an arkworks `VerifyingKey<Bn254>` into the Molecule wire format
/// defined by `schemas/groth16.mol`.
pub fn encode_vk_molecule(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<u8> {
    let alpha =
        G1Compressed::from_slice(&ark_to_bytes(&vk.alpha_g1)).expect("alpha_g1 -> 32 bytes");
    let beta = G2Compressed::from_slice(&ark_to_bytes(&vk.beta_g2)).expect("beta_g2 -> 64 bytes");
    let gamma =
        G2Compressed::from_slice(&ark_to_bytes(&vk.gamma_g2)).expect("gamma_g2 -> 64 bytes");
    let delta =
        G2Compressed::from_slice(&ark_to_bytes(&vk.delta_g2)).expect("delta_g2 -> 64 bytes");

    let mut ic_builder = G1Vec::new_builder();
    for point in &vk.gamma_abc_g1 {
        let wrapped =
            G1Compressed::from_slice(&ark_to_bytes(point)).expect("gamma_abc_g1 entry -> 32 bytes");
        ic_builder = ic_builder.push(wrapped);
    }
    let ic_vec = ic_builder.build();

    let bn254 = VerifyingKeyBn254::new_builder()
        .alpha_g1(alpha)
        .beta_g2(beta)
        .gamma_g2(gamma)
        .delta_g2(delta)
        .gamma_abc_g1(ic_vec)
        .build();

    let version =
        Uint16::from_slice(&WIRE_VERSION.to_le_bytes()).expect("WIRE_VERSION fits in 2 bytes");

    Groth16VerifyingKey::new_builder()
        .version(version)
        .content(VerifyingKeyContent::from(bn254))
        .build()
        .as_slice()
        .to_vec()
}

/// Encode an arkworks `Proof<Bn254>` plus its public inputs into the Molecule
/// `Groth16Witness` wire format. Public inputs are serialized as `Fr` field
/// elements in their canonical 32-byte form.
pub fn encode_witness_molecule(
    proof: &ark_groth16::Proof<Bn254>,
    public_inputs: &[Fr],
) -> Vec<u8> {
    let a = G1Compressed::from_slice(&ark_to_bytes(&proof.a)).expect("proof.a -> 32 bytes");
    let b = G2Compressed::from_slice(&ark_to_bytes(&proof.b)).expect("proof.b -> 64 bytes");
    let c = G1Compressed::from_slice(&ark_to_bytes(&proof.c)).expect("proof.c -> 32 bytes");

    let proof_mol = ProofBn254::new_builder().a(a).b(b).c(c).build();

    let mut pi_builder = FrVec::new_builder();
    for fe in public_inputs {
        let wrapped =
            Byte32::from_slice(&ark_to_bytes(fe)).expect("Fr serializes to 32 canonical bytes");
        pi_builder = pi_builder.push(wrapped);
    }
    let pi_vec = pi_builder.build();

    let bn254 = Bn254Witness::new_builder()
        .proof(proof_mol)
        .public_inputs(pi_vec)
        .build();

    let version =
        Uint16::from_slice(&WIRE_VERSION.to_le_bytes()).expect("WIRE_VERSION fits in 2 bytes");

    Groth16Witness::new_builder()
        .version(version)
        .content(WitnessContent::from(bn254))
        .build()
        .as_slice()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::rand::SeedableRng;
    use groth16_schema::{
        Groth16VerifyingKeyReader, Groth16WitnessReader, VerifyingKeyContentUnionReader,
        WitnessContentUnionReader,
    };
    use molecule::prelude::Reader;

    fn sample_vk_proof_pi() -> (
        ark_groth16::VerifyingKey<Bn254>,
        ark_groth16::Proof<Bn254>,
        Vec<Fr>,
    ) {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
        let x = Fr::from(7u64);
        let y = x * x;
        let circuit = SquareCircuit {
            x: Some(x),
            y: Some(y),
        };
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).expect("setup");
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("prove");
        (vk, proof, vec![y])
    }

    #[test]
    fn encoded_vk_decodes_to_expected_shape() {
        let (vk, _, _) = sample_vk_proof_pi();
        let bytes = encode_vk_molecule(&vk);
        let r = Groth16VerifyingKeyReader::from_slice(&bytes).expect("valid molecule");

        let version_bytes: [u8; 2] = r.version().as_slice().try_into().unwrap();
        assert_eq!(u16::from_le_bytes(version_bytes), WIRE_VERSION);

        let bn254 = match r.content().to_enum() {
            VerifyingKeyContentUnionReader::VerifyingKeyBn254(v) => v,
        };
        assert_eq!(bn254.alpha_g1().as_slice().len(), 32);
        assert_eq!(bn254.beta_g2().as_slice().len(), 64);
        assert_eq!(bn254.gamma_g2().as_slice().len(), 64);
        assert_eq!(bn254.delta_g2().as_slice().len(), 64);
        // x*x=y has 1 public input, so IC has num_public+1 = 2 entries.
        assert_eq!(bn254.gamma_abc_g1().item_count(), vk.gamma_abc_g1.len());
    }

    #[test]
    fn encoded_witness_decodes_to_expected_shape() {
        let (_, proof, pi) = sample_vk_proof_pi();
        let bytes = encode_witness_molecule(&proof, &pi);
        let r = Groth16WitnessReader::from_slice(&bytes).expect("valid molecule");

        let version_bytes: [u8; 2] = r.version().as_slice().try_into().unwrap();
        assert_eq!(u16::from_le_bytes(version_bytes), WIRE_VERSION);

        let bn254 = match r.content().to_enum() {
            WitnessContentUnionReader::Bn254Witness(v) => v,
        };
        assert_eq!(bn254.proof().a().as_slice().len(), 32);
        assert_eq!(bn254.proof().b().as_slice().len(), 64);
        assert_eq!(bn254.proof().c().as_slice().len(), 32);
        assert_eq!(bn254.public_inputs().item_count(), pi.len());
    }
}
