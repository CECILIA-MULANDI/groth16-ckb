//! Host-side helpers for groth16-ckb: sample circuits, test-vector tooling.

use ark_ff::PrimeField;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
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
