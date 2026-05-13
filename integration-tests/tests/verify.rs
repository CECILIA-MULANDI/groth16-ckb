//! Happy-path integration test for the on-chain Groth16 verifier.
//!
//! Builds a mock transaction that mirrors the production call shape:
//! VK lives in a `cell_dep` whose `data_hash` equals the type-script's
//! `args`; the proof + public inputs are passed through `WitnessArgs.input_type`.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_hash::blake2b_256;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionBuilder,
    packed::{CellDep, CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
use host::{encode_vk_molecule, encode_witness_molecule, SquareCircuit};

const MAX_CYCLES: u64 = 250_000_000;

fn script_binary() -> Bytes {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("script")
        .join("target")
        .join("riscv64imac-unknown-none-elf")
        .join("release")
        .join("ckb-script");
    let bytes = std::fs::read(&path).unwrap_or_else(|_| {
        panic!(
            "ckb-script binary not found at {}; run scripts/build-ckb-script.sh first",
            path.display()
        )
    });
    bytes.into()
}

/// Setup, prove, and Molecule-encode a sample (vk, witness) pair for the
/// `x*x = y` circuit. Returns (vk_molecule_bytes, witness_molecule_bytes).
fn sample_vk_and_witness() -> (Vec<u8>, Vec<u8>) {
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
    (
        encode_vk_molecule(&vk),
        encode_witness_molecule(&proof, &[y]),
    )
}

#[test]
fn valid_proof_verifies() {
    let mut context = Context::default();
    let (vk_molecule, witness_molecule) = sample_vk_and_witness();

    let script_op = context.deploy_cell(script_binary());
    let always_success_op = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let vk_op = context.deploy_cell(Bytes::from(vk_molecule.clone()));

    let vk_data_hash = blake2b_256(&vk_molecule);
    let type_script = context
        .build_script(&script_op, Bytes::from(vk_data_hash.to_vec()))
        .expect("verifier type script");
    let lock_script = context
        .build_script(&always_success_op, Bytes::new())
        .expect("always-success lock");

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64)
            .lock(lock_script.clone())
            .type_(Some(type_script).pack())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(500u64)
        .lock(lock_script)
        .build();

    let witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(witness_molecule)).pack())
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .cell_dep(CellDep::new_builder().out_point(script_op).build())
        .cell_dep(CellDep::new_builder().out_point(always_success_op).build())
        .cell_dep(CellDep::new_builder().out_point(vk_op).build())
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("groth16 verification accepts the valid proof");
    eprintln!("verified at {} cycles", cycles);
}
