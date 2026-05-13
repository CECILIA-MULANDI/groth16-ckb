//! Cycle benchmark across public-input counts.
//!
//! Marked `#[ignore]` so `cargo test` stays fast. Run explicitly:
//!     cargo test -p integration-tests --test cycles -- --ignored --nocapture

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_hash::blake2b_256;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionBuilder,
    packed::{CellDep, CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
use host::{encode_vk_molecule, encode_witness_molecule, SumCircuit};

const MAX_CYCLES: u64 = 250_000_000;
const INPUT_COUNTS: &[usize] = &[1, 4, 8, 16, 32, 64];

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

/// Setup, prove, and on-chain-verify a `SumCircuit` with `n` public inputs.
/// Returns the cycle count reported by ckb-testtool.
fn measure_cycles(n: usize) -> u64 {
    let mut rng = StdRng::seed_from_u64(0xBEEFu64.wrapping_add(n as u64));
    let pi: Vec<Fr> = (1u64..=n as u64).map(Fr::from).collect();
    let sum: Fr = pi.iter().copied().sum();
    let circuit = SumCircuit {
        public_inputs: pi.iter().copied().map(Some).collect(),
        sum: Some(sum),
    };
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).expect("setup");
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    let vk_molecule = encode_vk_molecule(&vk);
    let witness_molecule = encode_witness_molecule(&proof, &pi);
    let args = blake2b_256(&vk_molecule);

    let mut context = Context::default();
    let script_op = context.deploy_cell(script_binary());
    let always_success_op = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let vk_op = context.deploy_cell(Bytes::from(vk_molecule));

    let type_script = context
        .build_script(&script_op, Bytes::from(args.to_vec()))
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

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("benchmark proof must verify")
}

#[test]
#[ignore = "benchmark — run with `cargo test --ignored cycle_benchmark -- --nocapture`"]
fn cycle_benchmark() {
    let results: Vec<(usize, u64)> = INPUT_COUNTS
        .iter()
        .map(|&n| (n, measure_cycles(n)))
        .collect();

    eprintln!();
    eprintln!("| num_public_inputs | cycles      |");
    eprintln!("|------------------:|------------:|");
    for (n, c) in &results {
        eprintln!("| {n:>17} | {c:>11} |");
    }
}
