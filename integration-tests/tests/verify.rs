//! End-to-end tests for the on-chain Groth16 verifier. Each test builds a
//! mock transaction whose shape mirrors the production call: VK in a
//! `cell_dep` (matched by `data_hash == args`), proof + public inputs in
//! `WitnessArgs.input_type`.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_error::Error as CkbError;
use ckb_testtool::ckb_hash::blake2b_256;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{Cycle, TransactionBuilder},
    packed::{CellDep, CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
use host::{encode_vk_molecule, encode_witness_molecule, SquareCircuit};

const MAX_CYCLES: u64 = 250_000_000;

// Exit codes — mirror script/crates/ckb-script/src/main.rs.
// ERROR_INVALID_PROOF (2) and ERROR_INVALID_VK (1) are exercised by
// verifier-core's lower-cost unit tests against raw arkworks buffers.
const ERROR_PUBLIC_INPUT_COUNT_MISMATCH: i8 = 4;
const ERROR_VERIFICATION_FAILED: i8 = 5;
const ERROR_VK_CELL_NOT_FOUND: i8 = 12;
const ERROR_WITNESS_MOLECULE_DECODE: i8 = 17;
const ERROR_VERSION_MISMATCH: i8 = 18;

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

struct Fixture {
    vk: ark_groth16::VerifyingKey<Bn254>,
    proof: ark_groth16::Proof<Bn254>,
    public_inputs: Vec<Fr>,
}

/// Deterministic Groth16 setup + prove for `x*x = y` with x=7, y=49.
fn sample_fixture(seed: u64) -> Fixture {
    let mut rng = StdRng::seed_from_u64(seed);
    let x = Fr::from(7u64);
    let y = x * x;
    let circuit = SquareCircuit {
        x: Some(x),
        y: Some(y),
    };
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).expect("setup");
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("prove");
    Fixture {
        vk,
        proof,
        public_inputs: vec![y],
    }
}

/// Build and verify a transaction with the given inputs. If `vk_for_cell_dep`
/// is None, the VK cell is omitted entirely (used to exercise the
/// `look_for_dep_with_data_hash` miss path).
fn run_tx(
    args: [u8; 32],
    vk_for_cell_dep: Option<Vec<u8>>,
    witness_molecule: Vec<u8>,
) -> Result<Cycle, CkbError> {
    let mut context = Context::default();

    let script_op = context.deploy_cell(script_binary());
    let always_success_op = context.deploy_cell(ALWAYS_SUCCESS.clone());

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

    let mut builder = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .cell_dep(CellDep::new_builder().out_point(script_op).build())
        .cell_dep(CellDep::new_builder().out_point(always_success_op).build())
        .witness(witness.as_bytes().pack());

    if let Some(vk_bytes) = vk_for_cell_dep {
        let vk_op = context.deploy_cell(Bytes::from(vk_bytes));
        builder = builder.cell_dep(CellDep::new_builder().out_point(vk_op).build());
    }

    let tx = context.complete_tx(builder.build());
    context.verify_tx(&tx, MAX_CYCLES)
}

/// Assert that the verifier exited with `expected` after a script failure.
/// ckb-testtool surfaces the exit code in the error's Display impl as
/// `... code <N>`; we match on that substring.
fn assert_exit_code(err: &CkbError, expected: i8) {
    let s = err.to_string();
    let needle = format!("code {expected}");
    assert!(
        s.contains(&needle),
        "expected `{needle}` in error, got: {s}"
    );
}

#[test]
fn valid_proof_verifies() {
    let f = sample_fixture(0xC0FFEE);
    let vk_molecule = encode_vk_molecule(&f.vk);
    let witness_molecule = encode_witness_molecule(&f.proof, &f.public_inputs);
    let args = blake2b_256(&vk_molecule);

    let cycles = run_tx(args, Some(vk_molecule), witness_molecule)
        .expect("groth16 verification accepts the valid proof");
    eprintln!("verified at {} cycles", cycles);
}

#[test]
fn forged_proof_rejected() {
    // Proof is valid for y=49 but witness encodes y=48 — pairing check fails.
    let f = sample_fixture(0xC0FFEE);
    let vk_molecule = encode_vk_molecule(&f.vk);
    let wrong_pi = vec![Fr::from(48u64)];
    let witness_molecule = encode_witness_molecule(&f.proof, &wrong_pi);
    let args = blake2b_256(&vk_molecule);

    let err = run_tx(args, Some(vk_molecule), witness_molecule).unwrap_err();
    assert_exit_code(&err, ERROR_VERIFICATION_FAILED);
}

#[test]
fn truncated_witness_rejected() {
    let f = sample_fixture(0xC0FFEE);
    let vk_molecule = encode_vk_molecule(&f.vk);
    let mut witness_molecule = encode_witness_molecule(&f.proof, &f.public_inputs);
    witness_molecule.truncate(witness_molecule.len() / 2);
    let args = blake2b_256(&vk_molecule);

    let err = run_tx(args, Some(vk_molecule), witness_molecule).unwrap_err();
    assert_exit_code(&err, ERROR_WITNESS_MOLECULE_DECODE);
}

#[test]
fn public_input_count_mismatch_rejected() {
    // VK has ic_len = 2 (1 public input + constant), witness ships 0 inputs.
    let f = sample_fixture(0xC0FFEE);
    let vk_molecule = encode_vk_molecule(&f.vk);
    let witness_molecule = encode_witness_molecule(&f.proof, &[]);
    let args = blake2b_256(&vk_molecule);

    let err = run_tx(args, Some(vk_molecule), witness_molecule).unwrap_err();
    assert_exit_code(&err, ERROR_PUBLIC_INPUT_COUNT_MISMATCH);
}

#[test]
fn missing_vk_cell_dep_rejected() {
    // args points to a hash that no cell_dep matches.
    let f = sample_fixture(0xC0FFEE);
    let witness_molecule = encode_witness_molecule(&f.proof, &f.public_inputs);
    let args = [0xAAu8; 32];

    let err = run_tx(args, None, witness_molecule).unwrap_err();
    assert_exit_code(&err, ERROR_VK_CELL_NOT_FOUND);
}

#[test]
fn wrong_vk_for_proof_rejected() {
    // Two independent setups produce VK_A and VK_B. We commit to VK_A
    // (args = hash(VK_A), VK_A in cell_dep) but supply a proof made for VK_B.
    // The verifier successfully loads VK_A; the pairing then rejects.
    let a = sample_fixture(0xAAAAAAAA);
    let b = sample_fixture(0xBBBBBBBB);
    let vk_a_molecule = encode_vk_molecule(&a.vk);
    let witness_b = encode_witness_molecule(&b.proof, &b.public_inputs);
    let args = blake2b_256(&vk_a_molecule);

    let err = run_tx(args, Some(vk_a_molecule), witness_b).unwrap_err();
    assert_exit_code(&err, ERROR_VERIFICATION_FAILED);
}

#[test]
fn bad_witness_version_rejected() {
    // Groth16Witness is a Molecule table with two fields (version, content).
    // The table header is `[total_size: u32][offset_version: u32][offset_content: u32]`,
    // putting the Uint16 version field at bytes [12..14]. The Reader's
    // structural checks do not inspect the version *value*, so flipping
    // these bytes yields a parseable witness with version != 1, which the
    // script's explicit version gate must reject.
    let f = sample_fixture(0xC0FFEE);
    let vk_molecule = encode_vk_molecule(&f.vk);
    let mut witness_molecule = encode_witness_molecule(&f.proof, &f.public_inputs);
    assert_eq!(
        &witness_molecule[12..14],
        &[1, 0],
        "version offset assumption broken; check Groth16Witness schema"
    );
    witness_molecule[12] = 0xFF;
    witness_molecule[13] = 0xFF;
    let args = blake2b_256(&vk_molecule);

    let err = run_tx(args, Some(vk_molecule), witness_molecule).unwrap_err();
    assert_exit_code(&err, ERROR_VERSION_MISMATCH);
}

