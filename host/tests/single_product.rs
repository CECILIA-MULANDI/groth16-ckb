//! Edge cases for the single-product pairing check in `verifier_core::verify`.
//!
//! The differential suite covers one public input (`SquareCircuit`). These
//! tests cover the paths the rewrite touches directly: the `X` accumulation
//! across many inputs, zero inputs (`X = IC_0`), an identity `X`, input
//! ordering, and the count guard in front of the accumulation.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use host::SumCircuit;

struct Case {
    vk: VerifyingKey<Bn254>,
    proof: Proof<Bn254>,
    pi: Vec<Fr>,
}

fn setup(n: usize, seed: u64) -> Case {
    let mut rng = StdRng::seed_from_u64(seed);
    let pi: Vec<Fr> = (1u64..=n as u64).map(|v| Fr::from(v * 7 + 3)).collect();
    let sum: Fr = pi.iter().copied().sum();
    let circuit = SumCircuit {
        public_inputs: pi.iter().copied().map(Some).collect(),
        sum: Some(sum),
    };
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).expect("setup");
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("prove");
    Case { vk, proof, pi }
}

fn bytes<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    v.serialize_compressed(&mut out).expect("serialize");
    out
}

fn pi_bytes(pi: &[Fr]) -> Vec<u8> {
    let mut out = Vec::new();
    (pi.len() as u32)
        .serialize_compressed(&mut out)
        .expect("count");
    for fe in pi {
        fe.serialize_compressed(&mut out).expect("fr");
    }
    out
}

fn ours(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, pi: &[Fr]) -> bool {
    verifier_core::verify(&bytes(vk), &bytes(proof), &pi_bytes(pi)).is_ok()
}

fn reference(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, pi: &[Fr]) -> bool {
    matches!(Groth16::<Bn254>::verify(vk, pi, proof), Ok(true))
}

#[test]
fn many_inputs_agree_with_arkworks() {
    for n in [2usize, 4, 8, 16] {
        let c = setup(n, 0x5150 + n as u64);
        assert!(ours(&c.vk, &c.proof, &c.pi), "n={n}: valid proof rejected");
        assert!(
            reference(&c.vk, &c.proof, &c.pi),
            "n={n}: arkworks rejected"
        );

        // Each input is bound to its own IC_i: changing any single one must fail.
        for i in 0..n {
            let mut bad = c.pi.clone();
            bad[i] += Fr::from(1u64);
            assert!(
                !ours(&c.vk, &c.proof, &bad),
                "n={n}: tampered input {i} accepted"
            );
            assert!(!reference(&c.vk, &c.proof, &bad));
        }

        // Swapping two inputs keeps the circuit's sum but moves them onto
        // different IC bases, so it must fail too.
        let mut swapped = c.pi.clone();
        swapped.swap(0, n - 1);
        assert!(
            !ours(&c.vk, &c.proof, &swapped),
            "n={n}: swapped inputs accepted"
        );
        assert!(!reference(&c.vk, &c.proof, &swapped));
    }
}

#[test]
fn zero_public_inputs_agree_with_arkworks() {
    // X = IC_0 only; the accumulation loop runs zero times.
    let c = setup(0, 0x2E70);
    assert_eq!(c.vk.gamma_abc_g1.len(), 1);
    assert!(ours(&c.vk, &c.proof, &c.pi), "zero-input proof rejected");
    assert!(reference(&c.vk, &c.proof, &c.pi));
}

#[test]
fn identity_x_fails_cleanly() {
    // Force IC_1 = -IC_0 and input 1, so X = IC_0 + IC_1 = identity.
    // Neither point is itself at infinity, so the VK passes the point checks
    // and the pairing path runs with an identity X. It must return an error,
    // not abort, and agree with arkworks.
    let c = setup(1, 0x1D);
    let mut vk = c.vk.clone();
    vk.gamma_abc_g1[1] = -vk.gamma_abc_g1[0];
    let one = [Fr::from(1u64)];
    let res = verifier_core::verify(&bytes(&vk), &bytes(&c.proof), &pi_bytes(&one));
    assert!(res.is_err(), "identity X accepted");
    assert!(!reference(&vk, &c.proof, &one));
}

#[test]
fn input_count_mismatch_is_rejected() {
    let c = setup(4, 0xC0);
    let short = &c.pi[..3];
    let mut long = c.pi.clone();
    long.push(Fr::from(9u64));
    assert!(verifier_core::verify(&bytes(&c.vk), &bytes(&c.proof), &pi_bytes(short)).is_err());
    assert!(verifier_core::verify(&bytes(&c.vk), &bytes(&c.proof), &pi_bytes(&long)).is_err());
}
