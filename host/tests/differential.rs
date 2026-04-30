//! Differential test: assert verifier-core::verify agrees with
//! ark_groth16::Groth16::verify on freshly-generated proofs.

use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
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
fn run_differential_loop(n: u64) {
    for i in 0..n {
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
fn differential_x_squared_100_samples() {
    run_differential_loop(100);
}

#[test]
#[ignore = "thorough variant — run via `cargo test -- --ignored`"]
fn differential_x_squared_1000_samples() {
    run_differential_loop(1000);
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

#[test]
fn proof_with_infinity_a_is_rejected() {
    let s = sample(7, 0xC0FFEE);

    let forged = Proof::<Bn254> {
        a: ark_bn254::G1Affine::zero(),
        b: s.proof.b,
        c: s.proof.c,
    };

    let mut forged_bytes = Vec::new();
    forged
        .serialize_compressed(&mut forged_bytes)
        .expect("serialize forged proof");

    let result = verifier_core::verify(&s.vk_bytes, &forged_bytes, &s.pi_bytes);
    assert!(
        result.is_err(),
        "verifier accepted a proof with A = identity (point at infinity) — soundness bug",
    );
    eprintln!("infinity-A rejected as: {:?}", result.unwrap_err());
}

fn probe_forged_vk<F>(label: &str, mutate: F)
where
    F: FnOnce(&mut VerifyingKey<Bn254>),
{
    let s = sample(7, 0xC0FFEE);
    let mut forged_vk = s.vk.clone();
    mutate(&mut forged_vk);

    let mut forged_vk_bytes = Vec::new();
    forged_vk
        .serialize_compressed(&mut forged_vk_bytes)
        .expect("serialize forged vk");

    let result = verifier_core::verify(&forged_vk_bytes, &s.proof_bytes, &s.pi_bytes);
    assert!(
        result.is_err(),
        "vk with {label} = identity was ACCEPTED — soundness bug",
    );
    eprintln!("vk.{label} forgery rejected as: {:?}", result.unwrap_err());
}

#[test]
fn vk_with_infinity_alpha_g1_is_rejected() {
    probe_forged_vk("alpha_g1", |vk| vk.alpha_g1 = ark_bn254::G1Affine::zero());
}

#[test]
fn vk_with_infinity_beta_g2_is_rejected() {
    probe_forged_vk("beta_g2", |vk| vk.beta_g2 = ark_bn254::G2Affine::zero());
}

#[test]
fn vk_with_infinity_gamma_g2_is_rejected() {
    probe_forged_vk("gamma_g2", |vk| vk.gamma_g2 = ark_bn254::G2Affine::zero());
}

#[test]
fn vk_with_infinity_delta_g2_is_rejected() {
    probe_forged_vk("delta_g2", |vk| vk.delta_g2 = ark_bn254::G2Affine::zero());
}

#[test]
fn vk_with_infinity_in_gamma_abc_g1_is_rejected() {
    probe_forged_vk("gamma_abc_g1[1]", |vk| {
        vk.gamma_abc_g1[1] = ark_bn254::G1Affine::zero();
    });
}

#[test]
fn non_canonical_fr_in_public_inputs_is_rejected() {
    use ark_ff::{BigInteger, PrimeField};

    let s = sample(7, 0xC0FFEE);

    // The Fr modulus encoded as bytes is value-equivalent to 0 but is NOT the
    // canonical 0 encoding. A canonical-encoding-enforcing deserializer must
    // reject this with `value < modulus` failing.
    let modulus_bytes = Fr::MODULUS.to_bytes_le();
    assert_eq!(modulus_bytes.len(), 32, "Fr modulus must fit in 32 bytes");

    let mut bad_pi_bytes = Vec::new();
    bad_pi_bytes.extend_from_slice(&1u32.to_le_bytes());
    bad_pi_bytes.extend_from_slice(&modulus_bytes);

    let result = verifier_core::verify(&s.vk_bytes, &s.proof_bytes, &bad_pi_bytes);
    assert!(
        result.is_err(),
        "verifier accepted non-canonical Fr (modulus as bytes) — soundness bug",
    );
    eprintln!("non-canonical Fr rejected as: {:?}", result.unwrap_err());
}

#[test]
fn non_canonical_fq_in_proof_is_rejected() {
    use ark_bn254::Fq;
    use ark_ff::{BigInteger, PrimeField};

    let s = sample(7, 0xC0FFEE);

    // proof_bytes layout: 32 B proof.a (G1) ‖ 64 B proof.b (G2) ‖ 32 B proof.c (G1).
    // For G1Affine compressed, the high 2 bits of byte 31 are infinity/y-sign flags;
    // the rest is the Fq x-coordinate. Fq modulus q is 254-bit, so its top 2 bits
    // are 0 — encoding q directly leaves both flags clear, asking the deserializer
    // to interpret the x-coordinate as exactly q. Canonical enforcement requires
    // x < q, so this must reject.
    let q_bytes = Fq::MODULUS.to_bytes_le();
    assert_eq!(q_bytes.len(), 32, "Fq modulus must fit in 32 bytes");

    let mut bad_proof_bytes = s.proof_bytes.clone();
    bad_proof_bytes[..32].copy_from_slice(&q_bytes);

    let result = verifier_core::verify(&s.vk_bytes, &bad_proof_bytes, &s.pi_bytes);
    assert!(
        result.is_err(),
        "verifier accepted non-canonical Fq in proof.a (modulus as x) — soundness bug",
    );
    eprintln!("non-canonical Fq rejected as: {:?}", result.unwrap_err());
}

// G1 has cofactor 1 on BN254, so every on-curve G1 point is in the prime-order
// subgroup — there is no off-subgroup G1 to construct. G2 has a non-trivial
// cofactor; the tests below exercise the load-bearing case.
fn off_subgroup_g2(seed: u64) -> ark_bn254::G2Affine {
    use ark_bn254::{Fq2, G2Affine};
    use ark_ff::UniformRand;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
    for _ in 0..1000 {
        let x = Fq2::rand(&mut rng);
        for greatest in [false, true] {
            if let Some(p) = G2Affine::get_point_from_x_unchecked(x, greatest) {
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    debug_assert!(p.is_on_curve());
                    return p;
                }
            }
        }
    }
    panic!("could not find off-subgroup G2 point in 1000 tries");
}

#[test]
fn proof_with_off_subgroup_b_is_rejected() {
    let s = sample(7, 0xC0FFEE);
    let bad_b = off_subgroup_g2(0xBAD_BAD);

    let forged = Proof::<Bn254> {
        a: s.proof.a,
        b: bad_b,
        c: s.proof.c,
    };

    let mut forged_bytes = Vec::new();
    forged
        .serialize_compressed(&mut forged_bytes)
        .expect("serialize forged proof");

    let result = verifier_core::verify(&s.vk_bytes, &forged_bytes, &s.pi_bytes);
    assert!(
        result.is_err(),
        "verifier accepted a proof with off-subgroup B — soundness bug",
    );
    eprintln!("off-subgroup B rejected as: {:?}", result.unwrap_err());
}

#[test]
fn vk_with_off_subgroup_beta_g2_is_rejected() {
    probe_forged_vk("beta_g2", |vk| vk.beta_g2 = off_subgroup_g2(0xBAD_BE7A));
}

#[test]
fn vk_with_off_subgroup_gamma_g2_is_rejected() {
    probe_forged_vk("gamma_g2", |vk| vk.gamma_g2 = off_subgroup_g2(0xBAD_6A33A));
}

#[test]
fn vk_with_off_subgroup_delta_g2_is_rejected() {
    probe_forged_vk("delta_g2", |vk| vk.delta_g2 = off_subgroup_g2(0xBAD_DE17A));
}

// Public-input count mismatch: pi-side count must equal vk.gamma_abc_g1.len() - 1.
// Sample circuit has 1 public input (so ic_len = 2). count=0 and count=2 must both
// be caught by the explicit cross-check, not silently wrapped into a pairing.
#[test]
fn public_inputs_too_few_is_rejected() {
    let s = sample(7, 0xC0FFEE);
    let bad_pi_bytes = 0u32.to_le_bytes().to_vec();
    let result = verifier_core::verify(&s.vk_bytes, &s.proof_bytes, &bad_pi_bytes);
    assert_eq!(
        result,
        Err(verifier_core::VerifyError::PublicInputCountMismatch),
    );
}

#[test]
fn public_inputs_too_many_is_rejected() {
    let s = sample(7, 0xC0FFEE);
    let mut bad_pi_bytes = Vec::new();
    bad_pi_bytes.extend_from_slice(&2u32.to_le_bytes());
    for fe in [Fr::from(1u64), Fr::from(2u64)] {
        fe.serialize_compressed(&mut bad_pi_bytes).expect("fr");
    }
    let result = verifier_core::verify(&s.vk_bytes, &s.proof_bytes, &bad_pi_bytes);
    assert_eq!(
        result,
        Err(verifier_core::VerifyError::PublicInputCountMismatch),
    );
}

#[test]
fn proof_with_infinity_b_is_rejected() {
    let s = sample(7, 0xC0FFEE);
    let forged = Proof::<Bn254> {
        a: s.proof.a,
        b: ark_bn254::G2Affine::zero(),
        c: s.proof.c,
    };
    let mut forged_bytes = Vec::new();
    forged
        .serialize_compressed(&mut forged_bytes)
        .expect("serialize forged proof");
    let result = verifier_core::verify(&s.vk_bytes, &forged_bytes, &s.pi_bytes);
    assert_eq!(result, Err(verifier_core::VerifyError::InvalidProof));
}

#[test]
fn proof_with_infinity_c_is_rejected() {
    let s = sample(7, 0xC0FFEE);
    let forged = Proof::<Bn254> {
        a: s.proof.a,
        b: s.proof.b,
        c: ark_bn254::G1Affine::zero(),
    };
    let mut forged_bytes = Vec::new();
    forged
        .serialize_compressed(&mut forged_bytes)
        .expect("serialize forged proof");
    let result = verifier_core::verify(&s.vk_bytes, &forged_bytes, &s.pi_bytes);
    assert_eq!(result, Err(verifier_core::VerifyError::InvalidProof));
}

#[test]
fn truncated_vk_is_rejected() {
    let s = sample(7, 0xC0FFEE);
    let truncated = &s.vk_bytes[..s.vk_bytes.len() - 1];
    let result = verifier_core::verify(truncated, &s.proof_bytes, &s.pi_bytes);
    assert_eq!(result, Err(verifier_core::VerifyError::InvalidVk));
}

#[test]
fn truncated_proof_is_rejected() {
    let s = sample(7, 0xC0FFEE);
    let truncated = &s.proof_bytes[..s.proof_bytes.len() - 1];
    let result = verifier_core::verify(&s.vk_bytes, truncated, &s.pi_bytes);
    assert_eq!(result, Err(verifier_core::VerifyError::InvalidProof));
}

#[test]
fn truncated_public_inputs_is_rejected() {
    let s = sample(7, 0xC0FFEE);
    let truncated = &s.pi_bytes[..s.pi_bytes.len() - 1];
    let result = verifier_core::verify(&s.vk_bytes, &s.proof_bytes, truncated);
    assert_eq!(
        result,
        Err(verifier_core::VerifyError::InvalidPublicInputs),
    );
}

#[test]
fn empty_buffers_are_rejected() {
    let s = sample(7, 0xC0FFEE);
    assert_eq!(
        verifier_core::verify(&[], &s.proof_bytes, &s.pi_bytes),
        Err(verifier_core::VerifyError::InvalidVk),
    );
    assert_eq!(
        verifier_core::verify(&s.vk_bytes, &[], &s.pi_bytes),
        Err(verifier_core::VerifyError::InvalidProof),
    );
    assert_eq!(
        verifier_core::verify(&s.vk_bytes, &s.proof_bytes, &[]),
        Err(verifier_core::VerifyError::InvalidPublicInputs),
    );
}

// Regression guard for the OOM gotcha: arkworks `Vec::deserialize_compressed`
// allocates from an attacker-controlled length prefix without bounding against
// the buffer. Without the explicit length pre-check, a single flipped bit could
// trigger a multi-GB allocation. These tests assert fast rejection — completing
// at all is the load-bearing observation.
#[test]
fn vk_with_oversized_ic_len_is_rejected_without_oom() {
    let s = sample(7, 0xC0FFEE);
    // VK layout: 224 B fixed header ‖ 8 B u64 LE ic_len ‖ ic_len × 32 B.
    // Setting ic_len = u64::MAX makes ic_len × 32 overflow usize on the
    // pre-check's `checked_mul`, so we never reach the deserializer.
    let mut bad_vk_bytes = s.vk_bytes.clone();
    bad_vk_bytes[224..232].copy_from_slice(&u64::MAX.to_le_bytes());
    let result = verifier_core::verify(&bad_vk_bytes, &s.proof_bytes, &s.pi_bytes);
    assert_eq!(result, Err(verifier_core::VerifyError::InvalidVk));
}

#[test]
fn public_inputs_with_oversized_count_is_rejected_without_oom() {
    let s = sample(7, 0xC0FFEE);
    // pi layout: 4 B u32 LE count ‖ count × 32 B Fr. count = u32::MAX would
    // ask the deserializer to allocate ~137 GB. The pre-check's buffer-length
    // comparison catches it without allocating anything.
    let mut bad_pi_bytes = s.pi_bytes.clone();
    bad_pi_bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let result = verifier_core::verify(&s.vk_bytes, &s.proof_bytes, &bad_pi_bytes);
    assert_eq!(
        result,
        Err(verifier_core::VerifyError::InvalidPublicInputs),
    );
}
