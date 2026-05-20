# Threat Model: groth16-ckb

Status: draft, Phase 4 (pre-audit). Reviewed and updated whenever the verifier input handling, Molecule schema, pinned arkworks version, or reproducible-build invariants change.

This describes what the on-chain BN254 Groth16 verifier (`script/crates/ckb-script` + `verifier-core` + `wire-decode`) is designed to defend against, the boundaries of that protection, the evidence behind each claim, and the residual risk an external audit should focus on.

## 1. System under consideration

A CKB-VM type script that verifies a Groth16 zkSNARK proof over BN254. Three on-chain artifacts:

- **Code cell**: holds the compiled `ckb-script` ELF. Its `data_hash` is referenced as `type.code_hash`.
- **VK cell**: holds the Molecule-encoded `Groth16VerifyingKey`. Its `data_hash` is the `type.args` (32 bytes) of cells that verify against it.
- **Trigger cell**: `type = (code_hash = data_hash(verifier ELF), args = data_hash(VK cell data))`. Verification runs when this cell is consumed as an input. On the creation side the verifier returns success without checking (matches the SUDT/xUDT convention).

Pipeline on spend: `ckb-script` reads `script.args`, the witness from `WitnessArgs.input_type`, and the VK cell via cell_dep. `wire_decode` turns both Molecule blobs into arkworks-shaped bytes. `verifier_core::verify` runs length pre-checks, arkworks compressed deserialization with subgroup validation, infinity-point rejection, and the Groth16 pairing equation.

## 2. Assets

In order of severity:

1. **Soundness of acceptance.** The verifier accepts `(vk, public_inputs, proof)` only if the proof is genuinely valid. A break lets an attacker spend a trigger cell without holding a real witness.
2. **CKB-VM liveness.** The verifier never panics, allocates unbounded memory, or exceeds the cycle limit. A break makes the verifier unusable or panics a node.
3. **Binding of trigger cell to its VK.** A trigger cell's verifier always runs against the VK whose `data_hash` is its `type.args`; an attacker cannot substitute a weaker VK at spend time.

## 3. Trust boundaries and attacker capabilities

Attacker controls: the witness bytes, the contents of any cell_dep they place in the transaction (subject to CKB's data_hash binding), and the transaction structure.

Trusted: CKB consensus and VM, `ckb-std` host calls, the pinned arkworks crates (audit assumption, see Section 5), BN254 hardness assumptions, blake2b256 collision resistance, and the trusted setup that produced the VK (out of scope).

Attacker can submit arbitrary transactions, run unlimited offline computation, and observe on-chain state (the verifier reveals no witness; Groth16 is zero-knowledge). The attacker cannot break BN254, forge a blake2b256 collision on cell data, or bypass CKB-VM accounting.

## 4. Attack scenarios

### 4.1 Forged proof (soundness break)

Goal: have the verifier accept a proof that should fail the pairing equation.

Three classes of vector, each with its own mitigation:

- **Encoding-level**: non-canonical Fr/Fq encodings (values >= field modulus), or values that decode but break invariants (public-input count disagreeing with VK `ic_len`). Mitigated by arkworks' canonical-encoding rejection and by the `count + 1 == ic_len` cross-check in `verifier-core::verify` before any deserialization.
- **Curve-level**: G2 points that lie in the curve over Fq2 but outside the prime-order subgroup, or substituting the point at infinity for an active VK or proof point. Mitigated by arkworks' `Validate::Yes` (the default on `deserialize_compressed`), which runs G2 subgroup membership, and by explicit infinity rejection in `verifier-core` on every G1 / G2 slot of VK and proof. Without the explicit infinity check, `gamma_g2 = infinity` would make public inputs irrelevant and `proof.a = infinity` would collapse the equation in attacker-exploitable ways.
- **Probabilistic**: random or bit-flipped bytes hoping verification slips. Mitigated cryptographically by the pairing check; exercised empirically by the bit-flip differential tests and the libFuzzer harness.

Evidence: hand-crafted cases in [host/tests/differential.rs](../host/tests/differential.rs) (non-canonical Fr/Fq, off-subgroup G2 on every G2 slot, infinity on every slot, bit-flip rejection across the whole input space, count mismatches). Property tests in [host/tests/properties.rs](../host/tests/properties.rs) run 256 randomized forged-public-input probes per invocation, all rejected. The libFuzzer target [fuzz/fuzz_targets/verify_arkworks.rs](../fuzz/fuzz_targets/verify_arkworks.rs) has run for millions of executions without a false accept.

### 4.2 Denial of service via panic, OOM, or cycle exhaustion

Goal: abort the script or make the verifier unusable.

The biggest specific concern is `Vec::deserialize_compressed` allocating from an attacker-controlled length prefix (arkworks 0.5 will happily try to allocate gigabytes for a flipped bit). Mitigated by explicit length pre-checks in `verifier-core::verify`: `ic_len` and `count` are read as raw integers from the buffer, multiplied against per-element size with `checked_mul`, and compared to the actual buffer length before any deserialization happens. Tested directly by `vk_with_oversized_ic_len_is_rejected_without_oom` and `public_inputs_with_oversized_count_is_rejected_without_oom` in [host/tests/differential.rs](../host/tests/differential.rs).

Beyond that specific gotcha, panic-class issues are mitigated by clippy lints (`deny(clippy::unwrap_used / expect_used / panic / unreachable)`) on the verifier-core and wire-decode crates, and by `Result` propagation throughout `ckb-script/main.rs`. Cycle exhaustion is bounded empirically: the worst measured case is ~121M cycles at N=64 public inputs (48.5% of the 250M block-vm bound), with each additional public input adding ~270k to 300k cycles (one G1 scalar multiplication). Benchmarks in [integration-tests/tests/cycles.rs](../integration-tests/tests/cycles.rs).

Coverage-guided fuzzing of the verifier and both Molecule decoders has produced no panic, hang, or OOM across millions of executions.

### 4.3 Molecule decoder exploitation

Goal: pass `wire_decode` with malformed bytes that bypass downstream validation, or trigger a panic in the Molecule library.

`Reader::from_slice` recursively validates offsets, item counts, and fixed-array sizes up front; after it returns `Ok`, every `as_slice()` on a fixed-size field is the right number of bytes. `wire-decode` is the single bridge from Molecule readers to arkworks-shaped buffers, lives in its own crate, and is fuzzed via [fuzz/fuzz_targets/decode_vk_molecule.rs](../fuzz/fuzz_targets/decode_vk_molecule.rs) and `decode_witness_molecule.rs`. A `version` field is checked against `VERSION_V1` after Molecule decode; the union dispatch on curve is exhaustive at the type level, so adding a future curve will force a new match arm at compile time.

### 4.4 VK substitution at spend time

Goal: spend a trigger cell against a different VK than its `type.args` commits to.

The on-chain script calls `look_for_dep_with_data_hash(args)` to locate the VK cell among cell_deps. Any other VK in cell_deps is irrelevant unless its `data_hash` collides, which requires a blake2b256 second pre-image (out of scope). Tested in [integration-tests/tests/verify.rs](../integration-tests/tests/verify.rs) (`wrong_vk_for_proof_rejected`, `missing_vk_cell_dep_rejected`).

### 4.5 Replay

The verifier is stateless. Each trigger cell is consumed on spend; CKB enforces single-spend, so replay against the same cell is impossible.

Across trigger cells: the proof binds to `(vk, public_inputs)`. Two trigger cells with the same VK and the same public-input semantics will accept the same proof. **This is a property of the protocol that uses the verifier, not of the verifier itself.** The protocol designer is responsible for adding any per-cell binding they need (for example, mixing the spent OutPoint into the public inputs). The verifier provides correctness of `verify(vk, public_inputs, proof)`; it does not constrain what the public inputs mean.

## 5. Out of scope

- **Trusted setup correctness.** The toxic waste of the Groth16 parameter ceremony is a separate concern; this verifier accepts whatever VK is published.
- **Prover correctness.** A faulty prover may produce proofs that legitimately verify but for the wrong statement (wrong circuit). The verifier checks that a proof exists for `(vk, public_inputs)`; semantic correctness is the integrator's responsibility.
- **arkworks correctness.** Versions are pinned `0.5` with `--locked` and we rely on upstream review. A discovered bug in arkworks Groth16, BN254, or compressed deserialization is in-scope for upstream and out-of-scope here. The reproducible-build script (`scripts/verify-reproducible.sh`) lets reviewers confirm exactly what they audited is what runs.
- **CKB layer**: capacity rules, lock script enforcement, transaction pool admission, consensus. Trusted.
- **Side channels.** On-chain verification time is observable and deterministic; constant-time pairing is an arkworks concern.

## 6. Residual risk and audit targets

Highest-value review areas for an external audit:

1. **Length pre-checks in `verifier-core::verify`** (~30 lines, Section 4.2). A single arithmetic error here reopens the OOM gap. Should be reviewed against the arkworks 0.5 `Vec::deserialize_compressed` source.
2. **Subgroup membership for G2.** We rely on `Validate::Yes` as the arkworks default. Audit should confirm this default has not been changed by feature flags or a version bump.
3. **Infinity-point rejection coverage.** Audit should walk every active G1 / G2 slot in VK and proof and confirm the check sequencing happens before the value is used.
4. **Long-running fuzz before audit handover.** A multi-hour scheduled run on the three fuzz targets is planned for Phase 4 wrap-up; findings (if any) feed into the audit packet.
5. **Cross-implementation differential.** Running snarkjs Groth16 verify on the same VK + proof + public inputs would harden the soundness claim beyond a single arkworks code path.
