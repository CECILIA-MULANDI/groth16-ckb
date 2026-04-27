# groth16-ckb

A production-ready Groth16 zkSNARK verifier for CKB-VM.

## Phase 0 spike: feasibility confirmed (2026-04-27)

A working PoC built on `arkworks` 0.5 verifies a real BN254 Groth16 proof on CKB-VM:

| Metric | Result |
|---|---|
| Cycles per verify | **~97.5M** (2.9% of 3.5B block limit) |
| Binary size | **75,576 bytes** |
| Heap | fits in default 1.5 MB |
| Toolchain | `rustc` 1.88, `ark-groth16` 0.5, `ckb-std` 1.1 — no patches |

This unblocks the rest of the build plan. Hardening, audit, and mainnet release follow per `PLAN.md`.

## Origin

The infrastructure gap this project addresses was identified while building [Spectre](https://github.com/CECILIA-MULANDI/spectre-protocol-ckb), a key recovery protocol for AI agents on CKB. Spectre's Phase 4 requires on-chain ZK verification of Noir-generated email proofs, but no production-ready SNARK verifier currently runs on CKB-VM. This repo addresses the on-chain Groth16/BN254 slice of that gap.

## What this is

A `no_std` Rust verifier targeting `riscv64imac-unknown-none-elf` for the CKB virtual machine. It accepts Groth16 proofs over BN254 in arkworks-compatible serialization.

- **Curve:** BN254
- **Proof system:** Groth16
- **Target:** `riscv64imac-unknown-none-elf` (CKB-VM)
- **Backend:** arkworks (`ark-groth16`, `ark-bn254`)

## What it accepts

Any Groth16 proof over BN254 produced with arkworks-compatible serialization. This covers circuits written directly in `arkworks`, `circom` (with BN254 + Groth16 backend), and similar toolchains.

## What it does not accept

- Native Noir / Barretenberg proofs (UltraPlonk, UltraHonk) — these are a different proof system and encoding. Using this verifier with a Noir circuit requires a prover-side adapter that emits arkworks-format Groth16 proofs.
- Other proof systems: PLONK, STARKs, Halo2, etc.
- Other curves: BLS12-381, Pasta, etc.

This project addresses the Groth16-on-BN254 slice of the CKB-VM ZK verification gap. PLONK / UltraHonk verification on CKB-VM is separate, longer-term work.

## Scope

This repo provides the on-chain verifier and the host-side SDKs needed to use it.

For Noir users specifically, an additional prover-side adapter is needed to convert Noir circuits/proofs into the arkworks-Groth16 format this verifier accepts. That adapter is a separate project, not delivered here. Native arkworks and circom users can adopt this verifier directly with no adapter.

## Roadmap

See the project plan for phased milestones, acceptance criteria, and audit approach. Mainnet release is audit-gated.

## License

To be dual-licensed under MIT and Apache-2.0. License files will be added before the first tagged release.
