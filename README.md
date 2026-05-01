# groth16-ckb

A Groth16 zkSNARK verifier for [CKB-VM](https://github.com/nervosnetwork/ckb-vm), built on [arkworks](https://github.com/arkworks-rs).

This repo provides an on-chain verifier (compiled to `riscv64imac-unknown-none-elf`) plus the host-side libraries and tooling needed to build, test, and integrate it.

## Status

- **Phase 0 (feasibility):** complete as of 2026-04-27.
- **Phase 1 (hardening + wire format):** in progress.
- **Mainnet release:** audit-gated.

This is pre-audit infrastructure. Do not deploy to mainnet.

## At a glance

| | |
|---|---|
| Curve | BN254 |
| Proof system | Groth16 |
| Backend | arkworks (`ark-groth16`, `ark-bn254`) 0.5 |
| Target | `riscv64imac-unknown-none-elf` (CKB-VM) |
| Environment | `no_std`, `panic = "abort"` |
| Toolchain | stable Rust, no patches |

## Compatibility

The verifier accepts any Groth16 proof over BN254 in arkworks-compatible serialization. Supported prover toolchains include:

- arkworks (`ark-groth16`) directly
- circom with the BN254 + Groth16 backend (via an arkworks-format export)

## Building

The on-chain script lives in its own workspace because it targets RISC-V `no_std`.

```sh
# On-chain script (verifier-core + ckb-script)
cd script
cargo build --release --target riscv64imac-unknown-none-elf
```

The host workspace builds for the native target:

```sh
# Host-side tooling and tests
cargo build --workspace
```

To regenerate the Molecule bindings after editing `schemas/groth16.mol`:

```sh
./scripts/regen-schema.sh   # requires `moleculec` on PATH
```

## Testing

```sh
# Host-side differential tests against arkworks reference
cargo test --workspace

# Larger differential sample (slower, ignored by default)
cargo test --workspace -- --ignored
```

The differential harness compares `verifier-core`'s output against arkworks across canonical and adversarial inputs (non-canonical field elements, off-subgroup `G2` points, points at infinity, truncated and oversized buffers).

## Performance

Phase 0 baseline (BN254, sample `x * x = y` circuit):

| Metric | Result |
|---|---|
| Cycles per verify | ~97.5M (~2.9% of the 3.5B block limit) |
| Binary size | 75,576 bytes |
| Heap | fits in the default 1.5 MB |

These numbers will move as hardening lands; treat them as a feasibility baseline rather than a final benchmark.

## Roadmap

The work is organised in phases: feasibility, verifier-core hardening, on-chain wire format, integration tooling, and audit. Mainnet release is gated on a third-party audit. Detailed milestones and acceptance criteria are tracked in the project's issue tracker.

## Origin

The infrastructure gap this project addresses was identified while building [Spectre](https://github.com/CECILIA-MULANDI/spectre-protocol-ckb), a key recovery protocol for AI agents on CKB. Spectre's later phases require on-chain ZK verification, but no production-ready SNARK verifier currently runs on CKB-VM. This repo addresses the Groth16-on-BN254 slice of that gap as general CKB infrastructure, useful to any CKB application that wants on-chain Groth16 verification, not just Spectre.
