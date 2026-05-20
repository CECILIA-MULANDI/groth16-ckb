# groth16-ckb

A Groth16 zkSNARK verifier for [CKB-VM](https://github.com/nervosnetwork/ckb-vm), built on [arkworks](https://github.com/arkworks-rs).

This repo provides an on-chain verifier (compiled to `riscv64imac-unknown-none-elf`) plus the host-side libraries and tooling needed to build, test, and integrate it.

## Status

- **Phase 0 (feasibility):** complete 2026-04-27.
- **Phase 1 (verifier-core hardening + Molecule wire format):** complete 2026-05-07.
- **Phase 2 (on-chain script + integration tests + benchmarks):** complete 2026-05-13.
- **Phase 3 (host SDKs + reference example):** complete 2026-05-13. End-to-end verification on CKB Pudge testnet confirmed 2026-05-15 (tx [`0xc658f9e8…3c96`](https://pudge.explorer.nervos.org/transaction/0xc658f9e8a846747a3aad373b2145ac49d920aba00c88885219d6c25f3dc53c96)).
- **Phase 4 (hardening + audit prep):** next.
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
./scripts/build-ckb-script.sh
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

# End-to-end integration tests through ckb-testtool (requires the on-chain
# binary built first via scripts/build-ckb-script.sh)
cargo test -p integration-tests
```

The differential harness compares `verifier-core`'s output against arkworks across canonical and adversarial inputs (non-canonical field elements, off-subgroup `G2` points, points at infinity, truncated and oversized buffers). The integration tests exercise the production call path: VK in a `cell_dep`, proof + public inputs in `WitnessArgs.input_type`, decoded through Molecule and handed to `verifier-core`.

### Fuzzing

Coverage-guided fuzzing of `verifier-core::verify` lives in [`fuzz/`](fuzz/). The harness feeds `(vk_bytes, proof_bytes, public_inputs_bytes)` as three independent attacker-controlled byte slices and asserts the verifier never panics. Requires `cargo install cargo-fuzz` and a nightly toolchain (pinned in `fuzz/rust-toolchain.toml`, scoped to the fuzz workspace only).

```sh
cd fuzz
cargo +nightly fuzz run verify_arkworks
```

## Performance

Cycle counts on the production call path (Molecule-decode VK from a `cell_dep`, proof from `WitnessArgs.input_type`, verify on `riscv64imac` CKB-VM) for a circuit with `N` public inputs:

| num_public_inputs | cycles      | % of 250M bound |
|------------------:|------------:|----------------:|
|                 1 | 102,419,769 |            41.0 |
|                 4 | 103,234,891 |            41.3 |
|                 8 | 104,285,448 |            41.7 |
|                16 | 106,588,487 |            42.6 |
|                32 | 111,343,646 |            44.5 |
|                64 | 121,128,923 |            48.5 |

The fixed-cost component (~102M cycles at N=1) is the pairing check; each additional public input adds ~270k–300k cycles for one G1 scalar multiplication. Binary size is 96 KB and the default 1.5 MB heap is sufficient across the whole range.

Reproduce with:

```sh
./scripts/build-ckb-script.sh
cargo test -p integration-tests --test cycles -- --ignored --nocapture
```

The on-chain binary is built reproducibly: pinned toolchain (`script/rust-toolchain.toml`), locked dependencies (`--locked`), and source-path remapping. Run `./scripts/verify-reproducible.sh` to confirm two clean builds produce byte-identical output.

## Roadmap

The work is organised in phases: feasibility, verifier-core hardening, on-chain wire format, integration tooling, and audit. Mainnet release is gated on a third-party audit. Detailed milestones and acceptance criteria are tracked in the project's issue tracker.

## Origin

The infrastructure gap this project addresses was identified while building [Spectre](https://github.com/CECILIA-MULANDI/spectre-protocol-ckb), a key recovery protocol for AI agents on CKB. Spectre's later phases require on-chain ZK verification, but no production-ready SNARK verifier currently runs on CKB-VM. This repo addresses the Groth16-on-BN254 slice of that gap as general CKB infrastructure, useful to any CKB application that wants on-chain Groth16 verification, not just Spectre.
