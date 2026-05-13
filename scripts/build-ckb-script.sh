#!/usr/bin/env bash
# Build the on-chain `ckb-script` binary for the riscv64imac CKB-VM target.
#
# Invariant to the caller's working directory; the output path is printed on
# success so that downstream tooling (e.g. the integration-tests crate) can
# locate it.

set -euo pipefail

# Prefer rustup's cargo over any system-installed cargo (e.g. /usr/bin/cargo
# from apt), which may be pinned to an older version that can't parse v4
# lockfiles or honour rust-toolchain.toml.
export PATH="$HOME/.cargo/bin:$PATH"

TARGET="riscv64imac-unknown-none-elf"
PKG="ckb-script"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! rustup target list --installed | grep -q "^${TARGET}$"; then
    echo "error: rust target ${TARGET} not installed." >&2
    echo "install with: rustup target add ${TARGET}" >&2
    exit 1
fi

# Rustflags. Two concerns combined:
#
# 1. `-C target-feature=-a`: disable the RISC-V A (atomic) extension. ckb-vm
#    1.x does not decode atomic ordering bits (`lr.d.aq`, `sc.d.rl`), so
#    LLVM must lower SeqCst atomics via libcalls instead. This flag mirrors
#    `script/.cargo/config.toml`; cargo's env-var RUSTFLAGS *replaces*
#    config rustflags rather than merging, so both layers need it.
#
# 2. `--remap-path-prefix`: arkworks transitive deps emit `assert!` location
#    data even under `panic = "abort"`, so without remap the binary embeds
#    /home/<user>/.cargo and /home/<user>/.rustup paths. Remap rewrites
#    those to canonical synthetic paths so the binary doesn't depend on the
#    build user's home layout. The exact spelling on the right of `=` is
#    part of the build's identity.
CARGO_HOME_PATH="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME_PATH="${RUSTUP_HOME:-$HOME/.rustup}"
export RUSTFLAGS="-C target-feature=-a --remap-path-prefix=${CARGO_HOME_PATH}/registry/src=/cargo-registry --remap-path-prefix=${RUSTUP_HOME_PATH}/toolchains=/rustup-toolchains --remap-path-prefix=${REPO_ROOT}=/build"

# cd into script/ so rustup honours script/rust-toolchain.toml — the lockfile
# pins ckb-gen-types 1.1 which requires rustc >= 1.92, and the toolchain is
# pinned to a specific version for reproducibility.
cd "${REPO_ROOT}/script"
# --locked: refuse to rewrite Cargo.lock. Any out-of-date lock is a build error,
# not an automatic dep bump, so the produced binary depends only on inputs in
# the tree.
cargo build --release --locked --target "${TARGET}" -p "${PKG}"

OUT="${REPO_ROOT}/script/target/${TARGET}/release/${PKG}"
echo "built: ${OUT}"
