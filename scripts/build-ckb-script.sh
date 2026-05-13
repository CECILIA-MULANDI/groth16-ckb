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

# cd into script/ so rustup honours script/rust-toolchain.toml — the lockfile
# pins ckb-gen-types 1.1 which requires rustc >= 1.92.
cd "${REPO_ROOT}/script"
cargo build --release --target "${TARGET}" -p "${PKG}"

OUT="${REPO_ROOT}/script/target/${TARGET}/release/${PKG}"
echo "built: ${OUT}"
