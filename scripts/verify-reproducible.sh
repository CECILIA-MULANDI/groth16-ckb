#!/usr/bin/env bash
# Verify that scripts/build-ckb-script.sh produces byte-identical output
# across two clean builds. Prints the canonical SHA256 on success.
#
# Cross-machine reproducibility is the real goal; this script catches
# same-machine regressions cheaply. A future CI step (or auditor) should run
# the same procedure on a different host to confirm.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET="riscv64imac-unknown-none-elf"
BIN="${REPO_ROOT}/script/target/${TARGET}/release/ckb-script"

build_and_hash() {
    rm -rf "${REPO_ROOT}/script/target/${TARGET}"
    "${SCRIPT_DIR}/build-ckb-script.sh" >/dev/null
    sha256sum "${BIN}" | awk '{print $1}'
}

echo "build 1..."
H1="$(build_and_hash)"
echo "  ${H1}"

echo "build 2..."
H2="$(build_and_hash)"
echo "  ${H2}"

if [[ "${H1}" != "${H2}" ]]; then
    echo "FAIL: builds produced different bytes." >&2
    exit 1
fi

SIZE="$(wc -c < "${BIN}")"
echo
echo "reproducible: ${H1}"
echo "size:         ${SIZE} bytes"
