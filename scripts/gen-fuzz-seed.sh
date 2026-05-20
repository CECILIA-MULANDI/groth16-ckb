#!/usr/bin/env bash
# Build canonical seed inputs for the fuzz targets from the committed test
# vectors. Without seeds the fuzzer wanders in length-reject territory; with
# seeds it explores past the structural checks into the code paths where
# bugs would actually hide.
#
# Targets seeded:
#   - verify_arkworks         framed (vk_len|proof_len|vk|proof|pi)
#   - decode_vk_molecule      raw bytes of vk.mol.bin
#   - decode_witness_molecule raw bytes of witness.mol.bin

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VK="${REPO_ROOT}/test_vectors/vk.bin"
PROOF="${REPO_ROOT}/test_vectors/proof.bin"
PI="${REPO_ROOT}/test_vectors/public_inputs.bin"
VK_MOL="${REPO_ROOT}/test_vectors/vk.mol.bin"
WITNESS_MOL="${REPO_ROOT}/test_vectors/witness.mol.bin"

for f in "$VK" "$PROOF" "$PI" "$VK_MOL" "$WITNESS_MOL"; do
  [[ -f "$f" ]] || { echo "missing $f; regenerate with cargo run -p host --bin generate-vectors" >&2; exit 1; }
done

CORPUS_ROOT="${REPO_ROOT}/fuzz/corpus"

# verify_arkworks: framed seed with explicit (vk_len, proof_len) LE u16 header.
VA_DIR="${CORPUS_ROOT}/verify_arkworks"
mkdir -p "$VA_DIR"
VA_DEST="${VA_DIR}/seed-valid"

VK_LEN=$(stat -c%s "$VK")
PROOF_LEN=$(stat -c%s "$PROOF")
printf '%b%b%b%b' \
  "\\x$(printf '%02x' $(( VK_LEN & 0xFF )))" \
  "\\x$(printf '%02x' $(( (VK_LEN >> 8) & 0xFF )))" \
  "\\x$(printf '%02x' $(( PROOF_LEN & 0xFF )))" \
  "\\x$(printf '%02x' $(( (PROOF_LEN >> 8) & 0xFF )))" \
  > "$VA_DEST"
cat "$VK" "$PROOF" "$PI" >> "$VA_DEST"
echo "wrote ${VA_DEST} ($(stat -c%s "$VA_DEST") bytes; vk_len=${VK_LEN}, proof_len=${PROOF_LEN})"

# decode_vk_molecule and decode_witness_molecule: raw Molecule bytes.
VK_MOL_DIR="${CORPUS_ROOT}/decode_vk_molecule"
mkdir -p "$VK_MOL_DIR"
cp "$VK_MOL" "${VK_MOL_DIR}/seed-valid"
echo "wrote ${VK_MOL_DIR}/seed-valid ($(stat -c%s "${VK_MOL_DIR}/seed-valid") bytes)"

WITNESS_MOL_DIR="${CORPUS_ROOT}/decode_witness_molecule"
mkdir -p "$WITNESS_MOL_DIR"
cp "$WITNESS_MOL" "${WITNESS_MOL_DIR}/seed-valid"
echo "wrote ${WITNESS_MOL_DIR}/seed-valid ($(stat -c%s "${WITNESS_MOL_DIR}/seed-valid") bytes)"
