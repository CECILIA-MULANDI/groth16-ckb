#!/usr/bin/env bash
# Build the canonical seed input for the `verify_arkworks` fuzz target from
# the committed test vectors. The target's framing is:
#   LE u16 vk_len || LE u16 proof_len || vk_bytes || proof_bytes || public_inputs_bytes
#
# Giving the fuzzer a valid starting input lets it explore deserialization
# paths past the length pre-checks, where bugs would actually hide.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VK="${REPO_ROOT}/test_vectors/vk.bin"
PROOF="${REPO_ROOT}/test_vectors/proof.bin"
PI="${REPO_ROOT}/test_vectors/public_inputs.bin"

for f in "$VK" "$PROOF" "$PI"; do
  [[ -f "$f" ]] || { echo "missing $f; regenerate with cargo run -p host --bin generate-vectors" >&2; exit 1; }
done

DEST_DIR="${REPO_ROOT}/fuzz/corpus/verify_arkworks"
mkdir -p "$DEST_DIR"
DEST="${DEST_DIR}/seed-valid"

VK_LEN=$(stat -c%s "$VK")
PROOF_LEN=$(stat -c%s "$PROOF")

# Emit 4-byte LE u16 header (vk_len, proof_len) then the payload bytes.
printf '%b%b%b%b' \
  "\\x$(printf '%02x' $(( VK_LEN & 0xFF )))" \
  "\\x$(printf '%02x' $(( (VK_LEN >> 8) & 0xFF )))" \
  "\\x$(printf '%02x' $(( PROOF_LEN & 0xFF )))" \
  "\\x$(printf '%02x' $(( (PROOF_LEN >> 8) & 0xFF )))" \
  > "$DEST"
cat "$VK" "$PROOF" "$PI" >> "$DEST"

echo "wrote ${DEST} ($(stat -c%s "$DEST") bytes; vk_len=${VK_LEN}, proof_len=${PROOF_LEN})"
