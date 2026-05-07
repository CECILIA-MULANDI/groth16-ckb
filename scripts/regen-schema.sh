#!/usr/bin/env bash
# Regenerate Rust + TypeScript bindings for schemas/groth16.mol.
#
# Requires:
#   - moleculec     (install via `cargo install moleculec --locked`)
#   - moleculec-es  (Go binary; download a prebuilt release from
#                   https://github.com/nervosnetwork/moleculec-es/releases
#                   or install via `go install github.com/xxuejie/moleculec-es/cmd/moleculec-es@latest`)
#
# Run from repo root.

set -euo pipefail

if ! command -v moleculec >/dev/null 2>&1; then
    echo "error: moleculec not found on PATH." >&2
    echo "install with: cargo install moleculec --locked" >&2
    exit 1
fi

if ! command -v moleculec-es >/dev/null 2>&1; then
    echo "error: moleculec-es not found on PATH." >&2
    echo "install: download a release from https://github.com/nervosnetwork/moleculec-es/releases" >&2
    echo "  or: go install github.com/xxuejie/moleculec-es/cmd/moleculec-es@latest" >&2
    exit 1
fi

SCHEMA="schemas/groth16.mol"
RUST_OUT="script/crates/groth16-schema/src/generated.rs"
TS_OUT_DIR="schemas/generated"
TS_OUT_JS="$TS_OUT_DIR/groth16.js"

# Rust bindings.
moleculec --language rust --schema-file "$SCHEMA" > "$RUST_OUT"
cargo fmt --manifest-path script/Cargo.toml -p groth16-schema

# TypeScript bindings. moleculec-es consumes a JSON IR produced by moleculec,
# and derives the .d.ts path by swapping `.js` -> `.d.ts` on -outputFile.
mkdir -p "$TS_OUT_DIR"
SCHEMA_JSON="$(mktemp -t groth16-schema.XXXXXX.json)"
trap 'rm -f "$SCHEMA_JSON"' EXIT
moleculec --language - --schema-file "$SCHEMA" --format json > "$SCHEMA_JSON"
moleculec-es \
    -inputFile "$SCHEMA_JSON" \
    -outputFile "$TS_OUT_JS" \
    -hasBigInt \
    -generateTypeScriptDefinition

echo "regenerated:"
echo "  $RUST_OUT"
echo "  $TS_OUT_JS"
echo "  ${TS_OUT_JS%.js}.d.ts"
