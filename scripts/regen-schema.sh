#!/usr/bin/env bash
# Regenerate Rust bindings for schemas/groth16.mol.
#
# Requires `moleculec` (install via `cargo install moleculec --locked`).
# Run from repo root.

set -euo pipefail

if ! command -v moleculec >/dev/null 2>&1; then
    echo "error: moleculec not found on PATH." >&2
    echo "install with: cargo install moleculec --locked" >&2
    exit 1
fi

SCHEMA="schemas/groth16.mol"
OUT="script/crates/groth16-schema/src/generated.rs"

moleculec --language rust --schema-file "$SCHEMA" > "$OUT"
cargo fmt --manifest-path script/Cargo.toml -p groth16-schema

echo "regenerated $OUT from $SCHEMA"
