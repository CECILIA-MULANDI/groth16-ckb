#![no_std]

//! Generated Molecule readers/writers for the Groth16 wire format.
//!
//! Schema is `schemas/groth16.mol` at the repo root. The contents of
//! `generated.rs` are produced by `moleculec --language rust` from that
//! schema and committed to the tree so audit reviewers (and CI) do not
//! need `moleculec` installed at build time.
//!
//! To regenerate after editing the schema:
//!
//! ```sh
//! moleculec --language rust --schema-file schemas/groth16.mol \
//!     > script/crates/groth16-schema/src/generated.rs
//! cargo fmt -p groth16-schema
//! ```

extern crate alloc;

#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(unused_imports)]
#[rustfmt::skip]
pub mod generated;

pub use generated::*;
