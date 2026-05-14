import { ccc } from "@ckb-ccc/core";
import { blake2b } from "@noble/hashes/blake2b";

import {
  Groth16VerifyingKey,
  Groth16Witness,
  SerializeGroth16VerifyingKey,
  SerializeGroth16Witness,
} from "../../../schemas/generated/groth16.js";

export const WIRE_VERSION = 1;
export const G1_BYTES = 32;
export const G2_BYTES = 64;
export const FR_BYTES = 32;

export interface VerifyingKey {
  version: number;
  curve: "bn254";
  alphaG1: Uint8Array;
  betaG2: Uint8Array;
  gammaG2: Uint8Array;
  deltaG2: Uint8Array;
  ic: Uint8Array[];
}

export interface Proof {
  a: Uint8Array;
  b: Uint8Array;
  c: Uint8Array;
}

export interface Witness {
  version: number;
  curve: "bn254";
  proof: Proof;
  publicInputs: Uint8Array[];
}

function assertLen(buf: Uint8Array, expected: number, label: string): void {
  if (buf.length !== expected) {
    throw new Error(
      `${label}: expected ${expected} bytes, got ${buf.length}`,
    );
  }
}

function toBuffer(u8: Uint8Array): ArrayBuffer {
  // Copy into a fresh Uint8Array so the underlying buffer is a plain
  // ArrayBuffer (not a SharedArrayBuffer or a slice of a larger buffer).
  const copy = new Uint8Array(u8.length);
  copy.set(u8);
  return copy.buffer as ArrayBuffer;
}

function versionBytes(version: number): ArrayBuffer {
  if (!Number.isInteger(version) || version < 0 || version > 0xffff) {
    throw new Error(`version must be a uint16, got ${version}`);
  }
  return new Uint8Array([version & 0xff, (version >> 8) & 0xff]).buffer;
}

function readVersion(raw: ArrayBuffer): number {
  if (raw.byteLength !== 2) {
    throw new Error(`version: expected 2 bytes, got ${raw.byteLength}`);
  }
  const v = new Uint8Array(raw);
  return v[0]! | (v[1]! << 8);
}

export function encodeVerifyingKey(vk: VerifyingKey): Uint8Array {
  if (vk.curve !== "bn254") {
    throw new Error(`unsupported curve: ${vk.curve}`);
  }
  assertLen(vk.alphaG1, G1_BYTES, "alphaG1");
  assertLen(vk.betaG2, G2_BYTES, "betaG2");
  assertLen(vk.gammaG2, G2_BYTES, "gammaG2");
  assertLen(vk.deltaG2, G2_BYTES, "deltaG2");
  if (vk.ic.length < 1) {
    throw new Error("ic must have at least one entry (num_public_inputs + 1)");
  }
  vk.ic.forEach((p, i) => assertLen(p, G1_BYTES, `ic[${i}]`));

  const bytes = SerializeGroth16VerifyingKey({
    version: versionBytes(vk.version),
    content: {
      type: "VerifyingKeyBn254",
      value: {
        alpha_g1: toBuffer(vk.alphaG1),
        beta_g2: toBuffer(vk.betaG2),
        gamma_g2: toBuffer(vk.gammaG2),
        delta_g2: toBuffer(vk.deltaG2),
        gamma_abc_g1: vk.ic.map(toBuffer),
      },
    },
  });
  return new Uint8Array(bytes);
}

export function decodeVerifyingKey(bytes: Uint8Array): VerifyingKey {
  const reader = new Groth16VerifyingKey(toBuffer(bytes));
  const version = readVersion(reader.getVersion().raw());

  const content = reader.getContent();
  const tag = content.unionType();
  if (tag !== "VerifyingKeyBn254") {
    throw new Error(`unsupported VK union variant: ${tag}`);
  }
  const bn254 = content.value();
  const icVec = bn254.getGammaAbcG1();
  const ic: Uint8Array[] = [];
  for (let i = 0; i < icVec.length(); i++) {
    ic.push(new Uint8Array(icVec.indexAt(i).raw()));
  }

  return {
    version,
    curve: "bn254",
    alphaG1: new Uint8Array(bn254.getAlphaG1().raw()),
    betaG2: new Uint8Array(bn254.getBetaG2().raw()),
    gammaG2: new Uint8Array(bn254.getGammaG2().raw()),
    deltaG2: new Uint8Array(bn254.getDeltaG2().raw()),
    ic,
  };
}

export function encodeWitness(w: Witness): Uint8Array {
  if (w.curve !== "bn254") {
    throw new Error(`unsupported curve: ${w.curve}`);
  }
  assertLen(w.proof.a, G1_BYTES, "proof.a");
  assertLen(w.proof.b, G2_BYTES, "proof.b");
  assertLen(w.proof.c, G1_BYTES, "proof.c");
  w.publicInputs.forEach((p, i) =>
    assertLen(p, FR_BYTES, `publicInputs[${i}]`),
  );

  const bytes = SerializeGroth16Witness({
    version: versionBytes(w.version),
    content: {
      type: "Bn254Witness",
      value: {
        proof: {
          a: toBuffer(w.proof.a),
          b: toBuffer(w.proof.b),
          c: toBuffer(w.proof.c),
        },
        public_inputs: w.publicInputs.map(toBuffer),
      },
    },
  });
  return new Uint8Array(bytes);
}

// "ckb-default-hash" — the personalization CKB uses for data_hash / type_hash
// computation. 16 ASCII bytes, exactly what blake2b's personalization expects.
const CKB_HASH_PERSONALIZATION = new Uint8Array([
  0x63, 0x6b, 0x62, 0x2d, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x68,
  0x61, 0x73, 0x68,
]);

function ckbHash(bytes: Uint8Array): Uint8Array {
  return blake2b(bytes, {
    dkLen: 32,
    personalization: CKB_HASH_PERSONALIZATION,
  });
}

/**
 * Returns the CKB data_hash of the encoded verifying key — the 32-byte value
 * a consumer must set as the type script's `args` so the on-chain verifier
 * (which matches VK cell_deps by `data_hash == args`) picks the right cell.
 */
export function verifyingKeyDataHash(vk: VerifyingKey): Uint8Array {
  return ckbHash(encodeVerifyingKey(vk));
}

export function decodeWitness(bytes: Uint8Array): Witness {
  const reader = new Groth16Witness(toBuffer(bytes));
  const version = readVersion(reader.getVersion().raw());

  const content = reader.getContent();
  const tag = content.unionType();
  if (tag !== "Bn254Witness") {
    throw new Error(`unsupported witness union variant: ${tag}`);
  }
  const bn254 = content.value();
  const proof = bn254.getProof();
  const piVec = bn254.getPublicInputs();
  const publicInputs: Uint8Array[] = [];
  for (let i = 0; i < piVec.length(); i++) {
    publicInputs.push(new Uint8Array(piVec.indexAt(i).raw()));
  }

  return {
    version,
    curve: "bn254",
    proof: {
      a: new Uint8Array(proof.getA().raw()),
      b: new Uint8Array(proof.getB().raw()),
      c: new Uint8Array(proof.getC().raw()),
    },
    publicInputs,
  };
}

/**
 * Encode the witness and wrap it in `WitnessArgs.input_type`, returning the
 * molecule-encoded `WitnessArgs` bytes that go directly into a transaction's
 * `witnesses[i]` (where `i` is the index of the input bearing the verifier
 * type script). The on-chain script reads `WitnessArgs.input_type` and decodes
 * the inner `Groth16Witness`.
 */
export function encodeWitnessArgs(w: Witness): Uint8Array {
  const witnessBytes = encodeWitness(w);
  return ccc.WitnessArgs.from({ inputType: witnessBytes }).toBytes();
}

export interface VerifierTypeScriptInput {
  /** Code hash of the deployed groth16-ckb verifier binary. */
  codeHash: Uint8Array;
  /** Hash type for the verifier cell — typically "data1" for a code cell. */
  hashType: ccc.HashType;
  /** The verifying key this script must accept proofs for. */
  vk: VerifyingKey;
}

/**
 * Build the CKB type script that runs the verifier against `vk`. The script's
 * `args` is set to `verifyingKeyDataHash(vk)`, which is the value the on-chain
 * script matches against to find the VK cell among `cell_deps`.
 */
export function verifierTypeScript(input: VerifierTypeScriptInput): ccc.Script {
  return ccc.Script.from({
    codeHash: input.codeHash,
    hashType: input.hashType,
    args: verifyingKeyDataHash(input.vk),
  });
}
