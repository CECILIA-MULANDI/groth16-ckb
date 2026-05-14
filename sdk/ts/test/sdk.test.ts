import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  decodeVerifyingKey,
  decodeWitness,
  encodeVerifyingKey,
  encodeWitness,
  FR_BYTES,
  G1_BYTES,
  G2_BYTES,
  verifyingKeyDataHash,
  WIRE_VERSION,
  type VerifyingKey,
  type Witness,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = resolve(HERE, "../../../test_vectors");

function readBytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(resolve(VECTORS, name)));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe("verifying key SDK", () => {
  const vkBytes = readBytes("vk.mol.bin");

  it("decodes into a native JS shape", () => {
    const vk = decodeVerifyingKey(vkBytes);
    expect(vk.version).toBe(WIRE_VERSION);
    expect(vk.curve).toBe("bn254");
    expect(vk.alphaG1.length).toBe(G1_BYTES);
    expect(vk.betaG2.length).toBe(G2_BYTES);
    expect(vk.gammaG2.length).toBe(G2_BYTES);
    expect(vk.deltaG2.length).toBe(G2_BYTES);
    // SquareCircuit has 1 public input → IC length 2.
    expect(vk.ic.length).toBe(2);
    expect(vk.ic.every((p) => p.length === G1_BYTES)).toBe(true);
  });

  it("encode(decode(x)) is byte-identical", () => {
    const re = encodeVerifyingKey(decodeVerifyingKey(vkBytes));
    expect(bytesEqual(re, vkBytes)).toBe(true);
  });

  it("rejects wrong-length leaf bytes at the boundary", () => {
    const vk = decodeVerifyingKey(vkBytes);
    const bad: VerifyingKey = { ...vk, alphaG1: vk.alphaG1.slice(1) };
    expect(() => encodeVerifyingKey(bad)).toThrow(/alphaG1.*31/);
  });

  it("rejects empty IC", () => {
    const vk = decodeVerifyingKey(vkBytes);
    expect(() => encodeVerifyingKey({ ...vk, ic: [] })).toThrow(/ic/);
  });

  it("rejects unsupported version on encode", () => {
    const vk = decodeVerifyingKey(vkBytes);
    expect(() => encodeVerifyingKey({ ...vk, version: 70000 })).toThrow(
      /uint16/,
    );
  });
});

describe("verifyingKeyDataHash", () => {
  const vkBytes = readBytes("vk.mol.bin");
  const expectedHash = readBytes("vk_data_hash.bin");

  it("matches the Rust ckb_hash::blake2b_256 fixture", () => {
    const vk = decodeVerifyingKey(vkBytes);
    const hash = verifyingKeyDataHash(vk);
    expect(hash.length).toBe(32);
    expect(bytesEqual(hash, expectedHash)).toBe(true);
  });

  it("changes if the VK changes", () => {
    const vk = decodeVerifyingKey(vkBytes);
    const flipped = new Uint8Array(vk.alphaG1);
    flipped[0] ^= 0x01;
    const mutated: VerifyingKey = { ...vk, alphaG1: flipped };
    expect(bytesEqual(verifyingKeyDataHash(mutated), expectedHash)).toBe(false);
  });
});

describe("witness SDK", () => {
  const wBytes = readBytes("witness.mol.bin");

  it("decodes into a native JS shape", () => {
    const w = decodeWitness(wBytes);
    expect(w.version).toBe(WIRE_VERSION);
    expect(w.curve).toBe("bn254");
    expect(w.proof.a.length).toBe(G1_BYTES);
    expect(w.proof.b.length).toBe(G2_BYTES);
    expect(w.proof.c.length).toBe(G1_BYTES);
    expect(w.publicInputs.length).toBe(1);
    expect(w.publicInputs[0]!.length).toBe(FR_BYTES);
  });

  it("encode(decode(x)) is byte-identical", () => {
    const re = encodeWitness(decodeWitness(wBytes));
    expect(bytesEqual(re, wBytes)).toBe(true);
  });

  it("rejects wrong-length public input", () => {
    const w = decodeWitness(wBytes);
    const bad: Witness = {
      ...w,
      publicInputs: [w.publicInputs[0]!.slice(0, 16)],
    };
    expect(() => encodeWitness(bad)).toThrow(/publicInputs\[0\].*16/);
  });
});
