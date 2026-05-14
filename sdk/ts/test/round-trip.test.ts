import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  Groth16VerifyingKey,
  Groth16Witness,
  SerializeGroth16VerifyingKey,
  SerializeGroth16Witness,
} from "../../../schemas/generated/groth16.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = resolve(HERE, "../../../test_vectors");
const WIRE_VERSION = 1;

function readVector(name: string): ArrayBuffer {
  const buf = readFileSync(resolve(VECTORS, name));
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function bytesEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
  if (a.byteLength !== b.byteLength) return false;
  const av = new Uint8Array(a);
  const bv = new Uint8Array(b);
  for (let i = 0; i < av.length; i++) if (av[i] !== bv[i]) return false;
  return true;
}

describe("Groth16VerifyingKey round-trip", () => {
  const raw = readVector("vk.mol.bin");
  const vk = new Groth16VerifyingKey(raw);

  it("decodes to the expected wire shape", () => {
    expect(vk.getVersion().toLittleEndianUint16()).toBe(WIRE_VERSION);

    const content = vk.getContent();
    expect(content.unionType()).toBe("VerifyingKeyBn254");

    const bn254 = content.value();
    expect(bn254.getAlphaG1().raw().byteLength).toBe(32);
    expect(bn254.getBetaG2().raw().byteLength).toBe(64);
    expect(bn254.getGammaG2().raw().byteLength).toBe(64);
    expect(bn254.getDeltaG2().raw().byteLength).toBe(64);
    // SquareCircuit has 1 public input, so IC has N+1 = 2 entries.
    expect(bn254.getGammaAbcG1().length()).toBe(2);
    expect(bn254.getGammaAbcG1().indexAt(0).raw().byteLength).toBe(32);
  });

  it("re-encodes byte-for-byte from accessor output", () => {
    const bn254 = vk.getContent().value();
    const ic: ArrayBuffer[] = [];
    for (let i = 0; i < bn254.getGammaAbcG1().length(); i++) {
      ic.push(bn254.getGammaAbcG1().indexAt(i).raw());
    }

    const reEncoded = SerializeGroth16VerifyingKey({
      version: vk.getVersion().raw(),
      content: {
        type: "VerifyingKeyBn254",
        value: {
          alpha_g1: bn254.getAlphaG1().raw(),
          beta_g2: bn254.getBetaG2().raw(),
          gamma_g2: bn254.getGammaG2().raw(),
          delta_g2: bn254.getDeltaG2().raw(),
          gamma_abc_g1: ic,
        },
      },
    });

    expect(bytesEqual(reEncoded, raw)).toBe(true);
  });
});

describe("Groth16Witness round-trip", () => {
  const raw = readVector("witness.mol.bin");
  const witness = new Groth16Witness(raw);

  it("decodes to the expected wire shape", () => {
    expect(witness.getVersion().toLittleEndianUint16()).toBe(WIRE_VERSION);

    const content = witness.getContent();
    expect(content.unionType()).toBe("Bn254Witness");

    const bn254 = content.value();
    const proof = bn254.getProof();
    expect(proof.getA().raw().byteLength).toBe(32);
    expect(proof.getB().raw().byteLength).toBe(64);
    expect(proof.getC().raw().byteLength).toBe(32);

    // SquareCircuit has 1 public input (y).
    expect(bn254.getPublicInputs().length()).toBe(1);
    expect(bn254.getPublicInputs().indexAt(0).raw().byteLength).toBe(32);
  });

  it("re-encodes byte-for-byte from accessor output", () => {
    const bn254 = witness.getContent().value();
    const proof = bn254.getProof();
    const pi: ArrayBuffer[] = [];
    for (let i = 0; i < bn254.getPublicInputs().length(); i++) {
      pi.push(bn254.getPublicInputs().indexAt(i).raw());
    }

    const reEncoded = SerializeGroth16Witness({
      version: witness.getVersion().raw(),
      content: {
        type: "Bn254Witness",
        value: {
          proof: {
            a: proof.getA().raw(),
            b: proof.getB().raw(),
            c: proof.getC().raw(),
          },
          public_inputs: pi,
        },
      },
    });

    expect(bytesEqual(reEncoded, raw)).toBe(true);
  });
});
