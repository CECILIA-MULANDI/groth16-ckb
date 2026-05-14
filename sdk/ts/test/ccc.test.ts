import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { describe, expect, it } from "vitest";

import {
  decodeVerifyingKey,
  decodeWitness,
  encodeWitness,
  encodeWitnessArgs,
  verifierTypeScript,
  verifyingKeyDataHash,
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

describe("encodeWitnessArgs", () => {
  const w = decodeWitness(readBytes("witness.mol.bin"));

  it("decoded WitnessArgs.inputType matches the raw encoded witness", () => {
    const witnessArgsBytes = encodeWitnessArgs(w);
    const parsed = ccc.WitnessArgs.fromBytes(witnessArgsBytes);

    expect(parsed.lock).toBeUndefined();
    expect(parsed.outputType).toBeUndefined();
    expect(parsed.inputType).toBeDefined();

    const innerWitness = ccc.bytesFrom(parsed.inputType!);
    expect(bytesEqual(innerWitness, encodeWitness(w))).toBe(true);
  });
});

describe("verifierTypeScript", () => {
  const vk = decodeVerifyingKey(readBytes("vk.mol.bin"));
  const codeHash = new Uint8Array(32).fill(0xab); // placeholder for a real deploy
  const expectedArgs = readBytes("vk_data_hash.bin");

  it("sets args to the VK data_hash", () => {
    const script = verifierTypeScript({ codeHash, hashType: "data1", vk });
    expect(bytesEqual(ccc.bytesFrom(script.args), expectedArgs)).toBe(true);
    expect(script.hashType).toBe("data1");
    expect(bytesEqual(ccc.bytesFrom(script.codeHash), codeHash)).toBe(true);
  });

  it("args matches verifyingKeyDataHash(vk) independently", () => {
    const script = verifierTypeScript({ codeHash, hashType: "data1", vk });
    expect(bytesEqual(ccc.bytesFrom(script.args), verifyingKeyDataHash(vk))).toBe(
      true,
    );
  });

  it("changes args when the VK changes", () => {
    const flipped = new Uint8Array(vk.alphaG1);
    flipped[0] ^= 0x01;
    const scriptA = verifierTypeScript({ codeHash, hashType: "data1", vk });
    const scriptB = verifierTypeScript({
      codeHash,
      hashType: "data1",
      vk: { ...vk, alphaG1: flipped },
    });
    expect(
      bytesEqual(ccc.bytesFrom(scriptA.args), ccc.bytesFrom(scriptB.args)),
    ).toBe(false);
  });
});
