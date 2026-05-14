import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { describe, expect, it } from "vitest";

import {
  decodeVerifyingKey,
  decodeWitness,
  encodeWitness,
  verifyingKeyDataHash,
} from "../../../sdk/ts/src/index.js";
import {
  buildCreateTriggerTx,
  buildVerifyTx,
} from "../src/build-verify-tx.js";

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

const placeholderHash = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const userLock = {
  codeHash: placeholderHash(0xcc),
  hashType: "type" as const,
  args: new Uint8Array(20),
};

describe("buildCreateTriggerTx (Tx 1)", () => {
  const vk = decodeVerifyingKey(readBytes("vk.mol.bin"));

  function fixture() {
    return buildCreateTriggerTx({
      triggerLock: userLock,
      verifierCodeOutPoint: { txHash: placeholderHash(0x22), index: 0 },
      verifierCodeHash: placeholderHash(0xaa),
      verifierHashType: "data1" as const,
      vk,
      triggerCapacity: 150_00_000_000n,
    });
  }

  it("includes only the verifier code as a cell_dep (VK not needed at creation)", () => {
    const tx = fixture();
    expect(tx.cellDeps).toHaveLength(1);
    expect(tx.cellDeps[0]!.depType).toBe("code");
  });

  it("creates one output bearing the verifier type script with args = VK data_hash", () => {
    const tx = fixture();
    expect(tx.outputs).toHaveLength(1);
    const typeScript = tx.outputs[0]!.type!;
    expect(typeScript).toBeDefined();
    expect(bytesEqual(ccc.bytesFrom(typeScript.args), verifyingKeyDataHash(vk))).toBe(true);
  });

  it("leaves inputs empty so CCC can collect funding cells", () => {
    const tx = fixture();
    expect(tx.inputs).toHaveLength(0);
  });
});

describe("buildVerifyTx (Tx 2: spend trigger cell)", () => {
  const witness = decodeWitness(readBytes("witness.mol.bin"));

  function fixture() {
    return buildVerifyTx({
      triggerOutPoint: { txHash: placeholderHash(0x55), index: 0 },
      verifierCodeOutPoint: { txHash: placeholderHash(0x22), index: 0 },
      vkCellOutPoint: { txHash: placeholderHash(0x33), index: 0 },
      outputLock: userLock,
      outputCapacity: 149_50_000_000n,
      witness,
    });
  }

  it("has 2 cell_deps (verifier code + VK cell)", () => {
    const tx = fixture();
    expect(tx.cellDeps).toHaveLength(2);
    expect(tx.cellDeps[0]!.depType).toBe("code");
    expect(tx.cellDeps[1]!.depType).toBe("code");
  });

  it("spends the trigger cell (verifier sits on the input, not the output)", () => {
    const tx = fixture();
    expect(tx.inputs).toHaveLength(1);
    expect(bytesEqual(
      ccc.bytesFrom(tx.inputs[0]!.previousOutput.txHash),
      placeholderHash(0x55),
    )).toBe(true);

    // Output is a fresh capacity-returning cell with no type script.
    expect(tx.outputs).toHaveLength(1);
    expect(tx.outputs[0]!.type).toBeUndefined();
  });

  it("places the encoded witness in WitnessArgs.input_type at index 0", () => {
    const tx = fixture();
    expect(tx.witnesses).toHaveLength(1);
    const witnessArgs = ccc.WitnessArgs.fromBytes(tx.witnesses[0]!);
    expect(witnessArgs.lock).toBeUndefined();
    expect(witnessArgs.outputType).toBeUndefined();
    expect(bytesEqual(
      ccc.bytesFrom(witnessArgs.inputType!),
      encodeWitness(witness),
    )).toBe(true);
  });
});
