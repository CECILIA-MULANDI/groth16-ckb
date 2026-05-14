import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";

import {
  decodeVerifyingKey,
  decodeWitness,
  encodeWitnessArgs,
  verifierTypeScript,
  type VerifyingKey,
  type Witness,
} from "../../../sdk/ts/src/index.js";

// ---- Tx 1: create the trigger cell that the verifier sits on top of -----

export interface BuildCreateTriggerTxInput {
  /** Lock placed on the trigger cell — controls who can later spend it. */
  triggerLock: ccc.ScriptLike;

  /** OutPoint of the deployed verifier binary. */
  verifierCodeOutPoint: ccc.OutPointLike;

  /** data_hash of the verifier binary (goes into the trigger cell's type script codeHash). */
  verifierCodeHash: Uint8Array;
  /** Hash type — typically "data1" for a code cell matched by data_hash. */
  verifierHashType: ccc.HashType;

  /** The verifying key the trigger cell commits to. */
  vk: VerifyingKey;

  /** Capacity for the trigger cell (in shannons). */
  triggerCapacity: bigint;
}

/**
 * Build Tx 1 of the two-tx verification flow: create a trigger cell whose
 * type script is the verifier bound to `vk`. The verifier runs at creation,
 * sees no `Source::GroupInput`, and permits creation without requiring a
 * proof. The cell is now an open verification slot.
 *
 * No inputs are set — the caller is expected to run `completeInputsByCapacity`
 * + `completeFeeBy` on the returned transaction to pick funding cells from
 * the signer's wallet. No VK cell_dep is included either: the verifier
 * early-exits at creation before loading the VK, so the VK can even be
 * deployed *after* this tx.
 */
export function buildCreateTriggerTx(
  input: BuildCreateTriggerTxInput,
): ccc.Transaction {
  const typeScript = verifierTypeScript({
    codeHash: input.verifierCodeHash,
    hashType: input.verifierHashType,
    vk: input.vk,
  });

  return ccc.Transaction.from({
    cellDeps: [{ outPoint: input.verifierCodeOutPoint, depType: "code" }],
    outputs: [
      {
        capacity: input.triggerCapacity,
        lock: input.triggerLock,
        type: typeScript,
      },
    ],
    outputsData: ["0x"],
  });
}

// ---- Tx 2: spend the trigger cell, supplying the proof ------------------

export interface BuildVerifyTxInput {
  /** OutPoint of the trigger cell created by `buildCreateTriggerTx`. */
  triggerOutPoint: ccc.OutPointLike;

  /** OutPoint of the deployed verifier binary. */
  verifierCodeOutPoint: ccc.OutPointLike;
  /** OutPoint of the deployed VK cell (must match the trigger's type script args). */
  vkCellOutPoint: ccc.OutPointLike;

  /** Where the recovered capacity goes after the trigger cell is consumed. */
  outputLock: ccc.ScriptLike;
  /** Capacity of the output cell (in shannons). */
  outputCapacity: bigint;

  /** Proof + public inputs to verify. */
  witness: Witness;
}

/**
 * Build Tx 2 of the two-tx flow: spend the trigger cell, triggering the
 * on-chain verifier. The verifier runs on the input side, finds the VK by
 * matching `args == data_hash(vk_cell.data)`, decodes the proof from
 * `WitnessArgs.input_type[0]`, and accepts iff the pairing check passes.
 */
export function buildVerifyTx(input: BuildVerifyTxInput): ccc.Transaction {
  return ccc.Transaction.from({
    cellDeps: [
      { outPoint: input.verifierCodeOutPoint, depType: "code" },
      { outPoint: input.vkCellOutPoint, depType: "code" },
    ],
    inputs: [{ previousOutput: input.triggerOutPoint, since: 0 }],
    outputs: [
      {
        capacity: input.outputCapacity,
        lock: input.outputLock,
      },
    ],
    outputsData: ["0x"],
    witnesses: [encodeWitnessArgs(input.witness)],
  });
}

// ---- Dry-run main entry -------------------------------------------------

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = resolve(HERE, "../../../test_vectors");

function readBytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(resolve(VECTORS, name)));
}

// Print both transactions of the verification flow against placeholder
// OutPoints. Useful for inspecting the wire shape before deploying for real.
function main(): void {
  const vk = decodeVerifyingKey(readBytes("vk.mol.bin"));
  const witness = decodeWitness(readBytes("witness.mol.bin"));

  const placeholderHash = (n: number): Uint8Array => new Uint8Array(32).fill(n);
  const placeholderOutPoint = (n: number): ccc.OutPointLike => ({
    txHash: placeholderHash(n),
    index: 0,
  });

  const SECP256K1_CODE_HASH =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
  const userLock: ccc.ScriptLike = {
    codeHash: SECP256K1_CODE_HASH,
    hashType: "type",
    args: new Uint8Array(20),
  };

  const create = buildCreateTriggerTx({
    triggerLock: userLock,
    verifierCodeOutPoint: placeholderOutPoint(0x22),
    verifierCodeHash: placeholderHash(0xaa),
    verifierHashType: "data1",
    vk,
    triggerCapacity: 150_00_000_000n, // 150 CKB
  });

  const verify = buildVerifyTx({
    triggerOutPoint: placeholderOutPoint(0x55), // hash of create tx, output 0
    verifierCodeOutPoint: placeholderOutPoint(0x22),
    vkCellOutPoint: placeholderOutPoint(0x33),
    outputLock: userLock,
    outputCapacity: 149_50_000_000n, // 149.5 CKB, 0.5 CKB as fee
    witness,
  });

  const fmt = (tx: ccc.Transaction) =>
    JSON.stringify(tx, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2);

  console.log("// Tx 1 — create trigger cell");
  console.log(fmt(create));
  console.log("\n// Tx 2 — spend trigger cell, runs the verifier");
  console.log(fmt(verify));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
