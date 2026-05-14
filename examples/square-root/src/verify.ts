import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";

import { decodeWitness } from "../../../sdk/ts/src/index.js";
import { buildVerifyTx } from "./build-verify-tx.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../..");
const ARTIFACTS = resolve(HERE, "../artifacts");

interface DeployedCell {
  txHash: ccc.Hex;
  index: number;
  dataHash: ccc.Hex;
}

interface TriggerArtifact {
  txHash: ccc.Hex;
  index: number;
  typeScriptHash: ccc.Hex;
}

function loadArtifact<T>(name: string): T {
  return JSON.parse(
    readFileSync(resolve(ARTIFACTS, `${name}.json`), "utf8"),
  ) as T;
}

function loadWitnessBytes(): Uint8Array {
  return new Uint8Array(
    readFileSync(resolve(ROOT, "test_vectors/witness.mol.bin")),
  );
}

function privateKeyFromEnv(): string {
  const pk = process.env.CKB_PRIVATE_KEY;
  if (!pk) {
    throw new Error(
      "CKB_PRIVATE_KEY env var is required — a 0x-prefixed 32-byte hex secret " +
        "for a funded testnet address. Do NOT commit it.",
    );
  }
  return pk;
}

async function main(): Promise<void> {
  const verifierCode = loadArtifact<DeployedCell>("verifier-code");
  const vkCell = loadArtifact<DeployedCell>("vk-cell");
  const trigger = loadArtifact<TriggerArtifact>("trigger-cell");
  const witness = decodeWitness(loadWitnessBytes());

  const client = new ccc.ClientPublicTestnet();
  const signer = new ccc.SignerCkbPrivateKey(client, privateKeyFromEnv());
  const { script: outputLock } = await signer.getRecommendedAddressObj();

  // Recover the trigger cell's capacity (minus fee) into a fresh cell of the
  // user's lock. Use the trigger's storage-required capacity as a starting
  // point — completeFeeBy will reduce by the fee.
  const triggerLive = await client.getCell({
    txHash: trigger.txHash,
    index: trigger.index,
  });
  if (!triggerLive) {
    throw new Error(
      `trigger cell ${trigger.txHash}#${trigger.index} not found on chain — was it spent already?`,
    );
  }
  const triggerCapacity = triggerLive.cellOutput.capacity;

  const tx = buildVerifyTx({
    triggerOutPoint: { txHash: trigger.txHash, index: trigger.index },
    verifierCodeOutPoint: { txHash: verifierCode.txHash, index: verifierCode.index },
    vkCellOutPoint: { txHash: vkCell.txHash, index: vkCell.index },
    outputLock,
    // Leave a small head-room for the fee; completeFeeBy will trim further.
    outputCapacity: triggerCapacity - 10_00_000_000n,
    witness,
  });

  await tx.completeFeeBy(signer);

  const txHash = await signer.sendTransaction(tx);
  console.error(`Submitted verification tx ${txHash}`);
  console.log(txHash);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
