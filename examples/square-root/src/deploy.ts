import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";

import { decodeVerifyingKey } from "../../../sdk/ts/src/index.js";
import { buildCreateTriggerTx } from "./build-verify-tx.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../..");
const ARTIFACTS = resolve(HERE, "../artifacts");

export interface DeployedCell {
  txHash: ccc.Hex;
  index: number;
  /** data_hash of the cell's data — meaningful for code cells and the VK cell. */
  dataHash: ccc.Hex;
}

/**
 * Build, sign, and submit a transaction that publishes `data` as the data of
 * a new cell, with the signer's own lock. Returns the OutPoint of the new
 * cell plus its `data_hash`.
 */
export async function deployDataCell(
  signer: ccc.SignerCkbPrivateKey,
  data: Uint8Array,
): Promise<DeployedCell> {
  const { script: lock } = await signer.getRecommendedAddressObj();

  const tx = ccc.Transaction.from({
    outputs: [{ lock }], // capacity auto-computed when outputData is provided
    outputsData: [data],
  });

  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer);

  const txHash = await signer.sendTransaction(tx);
  return { txHash, index: 0, dataHash: ccc.hashCkb(data) };
}

interface TriggerArtifact {
  txHash: ccc.Hex;
  index: number;
  /** Hash of the type script committed at this OutPoint — useful for sanity-checking the spend tx. */
  typeScriptHash: ccc.Hex;
}

/**
 * Create a trigger cell: an empty cell whose type script is the verifier
 * bound to `vk.mol.bin`. The verifier permits creation freely; the cell sits
 * on chain until someone calls verify.ts to spend it with a proof.
 */
export async function deployTriggerCell(
  signer: ccc.SignerCkbPrivateKey,
  vkBytes: Uint8Array,
  verifierCode: DeployedCell,
): Promise<TriggerArtifact> {
  const { script: triggerLock } = await signer.getRecommendedAddressObj();
  const vk = decodeVerifyingKey(vkBytes);

  const tx = buildCreateTriggerTx({
    triggerLock,
    verifierCodeOutPoint: { txHash: verifierCode.txHash, index: verifierCode.index },
    verifierCodeHash: ccc.bytesFrom(verifierCode.dataHash),
    verifierHashType: "data1",
    vk,
    // Provisional capacity — CCC's completeFee will adjust output capacity to
    // cover the storage of the trigger cell + fee from collected inputs.
    triggerCapacity: 150_00_000_000n,
  });

  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer);

  const txHash = await signer.sendTransaction(tx);
  const typeScriptHash = tx.outputs[0]!.type!.hash();

  return { txHash, index: 0, typeScriptHash };
}

// ---- Loaders for deploy targets / artifacts -----------------------------

function loadVerifierBinary(): Uint8Array {
  // Built via scripts/build-ckb-script.sh — riscv64imac no_std ELF.
  const path = resolve(
    ROOT,
    "script/target/riscv64imac-unknown-none-elf/release/ckb-script",
  );
  return new Uint8Array(readFileSync(path));
}

function loadVk(): Uint8Array {
  return new Uint8Array(readFileSync(resolve(ROOT, "test_vectors/vk.mol.bin")));
}

function loadDeployedCell(name: string): DeployedCell {
  return JSON.parse(
    readFileSync(resolve(ARTIFACTS, `${name}.json`), "utf8"),
  ) as DeployedCell;
}

function writeArtifact(name: string, value: unknown): string {
  mkdirSync(ARTIFACTS, { recursive: true });
  const path = resolve(ARTIFACTS, `${name}.json`);
  writeFileSync(path, JSON.stringify(value, null, 2));
  return path;
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

// ---- CLI ----------------------------------------------------------------

async function main(): Promise<void> {
  const which = process.argv[2];
  if (which !== "verifier" && which !== "vk" && which !== "trigger") {
    throw new Error(
      `usage: pnpm deploy <verifier|vk|trigger>
  verifier  publish the on-chain script binary as a code cell
  vk        publish the Molecule-encoded VK as a data cell
  trigger   create a verifier-bound trigger cell (requires verifier already deployed)`,
    );
  }

  const client = new ccc.ClientPublicTestnet();
  const signer = new ccc.SignerCkbPrivateKey(client, privateKeyFromEnv());
  const address = await signer.getRecommendedAddress();

  if (which === "verifier") {
    const data = loadVerifierBinary();
    console.error(`Deploying verifier binary (${data.length} bytes) from ${address}…`);
    const result = await deployDataCell(signer, data);
    const out = writeArtifact("verifier-code", result);
    console.error(`Submitted ${result.txHash}, wrote ${out}`);
    console.log(JSON.stringify(result, null, 2));
  } else if (which === "vk") {
    const data = loadVk();
    console.error(`Deploying VK cell (${data.length} bytes) from ${address}…`);
    const result = await deployDataCell(signer, data);
    const out = writeArtifact("vk-cell", result);
    console.error(`Submitted ${result.txHash}, wrote ${out}`);
    console.log(JSON.stringify(result, null, 2));
  } else {
    const verifierCode = loadDeployedCell("verifier-code");
    const vkBytes = loadVk();
    console.error(`Creating trigger cell bound to vk.mol.bin from ${address}…`);
    const result = await deployTriggerCell(signer, vkBytes, verifierCode);
    const out = writeArtifact("trigger-cell", result);
    console.error(`Submitted ${result.txHash}, wrote ${out}`);
    console.log(JSON.stringify(result, null, 2));
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
