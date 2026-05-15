import { randomBytes } from "node:crypto";
import { ccc } from "@ckb-ccc/core";

async function main(): Promise<void> {
  const privateKey = `0x${randomBytes(32).toString("hex")}` as ccc.Hex;
  const client = new ccc.ClientPublicTestnet();
  const signer = new ccc.SignerCkbPrivateKey(client, privateKey);
  const address = await signer.getRecommendedAddress();

  console.log(`private_key: ${privateKey}`);
  console.log(`address:     ${address}`);
  console.log("");
  console.log("Next steps:");
  console.log(`  1. Paste the address into https://faucet.nervos.org/`);
  console.log(`  2. Export CKB_PRIVATE_KEY=${privateKey}`);
  console.log(`  3. pnpm deploy verifier  # once funds land`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
