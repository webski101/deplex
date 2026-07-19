// Generates the throwaway EVM keypair Deplex uses to PAY for x402 intel
// purchases (src/intel.mjs's INTEL_PAYER_PRIVATE_KEY) -- distinct from
// attack/crypto.mjs's demo attacker key generation (attack/drainer.mjs's
// generateAttackerKey()), which is a different throwaway, different purpose,
// generated fresh on every attack-demo run. This key is meant to persist
// across a session (it needs to hold real, if only testnet, USDC) so it's
// written to a local file instead.
//
// Security: the private key is NEVER printed to stdout/stderr by this
// script, only written to INTEL_PAYER_ENV_FILE. Only public addresses are
// printed. Run this yourself, in your own terminal -- don't ask an agent
// session to run it and relay the output, since the file write itself is the
// only place the key value should ever exist outside the chain it eventually
// signs for.

import { randomBytes } from 'node:crypto';
import { writeFileSync, existsSync, chmodSync } from 'node:fs';
import { privateKeyToAddress, bytesToHex } from '../attack/crypto.mjs';

const OUT_FILE = process.env.INTEL_PAYER_ENV_FILE || '.env.intel-payer';

function freshKeypair() {
  const privateKeyHex = bytesToHex(randomBytes(32));
  const address = privateKeyToAddress(privateKeyHex); // already 0x-prefixed
  return { privateKeyHex, address };
}

if (existsSync(OUT_FILE)) {
  console.error(`${OUT_FILE} already exists -- refusing to overwrite an existing key.`);
  console.error(`Delete it yourself first if you deliberately want to rotate keys.`);
  process.exit(1);
}

const payer = freshKeypair();
const payTo = freshKeypair(); // recipient only -- no signing ever happens from this address

const lines = [
  `INTEL_PAYER_PRIVATE_KEY=${payer.privateKeyHex}`,
  `INTEL_AGENT_PAY_TO=${payTo.address}`,
  `# recipient private key, kept only so you can sweep received testnet funds later -- Deplex code never reads this:`,
  `INTEL_AGENT_PAYTO_PRIVATE_KEY=${payTo.privateKeyHex}`,
  '',
].join('\n');

writeFileSync(OUT_FILE, lines);
try {
  chmodSync(OUT_FILE, 0o600); // best-effort; Windows/NTFS won't fully honor this, see the runbook
} catch {
  // chmod not meaningful on this filesystem -- fine, ignore
}

console.log(`Wrote ${OUT_FILE} (private keys inside, never printed here).`);
console.log(``);
console.log(`Payer address (fund THIS one with Base Sepolia USDC):`);
console.log(`  ${payer.address}`);
console.log(``);
console.log(`Recipient / INTEL_AGENT_PAY_TO address (needs no funding, just receives payment):`);
console.log(`  ${payTo.address}`);
console.log(``);
console.log(`Next: run the server and client with`);
console.log(`  node --env-file=${OUT_FILE} intel-agent/server.mjs`);
console.log(`so the private keys load straight from the file into that process only --`);
console.log(`never typed, exported, or echoed in this terminal.`);
