// One-time demo setup: grants an unlimited WETH approval FROM the
// KeeperHub-managed wallet TO a clearly-labeled synthetic "attacker"
// address, via execute_contract_call. Exists because that wallet has no
// MetaMask key we hold -- KeeperHub's Turnkey integration is the only
// signer, so the "attacker approves a spender" step MetaMask did by hand
// before has to go through KeeperHub itself now.
//
// Uses the same executeContractCall/pollExecution path responder.mjs uses
// for real revocations, not a hand-rolled call -- if this script's approve()
// succeeds, the abi/function_args stringification fixes are proven live
// before the detection+response flow depends on them for real.
//
// Usage: node scripts/plant-approval.mjs
// Needs: KEEPERHUB_API_KEY in env. CHAIN_ID optional (defaults Sepolia).

import { KeeperHubClient, executeContractCall, pollExecution } from '../src/keeperhub.mjs';
import { loadConfig } from '../src/config.mjs';

const WETH_SEPOLIA = '0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14';
// Repeating hex pattern -- deliberately not a hand-typed address, so it's
// unambiguous at a glance in logs/Etherscan that this is a synthetic demo
// spender, not a transcription error. No private key needed: this script
// only ever calls approve(), never transferFrom, so nothing needs to
// actually control this address for the demo to work.
const ATTACKER_ADDRESS = '0x' + 'a1'.repeat(20);
const MAX_UINT256 = ((1n << 256n) - 1n).toString();

const APPROVE_ABI = {
  name: 'approve',
  type: 'function',
  stateMutability: 'nonpayable',
  inputs: [
    { name: 'spender', type: 'address' },
    { name: 'amount', type: 'uint256' },
  ],
  outputs: [{ name: '', type: 'bool' }],
};

const cfg = loadConfig();
if (!cfg.keeperHub.apiKey) {
  console.error('KEEPERHUB_API_KEY is not set');
  process.exit(1);
}

console.log('Planting unlimited WETH approval via KeeperHub:');
console.log(`  token:   ${WETH_SEPOLIA}`);
console.log(`  spender: ${ATTACKER_ADDRESS}  (synthetic demo address, no real key)`);
console.log(`  amount:  MAX_UINT256 (unlimited)`);
console.log(`  chain:   ${cfg.chainId}`);
console.log('  signer:  whichever wallet integration is connected to this API key\n');

const client = new KeeperHubClient(cfg.keeperHub);

const submitted = await executeContractCall(client, {
  chain: cfg.chainId,
  to: WETH_SEPOLIA,
  abiFragment: APPROVE_ABI,
  args: [ATTACKER_ADDRESS, MAX_UINT256],
  idempotencyKey: `plant-approval:${WETH_SEPOLIA}:${ATTACKER_ADDRESS}`,
});

console.log('Submitted:', JSON.stringify(submitted, null, 2));

if (!submitted.executionId) {
  console.log('\nNo execution id returned -- treating the submit response as final.');
  process.exit(submitted.txHash ? 0 : 1);
}

console.log(`\nPolling execution ${submitted.executionId} ...`);
const final = await pollExecution(client, submitted.executionId, {
  intervalMs: cfg.keeperHub.pollIntervalMs,
  timeoutMs: cfg.keeperHub.pollTimeoutMs,
});

console.log('\nFinal result:', JSON.stringify(final, null, 2));
if (final.txHash) {
  console.log(`\nExplorer: ${final.explorerUrl || `https://sepolia.etherscan.io/tx/${final.txHash}`}`);
  console.log('\nApproval planted. Next: point WATCHED_WALLET at the KeeperHub wallet and restart the watcher.');
  process.exit(0);
} else {
  console.error('\nFAILED -- no txHash in final result. Do not proceed to re-arming until this succeeds.');
  process.exit(1);
}
