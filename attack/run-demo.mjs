// End-to-end attack/defense race. Doubles as the integration test and the
// demo-video script (per Phase 6 spec) -- exits nonzero if the drainer ever
// succeeds.
//
// Assumes Deplex (node src/watcher.mjs) is ALREADY RUNNING as a separate,
// long-running process watching the same WATCHED_WALLET. This script only
// plays the attacker's side: plant a malicious approval through KeeperHub
// (the demo wallet is KeeperHub-controlled, so that's the only way to sign
// from it -- see docs/FAILURE-MODES.md), wait, then attempt to drain with an
// independent throwaway key, and report both outcomes side by side.
//
// Usage: node attack/run-demo.mjs
// Needs: same env as the watcher (RPC_URL, WATCHED_WALLET, KEEPERHUB_API_KEY,
// CHAIN_ID) plus SAFE_ADDRESS if you want to see the delay=0 EVACUATE
// fallback path resolve. Optional: ATTACK_DELAY_MS (default 25000),
// ATTACK_NFT_CONTRACT (enables the every-6th-run NFT vector).
//
// ATTACK_DELAY_MS=0 is a DELIBERATE loss test for the "drainer wins"
// fallback (see docs/FAILURE-MODES.md timing model): with no delay, the
// drainer very likely succeeds before Deplex's next poll cycle, which is
// the expected, correct outcome for that specific scenario -- a nonzero
// exit in that mode confirms the drainer won, not that this script is
// broken. Use a realistic delay (the default) for an actual demo run.

import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadConfig, assertRuntimeConfig } from '../src/config.mjs';
import { KeeperHubClient } from '../src/keeperhub.mjs';
import { readAll } from '../src/auditlog.mjs';
import { rpcCallWithRetry } from '../src/watcher.mjs';
import {
  generateAttackerKey,
  ensureWethBalance,
  ensureAttackerGas,
  plantApproval,
  plantNftApproval,
  attemptDrain,
  attemptNftDrain,
  isNftVectorAvailable,
  getAllowance,
  getIsApprovedForAll,
  WETH_SEPOLIA,
} from './drainer.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const RUN_COUNT_FILE = join(__dirname, '.run-count.json');
const NFT_VECTOR_INTERVAL = 6;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function nextRunNumber() {
  let count = 0;
  if (existsSync(RUN_COUNT_FILE)) {
    try {
      count = JSON.parse(readFileSync(RUN_COUNT_FILE, 'utf8')).count ?? 0;
    } catch {
      count = 0;
    }
  }
  count += 1;
  const tmp = `${RUN_COUNT_FILE}.tmp`;
  writeFileSync(tmp, JSON.stringify({ count }));
  renameSync(tmp, RUN_COUNT_FILE);
  return count;
}

// Polls the audit log for the EXECUTION_RESULT that resolves `target.key`
// under `actionType`, appearing after `sinceTs`. Returns null on timeout
// rather than throwing -- "Deplex didn't respond in time" is itself a valid,
// reportable demo outcome, not a script error.
async function waitForDeplexExecution(cfg, { actionType, targetKey, sinceTs, timeoutMs = 90_000, pollMs = 2000 }) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const records = readAll(cfg.auditLogPath);
    const hit = records.find(
      (r) => r.type === 'EXECUTION_RESULT' && r.payload?.actionType === actionType && r.payload?.target?.key === targetKey && r.ts >= sinceTs,
    );
    if (hit) return hit.payload;
    await sleep(pollMs);
  }
  return null;
}

async function blockNumberForTx(cfg, txHash) {
  const receipt = await rpcCallWithRetry(cfg.rpcUrl, 'eth_getTransactionReceipt', [txHash], cfg);
  return receipt ? parseInt(receipt.blockNumber, 16) : null;
}

async function runErc20Vector(cfg, client, { delayMs }) {
  console.log(`\n[setup] ensuring the demo wallet holds WETH to drain (so a block is "insufficient allowance", not "insufficient balance")`);
  const wethSetup = await ensureWethBalance(client, cfg);
  console.log(`[setup] WETH: ${wethSetup.wrapped ? `wrapped ${wethSetup.amount} wei` : `already held ${wethSetup.balance} wei`}`);

  const attacker = generateAttackerKey();
  console.log(`[setup] attacker address (throwaway): ${attacker.address}`);

  console.log(`[setup] funding attacker with gas money (a raw self-signed tx needs its own ETH, regardless of what it's attacking)...`);
  const gasSetup = await ensureAttackerGas(client, cfg, attacker.address);
  console.log(`[setup] attacker gas: ${gasSetup.funded ? `funded ${gasSetup.amount} wei (tx ${gasSetup.result.txHash})` : `already had ${gasSetup.balance} wei`}`);

  const plantedAt = new Date().toISOString();
  console.log(`\n[attack] planting unlimited WETH approval via KeeperHub...`);
  const planted = await plantApproval(client, cfg, { spenderAddress: attacker.address, tokenAddress: WETH_SEPOLIA });
  console.log(`[attack] approval planted: ${planted.txHash}`);
  console.log(`[attack] Deplex (if running) should now be racing to detect + revoke this.`);

  console.log(`\n[attack] waiting ${delayMs}ms before attempting the drain...`);
  const drainResult = await attemptDrain(cfg, {
    attackerPrivateKeyHex: attacker.privateKeyHex,
    attackerAddress: attacker.address,
    tokenAddress: WETH_SEPOLIA,
    demoWalletAddress: cfg.watchedWallet,
    delayMs,
  });

  const targetKey = `${WETH_SEPOLIA.toLowerCase()}:${attacker.address.toLowerCase()}`;
  const deplexResult = await waitForDeplexExecution(cfg, { actionType: 'REVOKE', targetKey, sinceTs: plantedAt });

  return {
    drainResult,
    deplexResult,
    vector: 'erc20-approve',
    tokenAddress: WETH_SEPOLIA,
    attackerAddress: attacker.address,
    demoWalletAddress: cfg.watchedWallet,
  };
}

async function runNftVector(cfg, client, { delayMs }) {
  const attacker = generateAttackerKey();
  console.log(`[setup] NFT vector active (ATTACK_NFT_CONTRACT=${cfg.attackNftContract})`);
  console.log(`[setup] attacker address (throwaway): ${attacker.address}`);
  console.log(
    `[setup] NOTE: unlike the ERC-20 vector, token ownership on this contract isn't verified here -- ` +
      `a reverted drain could mean "insufficient allowance" (Deplex won) OR an unrelated ownership issue. ` +
      `See docs/ONBOARDING-TEARDOWN.md.`,
  );

  console.log(`[setup] funding attacker with gas money (a raw self-signed tx needs its own ETH, regardless of what it's attacking)...`);
  const gasSetup = await ensureAttackerGas(client, cfg, attacker.address);
  console.log(`[setup] attacker gas: ${gasSetup.funded ? `funded ${gasSetup.amount} wei (tx ${gasSetup.result.txHash})` : `already had ${gasSetup.balance} wei`}`);

  const plantedAt = new Date().toISOString();
  console.log(`\n[attack] planting NFT operator approval (setApprovalForAll) via KeeperHub...`);
  const planted = await plantNftApproval(client, cfg, { operatorAddress: attacker.address });
  console.log(`[attack] approval planted: ${planted.txHash}`);

  console.log(`\n[attack] waiting ${delayMs}ms before attempting the drain...`);
  const drainResult = await attemptNftDrain(cfg, {
    attackerPrivateKeyHex: attacker.privateKeyHex,
    attackerAddress: attacker.address,
    demoWalletAddress: cfg.watchedWallet,
    tokenId: process.env.ATTACK_NFT_TOKEN_ID || '0',
    delayMs,
  });

  const targetKey = `${cfg.attackNftContract.toLowerCase()}:${attacker.address.toLowerCase()}`;
  const deplexResult = await waitForDeplexExecution(cfg, { actionType: 'REVOKE', targetKey, sinceTs: plantedAt });

  return {
    drainResult,
    deplexResult,
    vector: 'nft-approvalForAll',
    tokenAddress: cfg.attackNftContract,
    attackerAddress: attacker.address,
    demoWalletAddress: cfg.watchedWallet,
    isNft: true,
  };
}

async function main() {
  const cfg = loadConfig();
  assertRuntimeConfig(cfg);
  if (!cfg.keeperHub.apiKey) throw new Error('KEEPERHUB_API_KEY is not set -- plantApproval requires it');

  const delayMs = Number(process.env.ATTACK_DELAY_MS ?? 25_000);
  const runNumber = nextRunNumber();
  const useNftVector = runNumber % NFT_VECTOR_INTERVAL === 0;

  console.log(`=== Deplex attack demo -- run #${runNumber} ===`);
  console.log(`watched wallet: ${cfg.watchedWallet}`);
  console.log(`ATTACK_DELAY_MS: ${delayMs}${delayMs === 0 ? '  (deliberate loss test -- see file header)' : ''}`);

  let vectorResult;
  if (useNftVector && isNftVectorAvailable(cfg)) {
    console.log(`vector: NFT ApprovalForAll (every ${NFT_VECTOR_INTERVAL}th run)`);
    vectorResult = await runNftVector(cfg, new KeeperHubClient(cfg.keeperHub), { delayMs });
  } else {
    if (useNftVector && !isNftVectorAvailable(cfg)) {
      console.log(`vector: run #${runNumber} would use the NFT vector, but ATTACK_NFT_CONTRACT is not set -- falling back to ERC-20`);
    } else {
      console.log(`vector: ERC-20 unlimited approve()`);
    }
    vectorResult = await runErc20Vector(cfg, new KeeperHubClient(cfg.keeperHub), { delayMs });
  }

  const { drainResult, deplexResult, vector, tokenAddress, attackerAddress, demoWalletAddress, isNft } = vectorResult;

  console.log(`\n=== Outcome (vector: ${vector}) ===`);
  if (drainResult.reverted) {
    console.log(`DRAINER: REVERTED at block ${drainResult.blockNumber}  (tx ${drainResult.txHash})`);
  } else {
    console.log(`DRAINER: SUCCEEDED at block ${drainResult.blockNumber}  (tx ${drainResult.txHash})  <-- Deplex lost the race`);
  }

  if (deplexResult?.txHash) {
    const block = await blockNumberForTx(cfg, deplexResult.txHash);
    console.log(`DEPLEX:  REVOKED at block ${block}  (tx ${deplexResult.txHash}, status ${deplexResult.status})`);
  } else if (deplexResult) {
    console.log(`DEPLEX:  attempted, status ${deplexResult.status} (no txHash)`);
  } else {
    console.log(`DEPLEX:  no matching REVOKE found in the audit log within the wait window -- is the watcher running?`);
  }

  if (!drainResult.reverted) {
    if (delayMs === 0) {
      console.log(`\n[fallback check] drainer won as expected at delay=0 -- checking whether Deplex evacuates the remainder...`);
      const evacuated = await waitForDeplexExecution(cfg, {
        actionType: 'EVACUATE',
        targetKey: 'native', // best-effort; ERC-20 evacuation legs use token-keyed targets instead
        sinceTs: new Date().toISOString(),
        timeoutMs: 60_000,
      });
      console.log(evacuated ? `[fallback check] EVACUATE observed -- fallback behavior confirmed.` : `[fallback check] no EVACUATE observed within the wait window.`);
    }
    console.error(`\nFAILED: the drainer succeeded. Deplex did not win the race.`);
    process.exit(1);
  }

  // A revert alone doesn't prove Deplex won the race: the audit-log check
  // above depends on the watcher process actually being up (it can be
  // silently absent), and the drain reverting could in principle have
  // another cause. Ground truth is the token contract's own state -- did
  // the allowance/operator-approval this attack planted actually get
  // cleared? WETH9 (and many older ERC-20s) revert with NO reason string at
  // all, so this on-chain check, not the revert reason, is what makes
  // PASSED mean something.
  console.log(`\n[verify] checking on-chain ${isNft ? 'operator approval' : 'allowance'} state directly (ground truth, independent of the audit log)...`);
  const stillApproved = isNft
    ? await getIsApprovedForAll(cfg, tokenAddress, demoWalletAddress, attackerAddress)
    : (await getAllowance(cfg, tokenAddress, demoWalletAddress, attackerAddress)) !== '0';

  if (stillApproved) {
    console.error(
      `\nINCONCLUSIVE: the drain reverted, but the ${isNft ? 'operator approval is still active' : 'allowance is still nonzero'} on-chain -- ` +
        `the revert was NOT caused by a revocation. Something else blocked it (wrong balance assumption, gas issue, etc). Do not treat this as Deplex winning.`,
    );
    process.exit(1);
  }

  console.log(`[verify] confirmed: ${isNft ? 'operator approval is now cleared' : 'allowance is now 0'} on-chain.`);
  console.log(`\nPASSED: the drainer was blocked, and the block is confirmed caused by a revocation (not an unrelated failure).`);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
