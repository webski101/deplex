// attack simulator for the demo
//
// Two actors, two different signing paths -- deliberately, matching what we
// learned building Phase 3: KeeperHub can only sign from a wallet it/you
// control (see docs/FAILURE-MODES.md), so the "demo wallet" granting a
// malicious approval has to go through KeeperHub itself (plantApproval,
// reusing scripts/plant-approval.mjs's proven pattern), while the
// "attacker" attempting to drain it is a genuinely independent throwaway
// key we sign raw transactions with directly (attack/crypto.mjs) -- the ONE
// place in this project a raw private key is used, and it never controls
// anything but a fresh, empty, disposable address.
//
// That throwaway key DOES need its own ETH for gas, though -- signing a
// transaction costs nothing, but a real EOA broadcasting one to the network
// pays gas regardless of what it's attacking. A fresh address has zero
// balance by construction, so ensureAttackerGas() funds it (from the
// KeeperHub-connected wallet, via executeTransfer -- the only wallet in this
// project that can sign a native transfer) before any drain attempt.

import { randomBytes } from 'node:crypto';
import { keccak256Hex, privateKeyToAddress, signLegacyTransaction, hexToBytes, bytesToHex } from './crypto.mjs';
import { executeContractCall, executeTransfer, pollExecution } from '../src/keeperhub.mjs';
import { rpcCallWithRetry, getTokenBalance } from '../src/watcher.mjs';

export const WETH_SEPOLIA = '0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14';
const MAX_UINT256 = ((1n << 256n) - 1n).toString();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Exported (not just internal) so tests can check the ABI-encoding math
// directly, including against real-world well-known selector constants --
// a wrong selector here means the attacker's tx silently calls the wrong
// function, undermining the whole demo.
export function selector(signature) {
  return keccak256Hex(signature).slice(0, 10); // 0x + 8 hex chars = 4 bytes
}

export function encodeAddressArg(addr) {
  return addr.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}

export function encodeUint256Arg(value) {
  return BigInt(value).toString(16).padStart(64, '0');
}

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

const DEPOSIT_ABI = { name: 'deposit', type: 'function', stateMutability: 'payable', inputs: [] };

const SET_APPROVAL_FOR_ALL_ABI = {
  name: 'setApprovalForAll',
  type: 'function',
  stateMutability: 'nonpayable',
  inputs: [
    { name: 'operator', type: 'address' },
    { name: 'approved', type: 'bool' },
  ],
  outputs: [],
};

// ---------------------------------------------------------------------------
// Attacker identity (raw key, demo-only, throwaway)
// ---------------------------------------------------------------------------

export function generateAttackerKey() {
  const privateKeyHex = bytesToHex(randomBytes(32));
  return { privateKeyHex, address: privateKeyToAddress(privateKeyHex) };
}

// ---------------------------------------------------------------------------
// Setup: ensure there's something real to drain, so a blocked attempt
// reverts for "insufficient allowance" specifically -- not "insufficient
// balance", which would credit Deplex for a defense it didn't provide.
// ---------------------------------------------------------------------------

export async function ensureWethBalance(client, cfg, { minWei = 1_000_000_000_000_000n } = {}) {
  const balance = BigInt(await getTokenBalance(cfg.rpcUrl, WETH_SEPOLIA, cfg.watchedWallet, cfg));
  if (balance >= minWei) return { wrapped: false, balance: balance.toString() };

  const topUp = minWei - balance;
  const submitted = await executeContractCall(client, {
    chain: cfg.chainId,
    to: WETH_SEPOLIA,
    abiFragment: DEPOSIT_ABI,
    args: [],
    value: topUp.toString(),
  });
  const final = submitted.executionId
    ? await pollExecution(client, submitted.executionId, { intervalMs: cfg.keeperHub.pollIntervalMs, timeoutMs: cfg.keeperHub.pollTimeoutMs })
    : submitted;
  // Confirmed live: this silently passed for a failed deposit() (insufficient
  // native ETH to cover `value`) -- ensureWethBalance returned {wrapped:true}
  // regardless, run-demo.mjs printed a misleading "wrapped X wei" line, and
  // the drain that followed had zero real balance to test against. Matches
  // the check plantApproval already had; this function was missing it.
  if (!final.txHash) {
    throw new Error(`ensureWethBalance deposit() did not produce a txHash -- likely failed: ${JSON.stringify(final)}`);
  }
  return { wrapped: true, amount: topUp.toString(), result: final };
}

// A fresh throwaway key has zero ETH by construction -- it needs gas money
// to broadcast its OWN transaction, entirely separate from whatever token
// balance it's attacking. Funded from the KeeperHub-connected wallet (the
// only wallet in this project that can sign a native transfer) and awaited
// to completion before returning, so the balance is actually on-chain by
// the time attemptDrain/attemptNftDrain builds a transaction against it.
export async function ensureAttackerGas(client, cfg, attackerAddress, { minWei = 1_000_000_000_000_000n /* 0.001 ETH */ } = {}) {
  const balanceHex = await rpcCallWithRetry(cfg.rpcUrl, 'eth_getBalance', [attackerAddress, 'latest'], cfg);
  const balance = BigInt(balanceHex);
  if (balance >= minWei) return { funded: false, balance: balance.toString() };

  const topUp = minWei - balance;
  const submitted = await executeTransfer(client, { chain: cfg.chainId, to: attackerAddress, amount: topUp.toString() });
  const final = submitted.executionId
    ? await pollExecution(client, submitted.executionId, { intervalMs: cfg.keeperHub.pollIntervalMs, timeoutMs: cfg.keeperHub.pollTimeoutMs })
    : submitted;
  if (!final.txHash) throw new Error(`ensureAttackerGas funding failed: ${JSON.stringify(final)}`);
  return { funded: true, amount: topUp.toString(), result: final };
}

// ---------------------------------------------------------------------------
// Vector 1 (default): ERC-20 unlimited approve(), planted via KeeperHub --
// same call responder.mjs's REVOKE will later reverse with approve(spender, 0).
// ---------------------------------------------------------------------------

export async function plantApproval(client, cfg, { spenderAddress, tokenAddress = WETH_SEPOLIA }) {
  const submitted = await executeContractCall(client, {
    chain: cfg.chainId,
    to: tokenAddress,
    abiFragment: APPROVE_ABI,
    args: [spenderAddress, MAX_UINT256],
    idempotencyKey: `drainer:approve:${tokenAddress}:${spenderAddress}:${Date.now()}`,
  });
  const final = submitted.executionId
    ? await pollExecution(client, submitted.executionId, { intervalMs: cfg.keeperHub.pollIntervalMs, timeoutMs: cfg.keeperHub.pollTimeoutMs })
    : submitted;
  if (!final.txHash) throw new Error(`plantApproval failed: ${JSON.stringify(final)}`);
  return final;
}

// ---------------------------------------------------------------------------
// Vector 2 (every 6th run): NFT ApprovalForAll. Gated on ATTACK_NFT_CONTRACT
// being set -- we won't guess/hardcode a Sepolia NFT contract address we
// haven't independently verified is live. Callers should check
// isNftVectorAvailable(cfg) before using this and fall back to vector 1 with
// a clear log line if it's false, per docs/ONBOARDING-TEARDOWN.md.
// ---------------------------------------------------------------------------

export function isNftVectorAvailable(cfg) {
  return Boolean(cfg.attackNftContract);
}

export async function plantNftApproval(client, cfg, { operatorAddress }) {
  if (!isNftVectorAvailable(cfg)) {
    throw new Error('ATTACK_NFT_CONTRACT is not configured; the NFT vector cannot run (see isNftVectorAvailable)');
  }
  const submitted = await executeContractCall(client, {
    chain: cfg.chainId,
    to: cfg.attackNftContract,
    abiFragment: SET_APPROVAL_FOR_ALL_ABI,
    args: [operatorAddress, true],
    idempotencyKey: `drainer:setApprovalForAll:${cfg.attackNftContract}:${operatorAddress}:${Date.now()}`,
  });
  const final = submitted.executionId
    ? await pollExecution(client, submitted.executionId, { intervalMs: cfg.keeperHub.pollIntervalMs, timeoutMs: cfg.keeperHub.pollTimeoutMs })
    : submitted;
  if (!final.txHash) throw new Error(`plantNftApproval failed: ${JSON.stringify(final)}`);
  return final;
}

// ---------------------------------------------------------------------------
// Raw-signed drain attempts (the attacker's own key, never KeeperHub)
// ---------------------------------------------------------------------------

async function sendRawAndAwaitReceipt(cfg, rawTxHex, { pollIntervalMs = 2000, timeoutMs = 120_000 } = {}) {
  const txHash = await rpcCallWithRetry(cfg.rpcUrl, 'eth_sendRawTransaction', [rawTxHex], cfg);
  const startedAt = Date.now();
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const receipt = await rpcCallWithRetry(cfg.rpcUrl, 'eth_getTransactionReceipt', [txHash], cfg);
    if (receipt) {
      return { txHash, reverted: receipt.status === '0x0', blockNumber: parseInt(receipt.blockNumber, 16), receipt };
    }
    if (Date.now() - startedAt > timeoutMs) {
      throw new Error(`transaction ${txHash} not mined within ${timeoutMs}ms`);
    }
    await sleep(pollIntervalMs);
  }
}

async function buildAndSendAttackerTx(cfg, attackerPrivateKeyHex, attackerAddress, { to, data, value = 0 }) {
  const [nonceHex, gasPriceHex] = await Promise.all([
    rpcCallWithRetry(cfg.rpcUrl, 'eth_getTransactionCount', [attackerAddress, 'pending'], cfg),
    rpcCallWithRetry(cfg.rpcUrl, 'eth_gasPrice', [], cfg),
  ]);
  const tx = {
    nonce: parseInt(nonceHex, 16),
    gasPrice: BigInt(gasPriceHex).toString(),
    // Fixed, generous gas limit -- deliberately NOT eth_estimateGas: a call
    // expected to revert (that's the whole point of this demo) often fails
    // gas estimation client-side before ever reaching the chain, which would
    // hide the real, on-chain "REVERTED" transaction the demo needs to show.
    gasLimit: 150_000,
    to,
    value,
    data,
  };
  const { raw, hash } = signLegacyTransaction(tx, attackerPrivateKeyHex, Number(cfg.chainId));
  const result = await sendRawAndAwaitReceipt(cfg, raw);
  if (result.txHash.toLowerCase() !== hash.toLowerCase()) {
    // Extremely unlikely (would mean our own hash computation is wrong), but
    // if it happens, surface it loudly rather than silently trust the wrong hash.
    throw new Error(`computed txHash ${hash} does not match submitted txHash ${result.txHash}`);
  }
  return result;
}

// "Everything" (per spec) means the wallet's actual balance -- NOT
// MAX_UINT256. Requesting MAX_UINT256 was a real bug: WETH's balance check
// runs before its allowance check, so that transferFrom reverted on
// insufficient BALANCE unconditionally, regardless of whether the allowance
// had been revoked. Fetching the real balance right before building the tx
// makes balance sufficient by construction, so a revert can only mean
// insufficient allowance.
export async function getAttackableBalance(cfg, tokenAddress, demoWalletAddress) {
  return getTokenBalance(cfg.rpcUrl, tokenAddress, demoWalletAddress, cfg);
}

// ERC-20 allowance(owner, spender) -- ground truth for whether a revoke
// actually landed, independent of (and more reliable than) both the revert
// reason (WETH9 reverts with NO reason string at all -- confirmed live,
// data:"0x" on a reverted eth_call replay) and the audit-log race (which
// depends on the watcher process actually being up).
export async function getAllowance(cfg, tokenAddress, ownerAddress, spenderAddress) {
  const data = selector('allowance(address,address)') + encodeAddressArg(ownerAddress) + encodeAddressArg(spenderAddress);
  const result = await rpcCallWithRetry(cfg.rpcUrl, 'eth_call', [{ to: tokenAddress, data }, 'latest'], cfg);
  return BigInt(result).toString();
}

// NFT-vector equivalent of getAllowance -- same ground-truth role.
export async function getIsApprovedForAll(cfg, nftAddress, ownerAddress, operatorAddress) {
  const data = selector('isApprovedForAll(address,address)') + encodeAddressArg(ownerAddress) + encodeAddressArg(operatorAddress);
  const result = await rpcCallWithRetry(cfg.rpcUrl, 'eth_call', [{ to: nftAddress, data }, 'latest'], cfg);
  return BigInt(result) !== 0n;
}

// Attempts transferFrom(demoWallet, attacker, <actual balance>) as the
// attacker. Returns { txHash, reverted, blockNumber }. `amount` can be
// overridden explicitly (e.g. for tests); left unset, it's fetched fresh
// right before the attempt.
export async function attemptDrain(cfg, { attackerPrivateKeyHex, attackerAddress, tokenAddress = WETH_SEPOLIA, demoWalletAddress, amount, delayMs = 0 }) {
  if (delayMs > 0) await sleep(delayMs);
  const drainAmount = amount ?? (await getAttackableBalance(cfg, tokenAddress, demoWalletAddress));
  const data =
    selector('transferFrom(address,address,uint256)') +
    encodeAddressArg(demoWalletAddress) +
    encodeAddressArg(attackerAddress) +
    encodeUint256Arg(drainAmount);
  return buildAndSendAttackerTx(cfg, attackerPrivateKeyHex, attackerAddress, { to: tokenAddress, data });
}

// NFT vector's drain attempt. Precision caveat: unlike the ERC-20 vector
// (where ensureWethBalance guarantees a real balance to drain), we don't
// mint/verify token ownership on an externally-configured NFT contract, so
// a revert here could be "insufficient allowance" (Deplex won) OR "not
// owner of tokenId" (an artifact of demo setup) -- report both possibilities
// rather than assume. See docs/ONBOARDING-TEARDOWN.md.
export async function attemptNftDrain(cfg, { attackerPrivateKeyHex, attackerAddress, demoWalletAddress, tokenId, delayMs = 0 }) {
  if (!isNftVectorAvailable(cfg)) {
    throw new Error('ATTACK_NFT_CONTRACT is not configured; the NFT vector cannot run');
  }
  if (delayMs > 0) await sleep(delayMs);
  const data =
    selector('transferFrom(address,address,uint256)') +
    encodeAddressArg(demoWalletAddress) +
    encodeAddressArg(attackerAddress) +
    encodeUint256Arg(tokenId);
  return buildAndSendAttackerTx(cfg, attackerPrivateKeyHex, attackerAddress, { to: cfg.attackNftContract, data });
}
