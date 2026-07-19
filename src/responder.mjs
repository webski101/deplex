// escalation state machine + KeeperHub execution calls
//
// ctx shape expected by handleEvent(event, ctx):
//   { rules, cfg, client, walletState, alert, keeperhub? }
// - client: a KeeperHubClient (src/keeperhub.mjs)
// - keeperhub: optional override of { executeContractCall, executeTransfer,
//   pollExecution } for tests -- defaults to the real module.
// - walletState: same object watcher.mjs maintains (activeApprovals,
//   balances, allowlist), plus .incident and .currentIncidentId that this
//   file owns.

import { randomUUID } from 'node:crypto';
import { evaluate, advanceIncident, resolveIncident, resetIncident } from './policy.mjs';
import { append as appendAudit, readAll as readAudit } from './auditlog.mjs';
import { rpcCallWithRetry, getTokenBalance, getTokenDecimals } from './watcher.mjs';
import * as keeperhubDefault from './keeperhub.mjs';

const TIER_STATE = ['ALERTED', 'REVOKING', 'REVOKING', 'EVACUATING'];

const ERC20_APPROVE_ABI = {
  name: 'approve',
  type: 'function',
  stateMutability: 'nonpayable',
  inputs: [
    { name: 'spender', type: 'address' },
    { name: 'amount', type: 'uint256' },
  ],
  outputs: [{ name: '', type: 'bool' }],
};

const ERC721_SET_APPROVAL_FOR_ALL_ABI = {
  name: 'setApprovalForAll',
  type: 'function',
  stateMutability: 'nonpayable',
  inputs: [
    { name: 'operator', type: 'address' },
    { name: 'approved', type: 'bool' },
  ],
  outputs: [],
};

// UNCONFIRMED against real KeeperHub status strings (see docs/KEEPERHUB-NOTES.md).
// Deliberately an allowlist of known-GOOD terminal values, not a denylist of
// known-bad ones: for a fund-safety idempotency check, treating an
// unrecognized status as "already succeeded" is the dangerous direction --
// defaulting to "not confirmed, safe to retry" is the fail-closed one.
const SUCCESS_STATUSES = new Set(['confirmed', 'success', 'succeeded', 'completed', 'complete']);

function isSuccessStatus(status) {
  return typeof status === 'string' && SUCCESS_STATUSES.has(status.toLowerCase());
}

const defaultRpc = {
  getTokenBalance,
  getTokenDecimals,
  async getNativeBalance(rpcUrl, walletAddress, retryOpts) {
    const hex = await rpcCallWithRetry(rpcUrl, 'eth_getBalance', [walletAddress, 'latest'], retryOpts);
    return BigInt(hex).toString();
  },
};

function actionKey(incidentId, actionType, subKey) {
  return `${incidentId}:${actionType}${subKey ? ':' + subKey : ''}`;
}

function loadCompletedKeys(auditLogPath) {
  const keys = new Set();
  for (const record of readAudit(auditLogPath)) {
    if (record.type === 'EXECUTION_RESULT' && record.payload?.actionKey && isSuccessStatus(record.payload.status)) {
      keys.add(record.payload.actionKey);
    }
  }
  return keys;
}

// ---------------------------------------------------------------------------
// Single execution primitive: idempotency check -> intent -> (DRY_RUN stop |
// submit -> poll -> result). Every REVOKE/REVOKE_ALL/EVACUATE leg goes
// through this so the audit trail and idempotency behavior stay uniform.
// ---------------------------------------------------------------------------

async function performExecution(ctx, { incidentId, actionType, target, execute }) {
  const key = actionKey(incidentId, actionType, target.key);
  if (ctx.completedKeys.has(key)) {
    return { skipped: true, success: true, key };
  }

  appendAudit(ctx.cfg.auditLogPath, 'EXECUTION_INTENT', { incidentId, actionType, target, actionKey: key });

  if (ctx.cfg.dryRun) {
    appendAudit(ctx.cfg.auditLogPath, 'EXECUTION_RESULT', {
      incidentId,
      actionType,
      target,
      actionKey: key,
      status: 'DRY_RUN',
    });
    return { dryRun: true, success: true, key };
  }

  const kh = ctx.keeperhub ?? keeperhubDefault;
  let submitted;
  try {
    // key doubles as KeeperHub's server-side idempotency_key: even a crash
    // between submit and the audit write below can't double-execute.
    submitted = await execute(kh, key);
  } catch (err) {
    appendAudit(ctx.cfg.auditLogPath, 'EXECUTION_RESULT', {
      incidentId,
      actionType,
      target,
      actionKey: key,
      status: 'failed',
      error: err.message,
    });
    return { success: false, key, error: err.message };
  }

  appendAudit(ctx.cfg.auditLogPath, 'EXECUTION_SUBMITTED', {
    incidentId,
    actionType,
    target,
    actionKey: key,
    executionId: submitted.executionId,
    status: submitted.status,
  });

  // Some direct executions may respond synchronously with no execution id to
  // poll (e.g. a view/pure call) -- treat that initial response as final.
  if (!submitted.executionId) {
    const success = isSuccessStatus(submitted.status) || Boolean(submitted.txHash);
    appendAudit(ctx.cfg.auditLogPath, 'EXECUTION_RESULT', { incidentId, actionType, target, actionKey: key, ...submitted });
    if (success) ctx.completedKeys.add(key);
    return { success, key, result: submitted };
  }

  let final;
  try {
    final = await kh.pollExecution(ctx.client, submitted.executionId, {
      intervalMs: ctx.cfg.keeperHub.pollIntervalMs,
      timeoutMs: ctx.cfg.keeperHub.pollTimeoutMs,
    });
  } catch (err) {
    appendAudit(ctx.cfg.auditLogPath, 'EXECUTION_RESULT', {
      incidentId,
      actionType,
      target,
      actionKey: key,
      status: 'poll_failed',
      error: err.message,
    });
    return { success: false, key, error: err.message };
  }

  const success = isSuccessStatus(final.status);
  appendAudit(ctx.cfg.auditLogPath, 'EXECUTION_RESULT', { incidentId, actionType, target, actionKey: key, ...final });
  if (success) ctx.completedKeys.add(key);
  return { success, key, result: final };
}

// ---------------------------------------------------------------------------
// Per-tier executors
// ---------------------------------------------------------------------------

async function runAlert(ctx, incidentId, event, ruleName) {
  const message = `Deplex ALERT -- incident ${incidentId}\nRule: ${ruleName}\nEvent: ${event.type} on token ${event.token ?? 'n/a'}`;
  await ctx.alert(message);
  appendAudit(ctx.cfg.auditLogPath, 'EXECUTION_RESULT', { incidentId, actionType: 'ALERT', status: 'sent' });
  return { success: true };
}

function revokeAbiFor(kind) {
  return kind === 'nft-operator'
    ? { fragment: ERC721_SET_APPROVAL_FOR_ALL_ABI, buildArgs: (spender) => [spender, false] }
    : { fragment: ERC20_APPROVE_ABI, buildArgs: (spender) => [spender, '0'] };
}

async function runRevoke(ctx, incidentId, { token, spender, kind }) {
  const { fragment, buildArgs } = revokeAbiFor(kind);
  return performExecution(ctx, {
    incidentId,
    actionType: 'REVOKE',
    target: { key: `${token}:${spender}`, token, spender, kind: kind ?? 'erc20' },
    execute: (kh, idempotencyKey) =>
      kh.executeContractCall(ctx.client, {
        chain: ctx.cfg.chainId,
        to: token,
        abiFragment: fragment,
        args: buildArgs(spender),
        idempotencyKey,
      }),
  });
}

// Sequential on purpose -- spec calls out nonce sanity, not throughput.
// Continues past individual failures; escalation to EVACUATE (if any leg
// failed) happens once in runTier(), after the whole batch is done, so
// legs that would have succeeded still get their chance.
async function runRevokeAll(ctx, incidentId) {
  const entries = Object.values(ctx.walletState.activeApprovals ?? {});
  const results = [];
  for (const entry of entries) {
    results.push(await runRevoke(ctx, incidentId, entry));
  }
  const anyFailed = results.some((r) => !r.success);
  return { success: entries.length === 0 || !anyFailed, results };
}

async function runEvacuate(ctx, incidentId) {
  const rpc = ctx.rpc ?? defaultRpc;
  const results = [];

  for (const token of ctx.cfg.trackedTokens) {
    let balance;
    try {
      balance = await rpc.getTokenBalance(ctx.cfg.rpcUrl, token, ctx.cfg.watchedWallet, ctx.cfg);
    } catch (err) {
      results.push({ success: false, key: `token:${token}`, error: `balance fetch failed: ${err.message}` });
      continue;
    }
    if (balance === '0') continue;
    // decimals: NOT assumed -- fetched per token. execute_transfer expects a
    // decimal-string amount (see keeperhub.mjs's weiToDecimalString); a
    // wrong decimals value here would misconvert a real evacuation amount
    // (e.g. treating a 6-decimal USDC balance as 18-decimal, off by 10^12).
    let decimals = 18;
    try {
      decimals = await rpc.getTokenDecimals(ctx.cfg.rpcUrl, token, ctx.cfg);
    } catch (err) {
      results.push({ success: false, key: `token:${token}`, error: `decimals fetch failed: ${err.message}` });
      continue;
    }
    results.push(
      await performExecution(ctx, {
        incidentId,
        actionType: 'EVACUATE',
        target: { key: `token:${token}`, token, amount: balance, decimals },
        execute: (kh, idempotencyKey) =>
          kh.executeTransfer(ctx.client, { chain: ctx.cfg.chainId, token, to: ctx.cfg.safeAddress, amount: balance, decimals, idempotencyKey }),
      }),
    );
  }

  let nativeBalance = '0';
  try {
    nativeBalance = await rpc.getNativeBalance(ctx.cfg.rpcUrl, ctx.cfg.watchedWallet, ctx.cfg);
  } catch (err) {
    results.push({ success: false, key: 'native', error: `native balance fetch failed: ${err.message}` });
  }
  if (nativeBalance !== '0') {
    results.push(
      await performExecution(ctx, {
        incidentId,
        actionType: 'EVACUATE',
        target: { key: 'native', amount: nativeBalance },
        execute: (kh, idempotencyKey) =>
          kh.executeTransfer(ctx.client, { chain: ctx.cfg.chainId, to: ctx.cfg.safeAddress, amount: nativeBalance, idempotencyKey }),
      }),
    );
  }

  const anyFailed = results.some((r) => !r.success);
  return { success: !anyFailed, results };
}

// ---------------------------------------------------------------------------
// Cascade: run the tier the incident just escalated to; on failure at any
// tier below EVACUATE, auto-escalate one tier and retry there. EVACUATE
// failing has nowhere higher to go -- alert critically instead.
// ---------------------------------------------------------------------------

async function runTier(ctx, incidentId, tier, event, ruleName) {
  ctx.walletState.incident = { stateName: TIER_STATE[tier], highestTier: tier };

  let outcome;
  if (tier === 0) outcome = await runAlert(ctx, incidentId, event, ruleName);
  else if (tier === 1) outcome = await runRevoke(ctx, incidentId, { token: event.token, spender: event.spender, kind: event.kind });
  else if (tier === 2) outcome = await runRevokeAll(ctx, incidentId);
  else outcome = await runEvacuate(ctx, incidentId);

  if (!outcome.success && tier < 3) {
    appendAudit(ctx.cfg.auditLogPath, 'ESCALATION', {
      incidentId,
      fromTier: tier,
      toTier: tier + 1,
      reason: 'execution failure',
    });
    await ctx.alert(`Deplex: tier ${tier} action failed for incident ${incidentId} -- auto-escalating to tier ${tier + 1}`);
    return runTier(ctx, incidentId, tier + 1, event, ruleName);
  }

  if (!outcome.success && tier === 3) {
    await ctx.alert(
      `Deplex CRITICAL: EVACUATE failed for incident ${incidentId} -- no higher tier available, manual intervention required`,
    );
  }

  return outcome;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function handleEvent(event, ctx) {
  if (!ctx.completedKeys) ctx.completedKeys = loadCompletedKeys(ctx.cfg.auditLogPath);

  const priorIncident = ctx.walletState.incident ?? { stateName: 'IDLE', highestTier: -1 };
  const triggered = evaluate(ctx.rules, event, ctx.walletState);
  if (triggered.length === 0) {
    // A null verdict is still a verdict -- record it. Distinguish "no rule
    // matched" from "rules matched but are suppressed by monotonic
    // escalation" (open incident already past their tier): the latter was
    // invisible before and cost a live debugging session.
    const unsuppressed = evaluate(ctx.rules, event, { ...ctx.walletState, incident: { highestTier: -1 } });
    const suppressed = unsuppressed.map((t) => ({ ruleName: t.ruleName, type: t.action.type, tier: t.action.tier }));
    appendAudit(ctx.cfg.auditLogPath, 'DECISION', {
      incidentId: ctx.walletState.currentIncidentId ?? null,
      event,
      triggered: [],
      suppressedByEscalation: suppressed,
      priorState: priorIncident.stateName,
      reason: suppressed.length
        ? `matching rules are below this incident's highest tier (${priorIncident.highestTier}); operator reset required to re-arm lower tiers`
        : 'no rule matched this event',
    });
    return { executed: false, reason: suppressed.length ? 'suppressed by monotonic escalation' : 'no rule triggered' };
  }

  const nextIncident = advanceIncident(priorIncident, triggered);
  const topAction = triggered.find((t) => t.action.tier === nextIncident.highestTier) ?? triggered[0];

  if (!ctx.walletState.currentIncidentId) {
    ctx.walletState.currentIncidentId = randomUUID();
  }
  const incidentId = ctx.walletState.currentIncidentId;

  appendAudit(ctx.cfg.auditLogPath, 'DECISION', {
    incidentId,
    event,
    triggered: triggered.map((t) => ({ ruleName: t.ruleName, type: t.action.type, tier: t.action.tier })),
    priorState: priorIncident.stateName,
    nextState: nextIncident.stateName,
  });

  const outcome = await runTier(ctx, incidentId, nextIncident.highestTier, event, topAction.ruleName);
  return { executed: true, incidentId, tier: nextIncident.highestTier, outcome };
}

export function resolveCurrentIncident(ctx) {
  appendAudit(ctx.cfg.auditLogPath, 'RESET', { incidentId: ctx.walletState.currentIncidentId, kind: 'resolved' });
  ctx.walletState.incident = resolveIncident();
  ctx.walletState.currentIncidentId = null;
}

export function resetCurrentIncident(ctx) {
  appendAudit(ctx.cfg.auditLogPath, 'RESET', { incidentId: ctx.walletState.currentIncidentId, kind: 'operator_reset' });
  ctx.walletState.incident = resetIncident();
  ctx.walletState.currentIncidentId = null;
}
