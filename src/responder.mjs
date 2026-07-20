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
  const key = `${token}:${spender}`;
  const result = await performExecution(ctx, {
    incidentId,
    actionType: 'REVOKE',
    target: { key, token, spender, kind: kind ?? 'erc20' },
    execute: (kh, idempotencyKey) =>
      kh.executeContractCall(ctx.client, {
        chain: ctx.cfg.chainId,
        to: token,
        abiFragment: fragment,
        args: buildArgs(spender),
        idempotencyKey,
      }),
  });
  // Prune immediately on confirmed success (including an idempotent
  // "already done" skip) rather than waiting for src/watcher.mjs's own
  // independent on-chain re-scan to notice the resulting zero-approval
  // event on some later poll cycle. Confirmed live: without this, repeated
  // testing accumulated a backlog of stale-but-still-tracked entries that
  // REVOKE_ALL kept re-attempting on every later incident, one of which
  // timed out after 20s -- see docs/FAILURE-MODES.md. This is an immediate,
  // in-memory prune; the watcher's log-driven prune is still the durable
  // source of truth and keeps running independently regardless, so a crash
  // between this line and the next state save just means the watcher's own
  // scan re-confirms it later, not a silent gap either way.
  if (result.success && ctx.walletState.activeApprovals) {
    delete ctx.walletState.activeApprovals[key];
  }
  return result;
}

// Sequential on purpose -- spec calls out nonce sanity, not throughput.
// Continues past individual failures; escalation to EVACUATE (if any leg
// failed) happens once in runTier(), after the whole batch is done, so
// legs that would have succeeded still get their chance.
//
// `event` (the trigger that actually escalated to this tier) is prioritized
// to the front of the queue when present. Confirmed live: an accumulated
// backlog of unrelated stale approvals made a real attacker's revoke land
// ~70s after detection instead of immediately -- REVOKE_ALL worked through
// four irrelevant entries sequentially (one of which alone timed out after
// 20s) before ever reaching the actual current threat, which happened to be
// last in object-key iteration order. The real, current threat must never
// queue behind unrelated backlog.
async function runRevokeAll(ctx, incidentId, event) {
  const entries = Object.values(ctx.walletState.activeApprovals ?? {});
  if (event?.token && event?.spender) {
    const triggerKey = `${event.token}:${event.spender}`.toLowerCase();
    const idx = entries.findIndex((e) => `${e.token}:${e.spender}`.toLowerCase() === triggerKey);
    if (idx > 0) {
      const [triggering] = entries.splice(idx, 1);
      entries.unshift(triggering);
    }
  }
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

const SEPOLIA_EXPLORER_TX = 'https://sepolia.etherscan.io/tx/';

// EVACUATE's outcome was previously only ever reported to Telegram on
// failure (see git history) -- REVOKE/REVOKE_ALL/EVACUATE all had NO
// success notification at any tier, for either a real auto-detected
// incident or a manually triggered /panic, because nothing in this
// cascade ever called ctx.alert() on a successful execution. /panic didn't
// uniquely skip anything; it just happened to be the first place a human
// was actively waiting on a response from this generic pipeline. Fixed
// here, at the shared tier-3 completion point, so both trigger paths get
// it -- not duplicated per-caller (see src/watcher.mjs's onPanic for the
// separate, /panic-specific "command received" acknowledgment, which is a
// different message with a different purpose).
function formatEvacuateAlert(incidentId, outcome) {
  const results = outcome.results ?? [];

  if (!outcome.success) {
    const failed = results.filter((r) => !r.success);
    const reason = failed.length ? failed.map((r) => `${r.key}: ${r.error ?? 'unknown error'}`).join('; ') : 'unknown error';
    return `❌ Evacuation failed: ${reason}. Manual intervention may be required.`;
  }

  const succeeded = results.filter((r) => r.success && r.result?.txHash);
  if (succeeded.length === 0) {
    return `✅ Evacuation complete for incident ${incidentId} -- no funds found to move (all tracked balances were already zero).`;
  }
  if (succeeded.length === 1) {
    const txHash = succeeded[0].result.txHash;
    return `✅ Evacuation complete. TxHash: ${txHash}. Explorer: ${SEPOLIA_EXPLORER_TX}${txHash}`;
  }
  const legs = succeeded.map((r) => `${r.result.txHash} (${SEPOLIA_EXPLORER_TX}${r.result.txHash})`).join(', ');
  return `✅ Evacuation complete (${succeeded.length} transfers). TxHashes: ${legs}`;
}

// ---------------------------------------------------------------------------
// Cascade: run the tier the incident just escalated to; on failure at any
// tier below EVACUATE, auto-escalate one tier and retry there. EVACUATE has
// nowhere higher to go -- its outcome (success or failure) is always
// reported directly instead.
// ---------------------------------------------------------------------------

async function runTier(ctx, incidentId, tier, event, ruleName) {
  ctx.walletState.incident = { stateName: TIER_STATE[tier], highestTier: tier };

  let outcome;
  if (tier === 0) outcome = await runAlert(ctx, incidentId, event, ruleName);
  else if (tier === 1) outcome = await runRevoke(ctx, incidentId, { token: event.token, spender: event.spender, kind: event.kind });
  else if (tier === 2) outcome = await runRevokeAll(ctx, incidentId, event);
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

  if (tier === 3) {
    await ctx.alert(formatEvacuateAlert(incidentId, outcome));
    // A successful EVACUATE is the terminal action -- there's nowhere higher
    // to escalate to, and the wallet's tracked balances have just been swept
    // to the safe address, so there's nothing left for a human to review
    // before it's safe to re-arm. Previously nothing ever called this
    // (resolveCurrentIncident/resetCurrentIncident were both operator-only,
    // via scripts/reset-incident.mjs), so ctx.walletState.currentIncidentId
    // stayed set forever after the FIRST successful EVACUATE -- every
    // subsequent trigger (a fresh /panic hours later, or a genuinely new
    // auto-detected event) silently reattached to that same stale id
    // instead of minting a new one. Confirmed live: three separate manual
    // /panic triggers hours apart all produced "Evacuation complete for
    // incident <same-id>". See docs/FAILURE-MODES.md.
    //
    // Deliberately scoped to SUCCESS only: a failed EVACUATE still needs a
    // human to look at it before anything re-arms (unchanged, and still
    // covered by the "stale escalated incident" regression test below,
    // which simulates exactly that stuck-open state).
    if (outcome.success) {
      resolveCurrentIncident(ctx);
    }
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
