import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compile } from '../src/policy.mjs';
import { readAll } from '../src/auditlog.mjs';
import { handleEvent, resolveCurrentIncident, resetCurrentIncident } from '../src/responder.mjs';

const TOKEN_A = '0x' + 'aa'.repeat(20);
const TOKEN_B = '0x' + 'bb'.repeat(20);
const TOKEN_C = '0x' + 'cc'.repeat(20);
const NFT = '0x' + 'dd'.repeat(20);
const SPENDER = '0x' + '11'.repeat(20);
const SAFE = '0x' + '99'.repeat(20);
const WALLET = '0x' + '22'.repeat(20);
const MAX_UINT256 = ((1n << 256n) - 1n).toString();

let tmpDir;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'deplex-responder-'));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function makeCfg(overrides = {}) {
  return {
    rpcUrl: 'http://unused.invalid',
    chainId: '11155111',
    watchedWallet: WALLET,
    safeAddress: SAFE,
    trackedTokens: [TOKEN_A],
    auditLogPath: join(tmpDir, 'audit.jsonl'),
    dryRun: false,
    keeperHub: { apiKey: 'kh_test', pollIntervalMs: 1, pollTimeoutMs: 1000 },
    ...overrides,
  };
}

// Mock KeeperHub module: success by default, per-call overrides via hooks.
function makeMockKeeperhub() {
  const calls = { contractCalls: [], transfers: [], polls: [] };
  let execCounter = 0;
  const mock = {
    calls,
    failContractCallFor: null, // (payload) => boolean
    failTransfers: false,
    async executeContractCall(client, payload) {
      calls.contractCalls.push(payload);
      if (mock.failContractCallFor && mock.failContractCallFor(payload)) {
        throw new Error('mock: contract call rejected');
      }
      return { executionId: `exec-${++execCounter}`, status: 'submitted' };
    },
    async executeTransfer(client, payload) {
      calls.transfers.push(payload);
      if (mock.failTransfers) throw new Error('mock: transfer rejected');
      return { executionId: `exec-${++execCounter}`, status: 'submitted' };
    },
    async pollExecution(client, executionId) {
      calls.polls.push(executionId);
      return { status: 'confirmed', txHash: `0xhash-${executionId}`, executionId };
    },
  };
  return mock;
}

function makeMockRpc({ tokenBalances = {}, nativeBalance = '0', tokenDecimals = {} } = {}) {
  return {
    async getTokenBalance(rpcUrl, token) {
      return tokenBalances[token] ?? '0';
    },
    async getNativeBalance() {
      return nativeBalance;
    },
    async getTokenDecimals(rpcUrl, token) {
      return tokenDecimals[token] ?? 18;
    },
  };
}

function makeCtx({ policy, cfg, keeperhub, rpc, walletState = {} } = {}) {
  const compiled = compile(policy);
  assert.equal(compiled.errors.length, 0, `test policy must compile: ${JSON.stringify(compiled.errors)}`);
  const alerts = [];
  return {
    ctx: {
      rules: compiled.rules,
      cfg,
      client: {}, // mocks never touch it
      walletState,
      alert: async (text) => {
        alerts.push(text);
      },
      keeperhub,
      rpc,
    },
    alerts,
  };
}

const REVOKE_POLICY = 'RULE r1: IF approval.unlimited AND approval.spender NOT ALLOWLISTED THEN REVOKE PRIORITY 5';
const PANIC_POLICY = 'RULE p1: IF panic.triggered THEN EVACUATE PRIORITY 10';

function approvalEvent(overrides = {}) {
  return {
    type: 'approval',
    kind: 'erc20',
    token: TOKEN_A,
    owner: WALLET,
    spender: SPENDER,
    amount: MAX_UINT256,
    unlimited: true,
    txHash: '0xevent1',
    block: 100,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Happy path: REVOKE
// ---------------------------------------------------------------------------

test('REVOKE: unlimited approval triggers approve(spender, 0) via KeeperHub and records the full audit trail', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg();
  const { ctx } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh });

  const result = await handleEvent(approvalEvent(), ctx);

  assert.equal(result.executed, true);
  assert.equal(result.tier, 1);
  assert.equal(result.outcome.success, true);
  assert.equal(kh.calls.contractCalls.length, 1);
  const call = kh.calls.contractCalls[0];
  assert.equal(call.chain, '11155111');
  assert.equal(call.to, TOKEN_A);
  assert.equal(call.abiFragment.name, 'approve');
  assert.deepEqual(call.args, [SPENDER, '0']);
  assert.equal(
    call.idempotencyKey,
    `${result.incidentId}:REVOKE:${TOKEN_A}:${SPENDER}`,
    'actionKey must ride to KeeperHub as the server-side idempotency key',
  );

  const types = readAll(cfg.auditLogPath).map((r) => r.type);
  assert.deepEqual(types, ['DECISION', 'EXECUTION_INTENT', 'EXECUTION_SUBMITTED', 'EXECUTION_RESULT']);
  const resultRecord = readAll(cfg.auditLogPath).find((r) => r.type === 'EXECUTION_RESULT');
  assert.equal(resultRecord.payload.status, 'confirmed');
  assert.ok(resultRecord.payload.txHash);
});

test('REVOKE for an nft-operator approval uses setApprovalForAll(spender, false)', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg();
  const { ctx } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh });

  await handleEvent(approvalEvent({ kind: 'nft-operator', token: NFT, amount: MAX_UINT256 }), ctx);

  assert.equal(kh.calls.contractCalls.length, 1);
  const call = kh.calls.contractCalls[0];
  assert.equal(call.to, NFT);
  assert.equal(call.abiFragment.name, 'setApprovalForAll');
  assert.deepEqual(call.args, [SPENDER, false]);
});

// ---------------------------------------------------------------------------
// DRY_RUN
// ---------------------------------------------------------------------------

test('DRY_RUN: full flow runs, no KeeperHub call is made, audit records intent + DRY_RUN result', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ dryRun: true });
  const { ctx } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh });

  const result = await handleEvent(approvalEvent(), ctx);

  assert.equal(result.executed, true);
  assert.equal(result.outcome.success, true);
  assert.equal(kh.calls.contractCalls.length, 0, 'DRY_RUN must stop before the KeeperHub call');
  const records = readAll(cfg.auditLogPath);
  assert.ok(records.some((r) => r.type === 'EXECUTION_INTENT'));
  assert.ok(records.some((r) => r.type === 'EXECUTION_RESULT' && r.payload.status === 'DRY_RUN'));
});

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

test('idempotency: re-processing the same event after a simulated restart never double-executes', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg();
  const walletState = {};
  const { ctx } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh, walletState });

  const first = await handleEvent(approvalEvent(), ctx);
  assert.equal(first.outcome.success, true);
  assert.equal(kh.calls.contractCalls.length, 1);

  // Simulated restart: fresh ctx (completedKeys must be re-derived from the
  // audit chain on disk), same persisted walletState (incident id survives
  // via the state file).
  const { ctx: ctx2 } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh, walletState });
  const second = await handleEvent(approvalEvent(), ctx2);

  assert.equal(second.executed, true);
  assert.equal(kh.calls.contractCalls.length, 1, 'must not execute a second time');
  assert.equal(second.outcome.skipped, true);
});

test('idempotency is fail-closed: a FAILED prior attempt does not block the retry', async () => {
  // Tier 3 (EVACUATE) is the right place to test this: same-tier re-triggers
  // are allowed under monotonic escalation (tier < highestTier is moot, but
  // tier == highestTier is not), so a retried panic exercises the
  // completedKeys check directly.
  const kh = makeMockKeeperhub();
  kh.failTransfers = true; // first run: evacuation legs fail
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const walletState = {};
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '5000' }, nativeBalance: '0' });
  const { ctx } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState });

  const first = await handleEvent({ type: 'panic' }, ctx);
  assert.equal(first.outcome.success, false);
  assert.equal(kh.calls.transfers.length, 1);
  assert.equal(walletState.currentIncidentId, first.incidentId, 'a failed EVACUATE must stay open, not auto-resolve');

  // retry with transfers now healthy, simulating a restart (fresh ctx,
  // completedKeys re-derived from the on-disk audit chain): the failed
  // EXECUTION_RESULT must NOT count as completed, so the leg runs again
  kh.failTransfers = false;
  const { ctx: ctx2 } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState });
  const second = await handleEvent({ type: 'panic' }, ctx2);

  assert.equal(kh.calls.transfers.length, 2, 'failed attempt must be retryable');
  assert.equal(second.outcome.success, true);
  assert.equal(second.incidentId, first.incidentId, 'retry of the same still-open incident keeps the same id');
});

test('idempotency within a still-open incident: a partial EVACUATE failure retries only the failed leg, not the already-succeeded one', async () => {
  // A fully successful EVACUATE now auto-resolves the incident (see the
  // "auto-resolve on success" fix in responder.mjs's runTier), so the only
  // way an EVACUATE stays open long enough to retry is a PARTIAL failure --
  // one leg succeeds, another fails, overall outcome.success stays false.
  // TOKEN_A succeeds on the first attempt; TOKEN_B fails until toggled off.
  const calls = { transfers: [] };
  let execCounter = 0;
  let failTokenB = true;
  const kh = {
    async executeTransfer(client, payload) {
      calls.transfers.push(payload);
      if (payload.token === TOKEN_B && failTokenB) throw new Error('mock: TOKEN_B transfer rejected');
      return { executionId: `exec-${++execCounter}`, status: 'submitted' };
    },
    async pollExecution(client, executionId) {
      return { status: 'confirmed', txHash: `0xhash-${executionId}`, executionId };
    },
  };
  const cfg = makeCfg({ trackedTokens: [TOKEN_A, TOKEN_B] });
  const walletState = {};
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '1000', [TOKEN_B]: '2000' }, nativeBalance: '0' });
  const { ctx } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState });

  const first = await handleEvent({ type: 'panic' }, ctx);
  assert.equal(first.outcome.success, false, 'TOKEN_B leg failed -> overall EVACUATE is not successful');
  assert.equal(calls.transfers.length, 2);
  assert.equal(walletState.currentIncidentId, first.incidentId, 'a failed EVACUATE must not auto-resolve -- stays open for retry');

  // retry (simulated restart: fresh ctx, completedKeys re-derived from the
  // on-disk audit chain, same persisted walletState/incident id)
  failTokenB = false;
  const { ctx: ctx2 } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState });
  const second = await handleEvent({ type: 'panic' }, ctx2);

  assert.equal(second.incidentId, first.incidentId, 'retry of a still-open incident keeps the same id');
  assert.equal(second.outcome.success, true);
  assert.equal(calls.transfers.length, 3, 'only the previously-failed TOKEN_B leg re-executes');
  assert.equal(calls.transfers[2].token, TOKEN_B);
  assert.equal(walletState.currentIncidentId, null, 'now that EVACUATE fully succeeded, the incident auto-resolves');
});

// ---------------------------------------------------------------------------
// Escalation on failure (spec: this path must have a test)
// ---------------------------------------------------------------------------

test('escalation: a failed REVOKE auto-escalates tier by tier and alerts at each step', async () => {
  const kh = makeMockKeeperhub();
  kh.failContractCallFor = () => true; // all revocations fail
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const walletState = {
    activeApprovals: {
      [`${TOKEN_A}:${SPENDER}`]: { token: TOKEN_A, spender: SPENDER, kind: 'erc20', unlimited: true },
    },
  };
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '5000' }, nativeBalance: '777' });
  const { ctx, alerts } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh, rpc, walletState });

  const result = await handleEvent(approvalEvent(), ctx);

  // tier 1 failed -> tier 2 (REVOKE ALL) failed -> tier 3 (EVACUATE) succeeded
  assert.equal(result.outcome.success, true);
  const records = readAll(cfg.auditLogPath);
  const escalations = records.filter((r) => r.type === 'ESCALATION').map((r) => [r.payload.fromTier, r.payload.toTier]);
  assert.deepEqual(escalations, [
    [1, 2],
    [2, 3],
  ]);
  assert.equal(alerts.filter((a) => a.includes('auto-escalating')).length, 2);

  // evacuation actually moved both legs to the safe address
  assert.equal(kh.calls.transfers.length, 2);
  const [tokenLeg, nativeLeg] = kh.calls.transfers;
  assert.equal(tokenLeg.token, TOKEN_A);
  assert.equal(tokenLeg.amount, '5000');
  assert.equal(tokenLeg.decimals, 18, 'must fetch and pass real decimals, not assume');
  assert.equal(tokenLeg.to, SAFE);
  assert.equal(nativeLeg.token, undefined);
  assert.equal(nativeLeg.amount, '777');
  assert.equal(nativeLeg.to, SAFE);

  // incident auto-resolves: EVACUATE succeeded, nothing higher to escalate
  // to and nothing left to review before it's safe to re-arm (see the
  // auto-resolve-on-success fix in runTier -- this used to assert
  // stateName stayed 'EVACUATING' forever, which was the actual production
  // bug: a resolved incident's id got reattached to the next trigger).
  assert.equal(walletState.incident.stateName, 'RESOLVED');
  assert.equal(walletState.incident.highestTier, -1);
  assert.equal(walletState.currentIncidentId, null);
});

test('EVACUATE failure has no higher tier: alerts once with a clear failure message and stops (no infinite recursion)', async () => {
  const kh = makeMockKeeperhub();
  kh.failTransfers = true;
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '5000' }, nativeBalance: '0' });
  const { ctx, alerts } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState: {} });

  const result = await handleEvent({ type: 'panic', observedAt: 'now' }, ctx);

  assert.equal(result.outcome.success, false);
  const evacAlerts = alerts.filter((a) => a.startsWith('❌ Evacuation failed'));
  assert.equal(evacAlerts.length, 1, 'exactly one failure alert, not zero and not a duplicate per leg');
  assert.match(evacAlerts[0], /manual intervention may be required/i);
  assert.match(evacAlerts[0], /mock: transfer rejected/); // the actual underlying error, not a vague message
});

// ---------------------------------------------------------------------------
// EVACUATE completion notification -- both directions, both trigger paths
// (manual /panic and an escalated auto-detected incident go through the
// exact same runTier() tier-3 branch, so one set of tests here covers both)
// ---------------------------------------------------------------------------

test('EVACUATE success (single leg): sends exactly one alert with the real txHash and an explorer link', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '1000' }, nativeBalance: '0' });
  const { ctx, alerts } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState: {} });

  const result = await handleEvent({ type: 'panic' }, ctx);

  assert.equal(result.outcome.success, true);
  const successAlerts = alerts.filter((a) => a.startsWith('✅ Evacuation complete'));
  assert.equal(successAlerts.length, 1);
  assert.match(successAlerts[0], /TxHash: 0xhash-exec-1\b/);
  assert.match(successAlerts[0], /https:\/\/sepolia\.etherscan\.io\/tx\/0xhash-exec-1/);
});

test('EVACUATE success (multiple legs, e.g. a token plus native): lists every txHash, not just the first', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '1000' }, nativeBalance: '42' });
  const { ctx, alerts } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState: {} });

  await handleEvent({ type: 'panic' }, ctx);

  const successAlerts = alerts.filter((a) => a.startsWith('✅ Evacuation complete'));
  assert.equal(successAlerts.length, 1);
  assert.match(successAlerts[0], /2 transfers/);
  assert.match(successAlerts[0], /0xhash-exec-1/);
  assert.match(successAlerts[0], /0xhash-exec-2/);
});

test('EVACUATE success with nothing to move: says so plainly instead of fabricating a txHash', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '0' }, nativeBalance: '0' });
  const { ctx, alerts } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState: {} });

  const result = await handleEvent({ type: 'panic' }, ctx);

  assert.equal(result.outcome.success, true);
  assert.equal(kh.calls.transfers.length, 0);
  const successAlerts = alerts.filter((a) => a.startsWith('✅ Evacuation complete'));
  assert.equal(successAlerts.length, 1);
  assert.match(successAlerts[0], /no funds found to move/);
  assert.doesNotMatch(successAlerts[0], /TxHash/);
});

test('EVACUATE success reached via escalation (real auto-detected incident, not /panic) also gets the completion alert', async () => {
  // This is the point-3 check: the automatic-detection path goes through
  // the exact same runTier() tier-3 branch as /panic, so it must get the
  // same completion notification -- confirming the fix is at the shared
  // root cause, not a /panic-only patch.
  const kh = makeMockKeeperhub();
  kh.failContractCallFor = () => true; // tier 1 and tier 2 both fail -> escalates to tier 3
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const walletState = {
    activeApprovals: {
      [`${TOKEN_A}:${SPENDER}`]: { token: TOKEN_A, spender: SPENDER, kind: 'erc20', unlimited: true },
    },
  };
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '5000' }, nativeBalance: '0' });
  const { ctx, alerts } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh, rpc, walletState });

  const result = await handleEvent(approvalEvent(), ctx);

  assert.equal(result.outcome.success, true);
  const successAlerts = alerts.filter((a) => a.startsWith('✅ Evacuation complete'));
  assert.equal(successAlerts.length, 1, 'a real detected incident escalating to EVACUATE must also get a completion alert');
});

// ---------------------------------------------------------------------------
// REVOKE ALL
// ---------------------------------------------------------------------------

test('REVOKE ALL: iterates approvals sequentially, continues past individual failures, records each outcome', async () => {
  const kh = makeMockKeeperhub();
  kh.failContractCallFor = (payload) => payload.to === TOKEN_B; // only B fails
  const cfg = makeCfg({ trackedTokens: [] });
  const walletState = {
    activeApprovals: {
      [`${TOKEN_A}:${SPENDER}`]: { token: TOKEN_A, spender: SPENDER, kind: 'erc20' },
      [`${TOKEN_B}:${SPENDER}`]: { token: TOKEN_B, spender: SPENDER, kind: 'erc20' },
      [`${TOKEN_C}:${SPENDER}`]: { token: TOKEN_C, spender: SPENDER, kind: 'erc20' },
    },
  };
  const rpc = makeMockRpc();
  // policy that goes straight to tier 2
  const policy = 'RULE r2: IF approval.unlimited THEN REVOKE ALL PRIORITY 7';
  const { ctx } = makeCtx({ policy, cfg, keeperhub: kh, rpc, walletState });

  await handleEvent(approvalEvent(), ctx);

  // all three attempted despite B failing mid-batch
  assert.deepEqual(
    kh.calls.contractCalls.map((c) => c.to),
    [TOKEN_A, TOKEN_B, TOKEN_C],
  );
  const results = readAll(cfg.auditLogPath).filter((r) => r.type === 'EXECUTION_RESULT');
  const byToken = Object.fromEntries(results.map((r) => [r.payload.target?.token, r.payload.status]));
  assert.equal(byToken[TOKEN_A], 'confirmed');
  assert.equal(byToken[TOKEN_B], 'failed');
  assert.equal(byToken[TOKEN_C], 'confirmed');
});

test('REVOKE ALL: prioritizes the triggering event\'s spender first, ahead of unrelated backlog (regression: real attacker queued last behind 4 stale entries)', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ trackedTokens: [] });
  // TOKEN_C is the real, current threat -- deliberately last in object-key
  // iteration order, matching the live incident (the actual attacker ended
  // up 5th in line behind 4 unrelated stale entries).
  const walletState = {
    activeApprovals: {
      [`${TOKEN_A}:${SPENDER}`]: { token: TOKEN_A, spender: SPENDER, kind: 'erc20' },
      [`${TOKEN_B}:${SPENDER}`]: { token: TOKEN_B, spender: SPENDER, kind: 'erc20' },
      [`${TOKEN_C}:${SPENDER}`]: { token: TOKEN_C, spender: SPENDER, kind: 'erc20' },
    },
  };
  const rpc = makeMockRpc();
  const policy = 'RULE r2: IF approval.unlimited THEN REVOKE ALL PRIORITY 7';
  const { ctx } = makeCtx({ policy, cfg, keeperhub: kh, rpc, walletState });

  await handleEvent(approvalEvent({ token: TOKEN_C, txHash: '0xcurrent-attacker' }), ctx);

  assert.deepEqual(
    kh.calls.contractCalls.map((c) => c.to),
    [TOKEN_C, TOKEN_A, TOKEN_B],
    'the triggering token must be revoked first, unrelated backlog follows',
  );
});

test('REVOKE ALL: does not reorder anything when the triggering spender is not in the tracked backlog', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ trackedTokens: [] });
  const walletState = {
    activeApprovals: {
      [`${TOKEN_A}:${SPENDER}`]: { token: TOKEN_A, spender: SPENDER, kind: 'erc20' },
      [`${TOKEN_B}:${SPENDER}`]: { token: TOKEN_B, spender: SPENDER, kind: 'erc20' },
    },
  };
  const rpc = makeMockRpc();
  const policy = 'RULE r2: IF approval.unlimited THEN REVOKE ALL PRIORITY 7';
  const { ctx } = makeCtx({ policy, cfg, keeperhub: kh, rpc, walletState });

  // triggering event's token (TOKEN_C) isn't one of the tracked entries
  await handleEvent(approvalEvent({ token: TOKEN_C, txHash: '0xunrelated' }), ctx);

  assert.deepEqual(kh.calls.contractCalls.map((c) => c.to), [TOKEN_A, TOKEN_B]);
});

test('activeApprovals is pruned immediately on a successful REVOKE, not left for the watcher to notice later', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg();
  const walletState = {
    activeApprovals: {
      [`${TOKEN_A}:${SPENDER}`]: { token: TOKEN_A, spender: SPENDER, kind: 'erc20', unlimited: true },
    },
  };
  const { ctx } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh, walletState });

  const result = await handleEvent(approvalEvent(), ctx);

  assert.equal(result.outcome.success, true);
  assert.equal(
    walletState.activeApprovals[`${TOKEN_A}:${SPENDER}`],
    undefined,
    'a successfully revoked entry must be removed immediately, in-memory',
  );
});

test('activeApprovals keeps a FAILED revoke\'s entry -- only success prunes it', async () => {
  const kh = makeMockKeeperhub();
  kh.failContractCallFor = () => true;
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const walletState = {
    activeApprovals: {
      [`${TOKEN_A}:${SPENDER}`]: { token: TOKEN_A, spender: SPENDER, kind: 'erc20', unlimited: true },
    },
  };
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '0' }, nativeBalance: '0' });
  const { ctx } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh, rpc, walletState });

  await handleEvent(approvalEvent(), ctx);

  assert.ok(
    walletState.activeApprovals[`${TOKEN_A}:${SPENDER}`],
    'a failed revoke must not be pruned -- it still needs a retry/escalation',
  );
});

test('REVOKE ALL: prunes each successfully revoked entry as it goes, keeps the one that failed', async () => {
  const kh = makeMockKeeperhub();
  kh.failContractCallFor = (payload) => payload.to === TOKEN_B;
  const cfg = makeCfg({ trackedTokens: [] });
  const walletState = {
    activeApprovals: {
      [`${TOKEN_A}:${SPENDER}`]: { token: TOKEN_A, spender: SPENDER, kind: 'erc20' },
      [`${TOKEN_B}:${SPENDER}`]: { token: TOKEN_B, spender: SPENDER, kind: 'erc20' },
      [`${TOKEN_C}:${SPENDER}`]: { token: TOKEN_C, spender: SPENDER, kind: 'erc20' },
    },
  };
  const rpc = makeMockRpc();
  const policy = 'RULE r2: IF approval.unlimited THEN REVOKE ALL PRIORITY 7';
  const { ctx } = makeCtx({ policy, cfg, keeperhub: kh, rpc, walletState });

  await handleEvent(approvalEvent(), ctx);

  assert.equal(walletState.activeApprovals[`${TOKEN_A}:${SPENDER}`], undefined, 'A succeeded -- pruned');
  assert.ok(walletState.activeApprovals[`${TOKEN_B}:${SPENDER}`], 'B failed -- kept');
  assert.equal(walletState.activeApprovals[`${TOKEN_C}:${SPENDER}`], undefined, 'C succeeded -- pruned');
});

// ---------------------------------------------------------------------------
// Panic -> EVACUATE, and incident lifecycle
// ---------------------------------------------------------------------------

test('panic event evacuates tracked tokens then native balance to SAFE_ADDRESS, skipping zero balances', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ trackedTokens: [TOKEN_A, TOKEN_B] });
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '1000', [TOKEN_B]: '0' }, nativeBalance: '42' });
  const { ctx } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState: {} });

  const result = await handleEvent({ type: 'panic' }, ctx);

  assert.equal(result.outcome.success, true);
  assert.deepEqual(
    kh.calls.transfers.map((t) => [t.token ?? 'native', t.amount]),
    [
      [TOKEN_A, '1000'],
      ['native', '42'],
    ],
  );
});

test('EVACUATE fetches and passes real per-token decimals, never assumes 18 (e.g. a USDC-shaped 6-decimal token)', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '2500000' }, tokenDecimals: { [TOKEN_A]: 6 }, nativeBalance: '0' });
  const { ctx } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState: {} });

  await handleEvent({ type: 'panic' }, ctx);

  assert.equal(kh.calls.transfers.length, 1);
  assert.equal(kh.calls.transfers[0].decimals, 6);
  assert.equal(kh.calls.transfers[0].amount, '2500000'); // raw wei-equivalent still passed through the mock
});

test('EVACUATE: a decimals-fetch failure fails that token leg without blocking the native leg', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '5000' }, nativeBalance: '42' });
  rpc.getTokenDecimals = async () => {
    throw new Error('mock: decimals() call reverted');
  };
  const { ctx } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState: {} });

  const result = await handleEvent({ type: 'panic' }, ctx);

  assert.equal(result.outcome.success, false, 'the token leg must be reported as failed, not silently skipped');
  assert.equal(kh.calls.transfers.length, 1, 'the native leg must still be attempted');
  assert.equal(kh.calls.transfers[0].token, undefined);
  const failedTokenResult = result.outcome.results.find((r) => r.key === `token:${TOKEN_A}`);
  assert.equal(failedTokenResult.success, false);
  assert.match(failedTokenResult.error, /decimals fetch failed/);
});

test('incident id persists across events in one incident and clears on resolve', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg();
  const walletState = {};
  const { ctx } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh, walletState });

  const first = await handleEvent(approvalEvent(), ctx);
  const second = await handleEvent(approvalEvent({ token: TOKEN_B, txHash: '0xevent2' }), ctx);
  assert.equal(first.incidentId, second.incidentId, 'same incident spans related events');

  resolveCurrentIncident(ctx);
  assert.equal(walletState.currentIncidentId, null);
  assert.equal(walletState.incident.stateName, 'RESOLVED');

  const third = await handleEvent(approvalEvent({ token: TOKEN_C, txHash: '0xevent3' }), ctx);
  assert.notEqual(third.incidentId, first.incidentId, 'post-resolve events start a fresh incident');
  assert.equal(walletState.incident.stateName, 'REVOKING', 'fresh incident advances normally after RESOLVED');
});

test('two separate /panic triggers, with a successful EVACUATE resolving in between, produce two distinct incident ids (regression: three real panics hours apart all reused the same id)', async () => {
  // Confirmed live: three separate manual /panic commands sent hours apart
  // all produced "Evacuation complete for incident <same-id>" every time.
  // Root cause -- nothing ever called resolveCurrentIncident()/
  // resetCurrentIncident() after a successful EVACUATE (both were operator-
  // only, via scripts/reset-incident.mjs), so walletState.currentIncidentId
  // stayed set forever after the FIRST successful EVACUATE, and every
  // subsequent handleEvent() call (line ~366: `if (!currentIncidentId)`)
  // saw it already set and reattached to it instead of minting a fresh one.
  const kh = makeMockKeeperhub();
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const walletState = {};
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '5000' }, nativeBalance: '0' });

  // First /panic -- own KeeperHubClient/ctx per trigger, same as a real
  // watcher process handling two /panic commands hours apart would use the
  // same long-lived ctx but genuinely separate handleEvent() invocations.
  const { ctx: ctx1 } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState });
  const first = await handleEvent({ type: 'panic', observedAt: '2026-07-20T07:57:00.000Z' }, ctx1);

  assert.equal(first.outcome.success, true, 'setup: the first EVACUATE must succeed for this scenario');
  assert.equal(walletState.currentIncidentId, null, 'a successful EVACUATE auto-resolves -- no operator action required');
  assert.equal(walletState.incident.stateName, 'RESOLVED');

  // Second /panic, hours later -- same persisted walletState (as a real
  // restart-surviving watcher process would have), no manual reset run.
  const { ctx: ctx2 } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState });
  const second = await handleEvent({ type: 'panic', observedAt: '2026-07-20T08:04:00.000Z' }, ctx2);

  assert.equal(second.outcome.success, true);
  assert.notEqual(second.incidentId, first.incidentId, 'a genuinely separate manual panic must mint a fresh incident id');

  // Third /panic, for good measure -- matches the exact reported scenario
  // (three triggers, all distinct).
  const { ctx: ctx3 } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState });
  const third = await handleEvent({ type: 'panic', observedAt: '2026-07-20T08:09:00.000Z' }, ctx3);

  assert.equal(third.outcome.success, true);
  assert.notEqual(third.incidentId, first.incidentId);
  assert.notEqual(third.incidentId, second.incidentId);
});

test('no rule matched -> nothing executed, but the null verdict is still recorded as a DECISION', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg();
  // limited approval doesn't match approval.unlimited
  const { ctx } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh });

  const result = await handleEvent(approvalEvent({ amount: '1000', unlimited: false }), ctx);

  assert.equal(result.executed, false);
  assert.equal(result.reason, 'no rule triggered');
  assert.equal(kh.calls.contractCalls.length, 0);
  const records = readAll(cfg.auditLogPath);
  assert.equal(records.length, 1);
  assert.equal(records[0].type, 'DECISION');
  assert.deepEqual(records[0].payload.triggered, []);
  assert.deepEqual(records[0].payload.suppressedByEscalation, []);
  assert.equal(records[0].payload.reason, 'no rule matched this event');
});

test('stale escalated incident: lower-tier rules are suppressed LOUDLY, and operator reset re-arms them (regression: silent armed run)', async () => {
  const kh = makeMockKeeperhub();
  const cfg = makeCfg();
  // exact shape left behind by the pre-fix dry run: incident stuck at tier 3
  const walletState = {
    incident: { stateName: 'EVACUATING', highestTier: 3 },
    currentIncidentId: 'stale-incident-id',
  };
  const { ctx } = makeCtx({ policy: REVOKE_POLICY, cfg, keeperhub: kh, walletState });

  const suppressedRun = await handleEvent(approvalEvent(), ctx);

  assert.equal(suppressedRun.executed, false);
  assert.equal(suppressedRun.reason, 'suppressed by monotonic escalation');
  assert.equal(kh.calls.contractCalls.length, 0, 'suppressed means no execution');
  const decision = readAll(cfg.auditLogPath).find((r) => r.type === 'DECISION');
  assert.equal(decision.payload.incidentId, 'stale-incident-id', 'record must name the blocking incident');
  assert.deepEqual(decision.payload.suppressedByEscalation, [{ ruleName: 'r1', type: 'REVOKE', tier: 1 }]);
  assert.match(decision.payload.reason, /operator reset/);

  // the documented fix: operator reset, then the same event executes exactly once
  resetCurrentIncident(ctx);
  assert.equal(walletState.currentIncidentId, null, 'reset clears the stale incident id');
  assert.equal(walletState.incident.stateName, 'IDLE', 'reset returns the machine to IDLE');

  const rearmedRun = await handleEvent(approvalEvent(), ctx);
  assert.equal(rearmedRun.executed, true, 'after reset, the same event is no longer suppressed');
  assert.equal(kh.calls.contractCalls.length, 1, 'executes exactly once -- no double-response from the earlier suppressed attempt');
  assert.equal(rearmedRun.tier, 1);
});
