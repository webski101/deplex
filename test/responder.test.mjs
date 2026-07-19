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

  // retry with transfers now healthy, simulating a restart (fresh ctx,
  // completedKeys re-derived from the on-disk audit chain): the failed
  // EXECUTION_RESULT must NOT count as completed, so the leg runs again
  kh.failTransfers = false;
  const { ctx: ctx2 } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState });
  const second = await handleEvent({ type: 'panic' }, ctx2);

  assert.equal(kh.calls.transfers.length, 2, 'failed attempt must be retryable');
  assert.equal(second.outcome.success, true);

  // and a third run now skips: the succeeded leg IS recorded as completed
  const { ctx: ctx3 } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState });
  await handleEvent({ type: 'panic' }, ctx3);
  assert.equal(kh.calls.transfers.length, 2, 'succeeded attempt must not re-execute');
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

  // incident state machine ended at EVACUATING
  assert.equal(walletState.incident.stateName, 'EVACUATING');
  assert.equal(walletState.incident.highestTier, 3);
});

test('EVACUATE failure has no higher tier: alerts CRITICAL and stops (no infinite recursion)', async () => {
  const kh = makeMockKeeperhub();
  kh.failTransfers = true;
  const cfg = makeCfg({ trackedTokens: [TOKEN_A] });
  const rpc = makeMockRpc({ tokenBalances: { [TOKEN_A]: '5000' }, nativeBalance: '0' });
  const { ctx, alerts } = makeCtx({ policy: PANIC_POLICY, cfg, keeperhub: kh, rpc, walletState: {} });

  const result = await handleEvent({ type: 'panic', observedAt: 'now' }, ctx);

  assert.equal(result.outcome.success, false);
  assert.equal(alerts.filter((a) => a.includes('CRITICAL')).length, 1);
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
