import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compile, evaluate, advanceIncident, resolveIncident, resetIncident } from '../src/policy.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_POLICY_PATH = join(__dirname, '..', 'policies', 'default.policy');

const SPENDER_UNKNOWN = '0x' + 'a'.repeat(40);
const SPENDER_ALLOWLISTED = '0x' + 'b'.repeat(40);
const RECIPIENT_UNKNOWN = '0x' + 'c'.repeat(40);
const MAX_UINT256 = ((1n << 256n) - 1n).toString();

function walletWith(allowlist = [SPENDER_ALLOWLISTED], extra = {}) {
  return { allowlist, balance: 1000, ...extra };
}

// ---------------------------------------------------------------------------
// default.policy compiles cleanly
// ---------------------------------------------------------------------------

test('default.policy compiles with zero errors and four rules', () => {
  const text = readFileSync(DEFAULT_POLICY_PATH, 'utf8');
  const { rules, errors } = compile(text);
  assert.deepEqual(errors, []);
  assert.equal(rules.length, 4);
});

// ---------------------------------------------------------------------------
// Parse errors - line-numbered, never throw
// ---------------------------------------------------------------------------

test('parse error: missing colon after rule name is line-numbered, not thrown', () => {
  const text = 'RULE bad-rule IF panic.triggered THEN EVACUATE';
  assert.doesNotThrow(() => compile(text));
  const { rules, errors } = compile(text);
  assert.equal(rules.length, 0);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
});

test('parse error: unrecognized statement is line-numbered', () => {
  const text = 'THIS IS NOT VALID SYNTAX';
  const { errors } = compile(text);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
  assert.match(errors[0].message, /unrecognized statement/);
});

test('parse error: invalid address in WATCH WALLET is line-numbered', () => {
  const text = 'WATCH WALLET not-an-address';
  const { errors, config } = compile(text);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
  assert.equal(config.watchWallet, null);
});

test('parse error: unknown action is line-numbered', () => {
  const text = 'RULE r: IF panic.triggered THEN DESTROY_EVERYTHING';
  const { errors } = compile(text);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
  assert.match(errors[0].message, /unknown action/);
});

test('parse error: PRIORITY out of range (0 and 11) is line-numbered', () => {
  const text = [
    'RULE r1: IF panic.triggered THEN EVACUATE PRIORITY 0',
    'RULE r2: IF panic.triggered THEN EVACUATE PRIORITY 11',
  ].join('\n');
  const { errors, rules } = compile(text);
  assert.equal(rules.length, 0);
  assert.equal(errors.length, 2);
  assert.equal(errors[0].line, 1);
  assert.equal(errors[1].line, 2);
});

test('parse error: dangling AND is line-numbered', () => {
  const text = 'RULE r: IF panic.triggered AND THEN EVACUATE';
  const { errors } = compile(text);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
});

test('parse error: unbalanced parentheses is line-numbered', () => {
  const text = 'RULE r: IF (panic.triggered THEN EVACUATE';
  const { errors } = compile(text);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
});

test('parse error: duplicate rule name is line-numbered, first rule still kept', () => {
  const text = [
    'RULE dup: IF panic.triggered THEN ALERT',
    'RULE dup: IF panic.triggered THEN EVACUATE',
  ].join('\n');
  const { errors, rules } = compile(text);
  assert.equal(rules.length, 1);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 2);
});

test('one bad line does not stop the rest of the file from compiling', () => {
  const text = [
    'GARBAGE LINE',
    'RULE ok: IF panic.triggered THEN EVACUATE',
  ].join('\n');
  const { errors, rules } = compile(text);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].name, 'ok');
});

// ---------------------------------------------------------------------------
// Each condition type
// ---------------------------------------------------------------------------

test('condition: approval.new only matches approval-type events', () => {
  const { rules } = compile('RULE r: IF approval.new THEN ALERT');
  assert.equal(evaluate(rules, { type: 'approval' }, walletWith()).length, 1);
  assert.equal(evaluate(rules, { type: 'transfer' }, walletWith()).length, 0);
});

test('condition: approval.unlimited true for max uint256 and > 10^30, false otherwise', () => {
  const { rules } = compile('RULE r: IF approval.unlimited THEN ALERT');
  assert.equal(evaluate(rules, { type: 'approval', amount: MAX_UINT256 }, walletWith()).length, 1);
  assert.equal(evaluate(rules, { type: 'approval', amount: (10n ** 31n).toString() }, walletWith()).length, 1);
  assert.equal(evaluate(rules, { type: 'approval', amount: '1000000' }, walletWith()).length, 0);
});

test('condition: approval.spender NOT ALLOWLISTED', () => {
  const { rules } = compile('RULE r: IF approval.spender NOT ALLOWLISTED THEN ALERT');
  assert.equal(evaluate(rules, { type: 'approval', spender: SPENDER_UNKNOWN }, walletWith()).length, 1);
  assert.equal(evaluate(rules, { type: 'approval', spender: SPENDER_ALLOWLISTED }, walletWith()).length, 0);
});

test('condition: approval.spender RISK > N compares against provided risk value', () => {
  const { rules } = compile('RULE r: IF approval.spender RISK > 70 THEN ALERT');
  assert.equal(evaluate(rules, { type: 'approval', spenderRisk: 80 }, walletWith()).length, 1);
  assert.equal(evaluate(rules, { type: 'approval', spenderRisk: 50 }, walletWith()).length, 0);
});

test('condition: RISK unavailable defaults to 100 (fail-closed)', () => {
  const { rules } = compile('RULE r: IF approval.spender RISK > 70 THEN ALERT');
  const triggered = evaluate(rules, { type: 'approval', spender: SPENDER_UNKNOWN }, walletWith());
  assert.equal(triggered.length, 1, 'missing risk score must fail closed as worst-case (100), not skip the rule');
});

test('condition: transfer.out.value > N% OF WALLET using precomputed percentOfWallet', () => {
  const { rules } = compile('RULE r: IF transfer.out.value > 20% OF WALLET THEN ALERT');
  assert.equal(evaluate(rules, { type: 'transfer', percentOfWallet: 25 }, walletWith()).length, 1);
  assert.equal(evaluate(rules, { type: 'transfer', percentOfWallet: 10 }, walletWith()).length, 0);
});

test('condition: transfer.out.value falls back to value/balance when percentOfWallet absent', () => {
  const { rules } = compile('RULE r: IF transfer.out.value > 20% OF WALLET THEN ALERT');
  const triggered = evaluate(rules, { type: 'transfer', value: 300 }, walletWith([SPENDER_ALLOWLISTED], { balance: 1000 }));
  assert.equal(triggered.length, 1);
});

test('condition: transfer.out.value never fires for a zero-value transfer, even with unknown wallet balance (regression: false EVACUATE on a blocked drain attempt)', () => {
  // Confirmed live: a zero-value transferFrom (a drain attempt with no real
  // allowance to move) was misread by the fail-closed "unknown balance"
  // path as Infinity% of wallet, firing EVACUATE for a transaction that
  // moved nothing. balance:undefined reproduces the untracked-token case
  // that triggered it (TRACKED_TOKENS didn't include the drained token).
  const { rules } = compile('RULE r: IF transfer.out.value > 20% OF WALLET THEN EVACUATE');
  const triggered = evaluate(rules, { type: 'transfer', value: '0' }, walletWith([], { balance: undefined }));
  assert.deepEqual(triggered, []);
});

test('condition: transfer.out.value still fails closed (fires) for a genuine nonzero-value transfer with unknown balance', () => {
  const { rules } = compile('RULE r: IF transfer.out.value > 20% OF WALLET THEN EVACUATE');
  const triggered = evaluate(rules, { type: 'transfer', value: '500' }, walletWith([], { balance: undefined }));
  assert.equal(triggered.length, 1, 'a real, nonzero outflow with unknown balance must still fail closed');
});

test('condition: transfer.out.to NOT ALLOWLISTED', () => {
  const { rules } = compile('RULE r: IF transfer.out.to NOT ALLOWLISTED THEN ALERT');
  assert.equal(evaluate(rules, { type: 'transfer', to: RECIPIENT_UNKNOWN }, walletWith()).length, 1);
  assert.equal(evaluate(rules, { type: 'transfer', to: SPENDER_ALLOWLISTED }, walletWith()).length, 0);
});

test('condition: panic.triggered only matches panic-type events', () => {
  const { rules } = compile('RULE r: IF panic.triggered THEN EVACUATE');
  assert.equal(evaluate(rules, { type: 'panic' }, walletWith()).length, 1);
  assert.equal(evaluate(rules, { type: 'approval' }, walletWith()).length, 0);
});

// ---------------------------------------------------------------------------
// AND/OR precedence and parentheses
// ---------------------------------------------------------------------------

test('AND binds tighter than OR: "A OR B AND C" is "A OR (B AND C)"', () => {
  // approval.new(true) OR (approval.unlimited(false) AND panic.triggered(true)) => true via left disjunct
  const { rules } = compile('RULE r: IF approval.new OR approval.unlimited AND panic.triggered THEN ALERT');
  const triggered = evaluate(rules, { type: 'approval', amount: '1' }, walletWith());
  assert.equal(triggered.length, 1, 'approval.new alone should satisfy the OR regardless of the AND clause');
});

test('parentheses override default precedence', () => {
  // (approval.new OR approval.unlimited) AND panic.triggered -- now requires panic.triggered too
  const { rules } = compile('RULE r: IF (approval.new OR approval.unlimited) AND panic.triggered THEN ALERT');
  const triggeredNoPanic = evaluate(rules, { type: 'approval', amount: '1' }, walletWith());
  assert.equal(triggeredNoPanic.length, 0, 'grouped OR must not short-circuit the required AND panic.triggered');
});

// ---------------------------------------------------------------------------
// Priority ordering + deterministic tie-break
// ---------------------------------------------------------------------------

test('evaluate() orders triggered actions by priority, highest first', () => {
  const text = [
    'RULE low: IF panic.triggered THEN ALERT PRIORITY 2',
    'RULE high: IF panic.triggered THEN EVACUATE PRIORITY 9',
  ].join('\n');
  const { rules } = compile(text);
  const triggered = evaluate(rules, { type: 'panic' }, walletWith());
  assert.deepEqual(triggered.map((t) => t.ruleName), ['high', 'low']);
});

test('evaluate() tie-breaks equal priority deterministically by rule name', () => {
  const text = [
    'RULE zebra: IF panic.triggered THEN ALERT PRIORITY 5',
    'RULE apple: IF panic.triggered THEN ALERT PRIORITY 5',
  ].join('\n');
  const { rules } = compile(text);
  const triggered = evaluate(rules, { type: 'panic' }, walletWith());
  assert.deepEqual(triggered.map((t) => t.ruleName), ['apple', 'zebra']);
});

test('unspecified PRIORITY defaults to 5', () => {
  const { rules } = compile('RULE r: IF panic.triggered THEN ALERT');
  assert.equal(rules[0].priority, 5);
});

// ---------------------------------------------------------------------------
// Monotonic escalation
// ---------------------------------------------------------------------------

test('monotonic escalation: once REVOKE ALL (tier 2) has fired, a REVOKE (tier 1) rule is moot', () => {
  const text = [
    'RULE revoke-one: IF approval.spender NOT ALLOWLISTED THEN REVOKE PRIORITY 5',
  ].join('\n');
  const { rules } = compile(text);
  const wallet = walletWith();
  wallet.incident = { stateName: 'REVOKING', highestTier: 2 };
  const triggered = evaluate(rules, { type: 'approval', spender: SPENDER_UNKNOWN }, wallet);
  assert.equal(triggered.length, 0, 'a lower-tier rule must not re-fire once a higher tier has already been reached');
});

test('monotonic escalation: a higher tier (EVACUATE) still fires after REVOKE ALL', () => {
  const text = 'RULE go-evacuate: IF panic.triggered THEN EVACUATE PRIORITY 10';
  const { rules } = compile(text);
  const wallet = walletWith();
  wallet.incident = { stateName: 'REVOKING', highestTier: 2 };
  const triggered = evaluate(rules, { type: 'panic' }, wallet);
  assert.equal(triggered.length, 1, 'a strictly higher tier must still be allowed to fire');
});

test('advanceIncident() moves state forward and tracks the highest tier reached', () => {
  let incident = resetIncident();
  assert.deepEqual(incident, { stateName: 'IDLE', highestTier: -1 });

  incident = advanceIncident(incident, [{ action: { tier: 0, type: 'ALERT' } }]);
  assert.equal(incident.stateName, 'ALERTED');
  assert.equal(incident.highestTier, 0);

  incident = advanceIncident(incident, [{ action: { tier: 2, type: 'REVOKE_ALL' } }]);
  assert.equal(incident.stateName, 'REVOKING');
  assert.equal(incident.highestTier, 2);

  // A lower tier arriving later must not move the state backward.
  incident = advanceIncident(incident, [{ action: { tier: 1, type: 'REVOKE' } }]);
  assert.equal(incident.stateName, 'REVOKING');
  assert.equal(incident.highestTier, 2);

  incident = advanceIncident(incident, [{ action: { tier: 3, type: 'EVACUATE' } }]);
  assert.equal(incident.stateName, 'EVACUATING');
  assert.equal(incident.highestTier, 3);
});

test('resolveIncident() returns a terminal RESOLVED state', () => {
  assert.deepEqual(resolveIncident(), { stateName: 'RESOLVED', highestTier: -1 });
});

test('advanceIncident() progresses normally for a fresh incident that starts from a prior RESOLVED state', () => {
  // Regression: INCIDENT_STATES orders RESOLVED last (it's a terminal marker,
  // not a rank), so comparing array positions directly left a second
  // incident's stateName stuck at RESOLVED forever instead of advancing to
  // ALERTED/REVOKING/EVACUATING.
  const resolved = resolveIncident();
  const triggered = [{ ruleName: 'r', action: { type: 'ALERT', tier: 0 }, priority: 5 }];
  const next = advanceIncident(resolved, triggered);
  assert.equal(next.stateName, 'ALERTED');
  assert.equal(next.highestTier, 0);
});

test('transfer.* conditions never trigger on approval events (regression: dry-run EVACUATE misfire)', () => {
  const { rules, errors } = compile(
    'RULE evac: IF transfer.out.value > 20% OF WALLET AND transfer.out.to NOT ALLOWLISTED THEN EVACUATE PRIORITY 9',
  );
  assert.equal(errors.length, 0);
  // approval events have `amount`, not `value`; before type-gating, the
  // missing-value path evaluated as Infinity% of wallet and fired EVACUATE
  const approval = { type: 'approval', token: '0x' + 'aa'.repeat(20), spender: SPENDER_UNKNOWN, amount: MAX_UINT256 };
  assert.deepEqual(evaluate(rules, approval, {}), []);
});

test('approval.* conditions never trigger on transfer events', () => {
  const { rules, errors } = compile(
    'RULE r: IF approval.spender NOT ALLOWLISTED AND approval.spender RISK > 70 THEN REVOKE ALL PRIORITY 7\n' +
      'RULE u: IF approval.unlimited THEN REVOKE PRIORITY 5',
  );
  assert.equal(errors.length, 0);
  // transfers have no spender; before type-gating, "spender undefined" read
  // as not-allowlisted and RISK fail-closed to 100, firing REVOKE ALL
  const transfer = { type: 'transfer', token: '0x' + 'aa'.repeat(20), to: RECIPIENT_UNKNOWN, value: '10' };
  assert.deepEqual(evaluate(rules, transfer, { balance: '1000000' }), []);
});

test('default policy on a live-shaped unlimited approval: REVOKE ALL + REVOKE, tier 2 max -- never EVACUATE', () => {
  const { rules, errors } = compile(readFileSync(DEFAULT_POLICY_PATH, 'utf8'));
  assert.equal(errors.length, 0);
  // exact shape watcher.mjs emits for a MetaMask unlimited approval
  const event = {
    type: 'approval',
    kind: 'erc20',
    token: '0x' + 'aa'.repeat(20),
    owner: '0x' + '22'.repeat(20),
    spender: SPENDER_UNKNOWN,
    amount: MAX_UINT256,
    unlimited: true,
    txHash: '0xlive',
    block: 1,
  };
  const triggered = evaluate(rules, event, { allowlist: [] });
  assert.deepEqual(
    triggered.map((t) => [t.ruleName, t.action.type]),
    [
      ['high-risk-unknown-spender', 'REVOKE_ALL'], // priority 7; RISK fail-closes to 100 until intel.mjs (Phase 5) exists
      ['unlimited-approval-unknown-spender', 'REVOKE'], // priority 5
    ],
  );
  const highestTier = Math.max(...triggered.map((t) => t.action.tier));
  assert.equal(highestTier, 2, 'must cap at REVOKE ALL -- EVACUATE firing here was the dry-run bug');
});

test('evaluate() never throws on missing/empty walletState', () => {
  const { rules } = compile('RULE r: IF approval.spender NOT ALLOWLISTED AND approval.spender RISK > 50 THEN REVOKE');
  assert.doesNotThrow(() => evaluate(rules, { type: 'approval', spender: SPENDER_UNKNOWN }, {}));
  assert.doesNotThrow(() => evaluate(rules, { type: 'approval', spender: SPENDER_UNKNOWN }, undefined));
});
