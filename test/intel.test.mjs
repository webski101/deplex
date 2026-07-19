import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { getRiskScore, signAuthorization, IntelError } from '../src/intel.mjs';
import { signPayload, createIntelAgentServer } from '../intel-agent/server.mjs';
import { readAll } from '../src/auditlog.mjs';
import { keccak256, hexToBytes, privateKeyToAddress, _pointMultiplyG } from '../attack/crypto.mjs';

const SPENDER = '0x' + 'aa'.repeat(20);
const PAY_TO = '0x' + 'bb'.repeat(20);
const ASSET = '0x' + 'cc'.repeat(20);
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function freshEdKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

// ---------------------------------------------------------------------------
// signAuthorization -- EIP-712 digest construction + signing
// ---------------------------------------------------------------------------

function baseRequirement(overrides = {}) {
  return {
    maxAmountRequired: '1000',
    asset: ASSET,
    payTo: PAY_TO,
    network: 'base-sepolia',
    maxTimeoutSeconds: 60,
    extra: { name: 'USDC', version: '2' },
    ...overrides,
  };
}

// First-principles ECDSA equation check (u1*G + u2*Q = R), same method as
// test/attack-crypto.test.mjs's verifyFromScratch -- independent of
// node:crypto's own hashing quirks (crypto.verify(null, ...) for a plain EC
// key silently defaults to SHA-256 rather than skipping hashing, which is
// NOT what's needed to check a raw pre-hashed digest; see that file's
// comment for the full explanation of why this method is used instead).
function verifyEcdsaEquation(digest32, r, s, privateKeyBigInt) {
  const modPow = (base, exp, mod) => {
    let b = ((base % mod) + mod) % mod;
    let e = exp;
    let result = 1n;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % mod;
      e >>= 1n;
      b = (b * b) % mod;
    }
    return result;
  };
  const modInv = (a, mod) => modPow(a, mod - 2n, mod);
  let z = 0n;
  for (const b of digest32) z = (z << 8n) | BigInt(b);
  z %= SECP256K1_N;
  const sInv = modInv(s, SECP256K1_N);
  const u1 = (z * sInv) % SECP256K1_N;
  const u2 = (r * sInv) % SECP256K1_N;
  const combined = (u1 + u2 * privateKeyBigInt) % SECP256K1_N;
  return _pointMultiplyG(combined).x % SECP256K1_N === r;
}

// Independently rebuilds the EIP-712 digest from scratch (not by calling any
// intel.mjs internals) so this is a real cross-check, not intel.mjs checking
// its own math.
function rebuildDigest(authorization, { name, version, chainId, verifyingContract }) {
  const concatBytes = (...arrs) => {
    const total = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  };
  const leftPad32 = (bytes) => {
    const out = new Uint8Array(32);
    out.set(bytes, 32 - bytes.length);
    return out;
  };
  const encodeAddr = (a) => leftPad32(hexToBytes(a));
  const encodeU256 = (v) => {
    const hex = v.toString(16);
    return leftPad32(hexToBytes('0x' + (hex.length % 2 ? '0' + hex : hex)));
  };
  const DOMAIN_TH = keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)');
  const TRANSFER_TH = keccak256(
    'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)',
  );
  const domainSeparator = keccak256(
    concatBytes(DOMAIN_TH, keccak256(name), keccak256(version), encodeU256(BigInt(chainId)), encodeAddr(verifyingContract)),
  );
  const structHash = keccak256(
    concatBytes(
      TRANSFER_TH,
      encodeAddr(authorization.from),
      encodeAddr(authorization.to),
      encodeU256(BigInt(authorization.value)),
      encodeU256(BigInt(authorization.validAfter)),
      encodeU256(BigInt(authorization.validBefore)),
      hexToBytes(authorization.nonce),
    ),
  );
  return keccak256(concatBytes(hexToBytes('0x1901'), domainSeparator, structHash));
}

test('signAuthorization produces a signature whose (r,s) satisfy the ECDSA equation for an independently rebuilt EIP-712 digest', () => {
  const priv = BigInt('0x' + randomBytes(32).toString('hex'));
  const privHex = priv.toString(16).padStart(64, '0');
  const requirement = baseRequirement();

  const { signature, authorization } = signAuthorization(privHex, requirement, {
    nowSeconds: 1_000_000,
    nonce: '0x' + '11'.repeat(32),
  });

  assert.equal(authorization.from, privateKeyToAddress(privHex));
  assert.equal(authorization.to, PAY_TO);
  assert.equal(authorization.value, '1000');
  // validAfter = now - 600, validBefore = now + maxTimeoutSeconds -- matches
  // the coinbase/x402 reference client's ExactEvmSchemeV1 exactly (confirmed
  // 2026-07-18, see X402-NOTES.md), not the earlier validAfter="0" guess.
  assert.equal(authorization.validAfter, String(1_000_000 - 600));
  assert.equal(authorization.validBefore, String(1_000_000 + 60));

  const digest = rebuildDigest(authorization, { name: 'USDC', version: '2', chainId: 84532, verifyingContract: ASSET });
  const sigBytes = hexToBytes(signature);
  assert.equal(sigBytes.length, 65);
  const r = BigInt('0x' + Buffer.from(sigBytes.subarray(0, 32)).toString('hex'));
  const s = BigInt('0x' + Buffer.from(sigBytes.subarray(32, 64)).toString('hex'));
  const v = sigBytes[64];
  assert.ok(v === 27 || v === 28, 'v must be the ecrecover-compatible 27/28 convention');
  assert.equal(verifyEcdsaEquation(digest, r, s, priv), true);
});

test('signAuthorization throws IntelError when the requirement is missing extra.name/version', () => {
  const privHex = randomBytes(32).toString('hex');
  const requirement = baseRequirement({ extra: {} });
  assert.throws(() => signAuthorization(privHex, requirement), IntelError);
});

test('signAuthorization throws IntelError for an unrecognized x402 network', () => {
  const privHex = randomBytes(32).toString('hex');
  const requirement = baseRequirement({ network: 'some-unknown-testnet' });
  assert.throws(() => signAuthorization(privHex, requirement), IntelError);
});

// ---------------------------------------------------------------------------
// getRiskScore -- the full buyer flow, fail-closed behavior, budget cap
// ---------------------------------------------------------------------------

let tmpDir;
let agentKeypair;
let payerPrivateKey;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'deplex-intel-'));
  agentKeypair = freshEdKeypair();
  payerPrivateKey = randomBytes(32).toString('hex');
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function makeCfg(overrides = {}) {
  return {
    auditLogPath: join(tmpDir, 'audit.jsonl'),
    maxIntelSpend: 100_000,
    intelAgent: {
      url: 'http://intel-agent.invalid',
      publicKeyPem: agentKeypair.publicKeyPem,
      payerPrivateKey,
      requestTimeoutMs: 5000,
    },
    ...overrides,
  };
}

function signedScoreBody(score, reasons = ['test reason']) {
  const payload = { address: SPENDER.toLowerCase(), score, reasons };
  const signature = signPayload(agentKeypair.privateKeyPem, payload);
  return { ...payload, signature, publicKeyPem: agentKeypair.publicKeyPem };
}

const REQUIREMENT_402 = {
  x402Version: 1,
  error: 'payment required',
  accepts: [
    {
      scheme: 'exact',
      network: 'base-sepolia',
      maxAmountRequired: '1000',
      asset: ASSET,
      payTo: PAY_TO,
      resource: `/score/${SPENDER}`,
      description: 'Deplex spender risk score',
      mimeType: 'application/json',
      outputSchema: null,
      maxTimeoutSeconds: 60,
      extra: { assetTransferMethod: 'eip3009', name: 'USDC', version: '2' },
    },
  ],
};

// Sequenced mock: each call to httpRequestJson pops the next scripted
// response. Records every call for assertions on call count/headers.
function makeScriptedFetch(responses) {
  const calls = [];
  let i = 0;
  return {
    calls,
    fn: async (url, opts) => {
      calls.push({ url, opts });
      if (i >= responses.length) throw new Error('scripted fetch called more times than expected');
      const next = responses[i++];
      if (next instanceof Error) throw next;
      return next;
    },
  };
}

test('getRiskScore: happy path pays on 402, verifies the signed response, and records an INTEL_PURCHASE', async () => {
  const cfg = makeCfg();
  const { fn, calls } = makeScriptedFetch([
    { statusCode: 402, body: REQUIREMENT_402 },
    { statusCode: 200, body: signedScoreBody(17, ['contract age ~30d, over the 7-day threshold']) },
  ]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 17);
  assert.equal(result.purchased, true);
  assert.equal(calls.length, 2);
  assert.ok(calls[1].opts.headers['X-PAYMENT'], 'second call must carry the X-PAYMENT header');

  // The X-PAYMENT payload must be the full v1 envelope -- {x402Version,
  // scheme, network, payload: {signature, authorization}} -- not the bare
  // {signature, authorization} pair. Confirmed against the coinbase/x402
  // reference SDK's PaymentPayloadV1 type and a live facilitator call that
  // only produced a coherent response in this exact shape (X402-NOTES.md).
  const decoded = JSON.parse(Buffer.from(calls[1].opts.headers['X-PAYMENT'], 'base64').toString('utf8'));
  assert.equal(decoded.x402Version, 1);
  assert.equal(decoded.scheme, 'exact');
  assert.equal(decoded.network, 'base-sepolia');
  assert.ok(decoded.payload.signature);
  assert.ok(decoded.payload.authorization);
  assert.equal(decoded.payload.authorization.to, PAY_TO);

  const records = readAll(cfg.auditLogPath).filter((r) => r.type === 'INTEL_PURCHASE');
  assert.equal(records.length, 1);
  assert.equal(records[0].payload.failed, false);
  assert.equal(records[0].payload.score, 17);
  assert.equal(records[0].payload.amount, '1000');
  assert.equal(records[0].payload.incidentId, 'inc-1');
});

// Regression: a real live purchase settled successfully (score delivered,
// signature verified) but its audit record had no settlement transaction
// reference at all -- httpRequestJson dropped response headers entirely, so
// the X-PAYMENT-RESPONSE header (where the real tx hash lives, per
// intel-agent/server.mjs) was never read. Confirmed by inspecting a real
// audit record after a real Base Sepolia settlement. Fixed by capturing
// response headers and decoding this one; these tests cover both the happy
// path and a missing/malformed header not blocking the purchase itself.
test('getRiskScore: captures the settlement transaction reference from X-PAYMENT-RESPONSE into the audit record', async () => {
  const cfg = makeCfg();
  const settlementHeader = Buffer.from(
    JSON.stringify({ success: true, transaction: '0xREALTXHASH', network: 'base-sepolia', payer: '0xpayerAddr' }),
  ).toString('base64');
  const { fn } = makeScriptedFetch([
    { statusCode: 402, body: REQUIREMENT_402 },
    { statusCode: 200, headers: { 'x-payment-response': settlementHeader }, body: signedScoreBody(9) },
  ]);

  await getRiskScore(SPENDER, { cfg, incidentId: 'inc-tx', httpRequestJson: fn });

  const records = readAll(cfg.auditLogPath).filter((r) => r.type === 'INTEL_PURCHASE');
  assert.equal(records.length, 1);
  assert.equal(records[0].payload.transaction, '0xREALTXHASH');
  assert.equal(records[0].payload.payer, '0xpayerAddr');
});

test('getRiskScore: a missing or malformed X-PAYMENT-RESPONSE header does not block a purchase that otherwise succeeded', async () => {
  const cfg = makeCfg();
  const { fn: fnMissing } = makeScriptedFetch([
    { statusCode: 402, body: REQUIREMENT_402 },
    { statusCode: 200, body: signedScoreBody(9) }, // no headers at all
  ]);
  const resultMissing = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-missing', httpRequestJson: fnMissing });
  assert.equal(resultMissing.purchased, true);
  assert.equal(resultMissing.risk, 9);

  const { fn: fnMalformed } = makeScriptedFetch([
    { statusCode: 402, body: REQUIREMENT_402 },
    { statusCode: 200, headers: { 'x-payment-response': 'not-valid-base64-json!!' }, body: signedScoreBody(9) },
  ]);
  const resultMalformed = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-malformed', httpRequestJson: fnMalformed });
  assert.equal(resultMalformed.purchased, true);
  assert.equal(resultMalformed.risk, 9);
});

// True wire-level test: a REAL createIntelAgentServer and the REAL (not
// mocked) httpRequestJson, so a header-name or encoding mismatch between
// the two sides -- exactly the class of bug that let this slip through
// unit tests mocking one side or the other -- would actually be caught.
test('getRiskScore: end-to-end against a real server captures the real X-PAYMENT-RESPONSE settlement reference', async () => {
  const agentKeypair2 = freshEdKeypair();
  const serverCfg = {
    rpcUrl: 'http://unused.invalid',
    payToAddress: PAY_TO,
    priceAtomic: '1000',
    assetAddress: ASSET,
    assetName: 'USDC',
    assetVersion: '2',
    network: 'base-sepolia',
    maxTimeoutSeconds: 60,
  };
  const server = createIntelAgentServer(serverCfg, {
    keypair: agentKeypair2,
    denylist: new Set([SPENDER.toLowerCase()]), // short-circuits scoreAddress, no RPC needed
    facilitatorVerify: async () => ({ isValid: true, payer: '0xrealpayer' }),
    facilitatorSettle: async () => ({ success: true, transaction: '0xREAL_E2E_TX', network: 'base-sepolia', payer: '0xrealpayer' }),
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  const cfg = makeCfg({ intelAgent: { ...makeCfg().intelAgent, url: `http://127.0.0.1:${port}`, publicKeyPem: agentKeypair2.publicKeyPem } });
  try {
    const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-e2e' }); // no httpRequestJson override -- the real one
    assert.equal(result.purchased, true);

    const records = readAll(cfg.auditLogPath).filter((r) => r.type === 'INTEL_PURCHASE');
    assert.equal(records.length, 1);
    assert.equal(records[0].payload.transaction, '0xREAL_E2E_TX');
    assert.equal(records[0].payload.payer, '0xrealpayer');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

// Regression: a live run left an undiagnosable gap -- the server logged the
// initial 402 and nothing else, and there was no way to tell whether the
// client ever built or sent a payment retry, or hung before reaching the
// network. getRiskScore now logs each stage; these tests pin the exact
// sequence and, more importantly, confirm that whichever stage a failure
// happens at, logging stops exactly there -- so a future hang is
// diagnosable from "last line printed" alone, not by reconstruction.
test('getRiskScore: logs every stage in order on a full successful paid purchase', async () => {
  const cfg = makeCfg();
  const { fn } = makeScriptedFetch([
    { statusCode: 402, body: REQUIREMENT_402 },
    { statusCode: 200, body: signedScoreBody(17) },
  ]);
  const messages = [];

  await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn, log: (m) => messages.push(m) });

  assert.ok(messages[0].includes('requesting score'));
  assert.ok(messages.some((m) => m.includes('received 402')));
  assert.ok(messages.some((m) => m.includes('building and signing')));
  assert.ok(messages.some((m) => m.includes('authorization signed')));
  assert.ok(messages.some((m) => m.includes('sending payment retry')));
  assert.ok(messages.some((m) => m.includes('received response to retry: HTTP 200')));
  assert.ok(messages.some((m) => m.includes('response signature verified')));
  // Stage order matters as much as presence -- confirms signing genuinely
  // happens before the retry is sent, not just that both log lines exist.
  const signedIdx = messages.findIndex((m) => m.includes('authorization signed'));
  const sendingIdx = messages.findIndex((m) => m.includes('sending payment retry'));
  assert.ok(signedIdx < sendingIdx, 'authorization must be signed before the retry is sent');
});

test('getRiskScore: logging stops exactly at the stage where a hang/failure would occur (retry sent, no response)', async () => {
  const cfg = makeCfg();
  const { fn } = makeScriptedFetch([
    { statusCode: 402, body: REQUIREMENT_402 },
    new Error('intel agent request timed out after 20000ms'), // simulates the retry itself hanging
  ]);
  const messages = [];

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn, log: (m) => messages.push(m) });

  assert.equal(result.risk, 100);
  assert.ok(messages.some((m) => m.includes('sending payment retry')), 'must reach the retry-send stage');
  assert.ok(!messages.some((m) => m.includes('received response to retry')), 'must NOT log a response that never arrived');
  assert.ok(messages.some((m) => m.includes('failed closed')), 'the failure itself must be logged too');
});

test('getRiskScore: an immediate 200 (no payment required) is accepted without an INTEL_PURCHASE record', async () => {
  const cfg = makeCfg();
  const { fn, calls } = makeScriptedFetch([{ statusCode: 200, body: signedScoreBody(3) }]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 3);
  assert.equal(result.purchased, false);
  assert.equal(calls.length, 1);
  assert.equal(readAll(cfg.auditLogPath).filter((r) => r.type === 'INTEL_PURCHASE').length, 0);
});

test('getRiskScore: fails closed to 100 when the 402 body has no payment requirements', async () => {
  const cfg = makeCfg();
  const { fn } = makeScriptedFetch([{ statusCode: 402, body: { x402Version: 1, error: 'payment required' } }]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason.includes('payment requirements'));
  const records = readAll(cfg.auditLogPath).filter((r) => r.type === 'INTEL_PURCHASE');
  assert.equal(records.length, 1);
  assert.equal(records[0].payload.failed, true);
  assert.equal(records[0].payload.score, 100);
});

test('getRiskScore: fails closed to 100 when the paid retry does not return 200', async () => {
  const cfg = makeCfg();
  const { fn } = makeScriptedFetch([
    { statusCode: 402, body: REQUIREMENT_402 },
    { statusCode: 402, body: { x402Version: 1, error: 'payment invalid' } },
  ]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason.includes('payment invalid') || result.failClosedReason.includes('402'));
});

test('getRiskScore: fails closed to 100 when the response signature does not verify (tampered score)', async () => {
  const cfg = makeCfg();
  const signed = signedScoreBody(5);
  const tampered = { ...signed, score: 99 }; // score changed after signing -- signature now invalid
  const { fn } = makeScriptedFetch([{ statusCode: 200, body: tampered }]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason.includes('signature'));
});

test('getRiskScore: never trusts a publicKeyPem embedded in the response body itself', async () => {
  const cfg = makeCfg();
  const attackerKeypair = freshEdKeypair();
  const payload = { address: SPENDER.toLowerCase(), score: 1, reasons: [] };
  // Signed by an attacker's own key, but claims to be verifiable and embeds
  // the attacker's OWN public key -- must still fail because getRiskScore
  // only trusts cfg.intelAgent.publicKeyPem (pinned out-of-band), never the
  // key carried in-band by the response.
  const signature = signPayload(attackerKeypair.privateKeyPem, payload);
  const forged = { ...payload, signature, publicKeyPem: attackerKeypair.publicKeyPem };
  const { fn } = makeScriptedFetch([{ statusCode: 200, body: forged }]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason.includes('signature'));
});

test('getRiskScore: fails closed to 100 when INTEL_AGENT_PUBLIC_KEY is not configured', async () => {
  const cfg = makeCfg({ intelAgent: { ...makeCfg().intelAgent, publicKeyPem: null } });
  const { fn } = makeScriptedFetch([{ statusCode: 200, body: signedScoreBody(2) }]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason.includes('INTEL_AGENT_PUBLIC_KEY'));
});

test('getRiskScore: fails closed to 100 when INTEL_PAYER_PRIVATE_KEY is not configured but payment is required', async () => {
  const cfg = makeCfg({ intelAgent: { ...makeCfg().intelAgent, payerPrivateKey: null } });
  const { fn, calls } = makeScriptedFetch([{ statusCode: 402, body: REQUIREMENT_402 }]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason.includes('INTEL_PAYER_PRIVATE_KEY'));
  assert.equal(calls.length, 1, 'must not attempt a payment retry without a payer key');
});

test('getRiskScore: fails closed to 100 (never throws) when the transport itself errors', async () => {
  const cfg = makeCfg();
  const { fn } = makeScriptedFetch([new Error('ECONNREFUSED')]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason.includes('ECONNREFUSED'));
});

// Regression: a live run produced an audit record with "error":"" and a
// caller (scripts/run-live-intel-purchase.mjs) that misreported the
// resulting fail-closed outcome as a success, because its branching used
// `if (result.failClosedReason)` -- a truthiness check that silently breaks
// when the underlying error's .message is the empty string (confirmed to
// happen with a real thrown value in practice; the exact native cause
// wasn't pinned down, but the failure mode is fully reproducible with any
// error whose .message is falsy). getRiskScore now falls back through
// .message -> .code -> .name -> String(err) so failClosedReason can never
// itself be an empty/falsy string, regardless of what threw.
test('getRiskScore: failClosedReason is never falsy, even when the underlying error has an empty .message', async () => {
  const cfg = makeCfg();
  const emptyMessageError = new Error('');
  const { fn } = makeScriptedFetch([emptyMessageError]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason, `failClosedReason must be truthy -- got ${JSON.stringify(result.failClosedReason)}`);
  assert.ok(!Array.isArray(result.reasons), 'a fail-closed result must not also look like a success result');

  const records = readAll(cfg.auditLogPath).filter((r) => r.type === 'INTEL_PURCHASE');
  assert.equal(records.length, 1);
  assert.ok(records[0].payload.error, `audit record's error field must be non-empty -- got ${JSON.stringify(records[0].payload.error)}`);
});

test('getRiskScore: failClosedReason falls back sensibly for a thrown value with only a .code, no .message', async () => {
  const cfg = makeCfg();
  const codeOnlyError = Object.assign(new Error(''), { code: 'ECONNRESET', name: 'Error' });
  const { fn } = makeScriptedFetch([codeOnlyError]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason.includes('ECONNRESET'), `expected the error code in the reason -- got ${JSON.stringify(result.failClosedReason)}`);
});

test('getRiskScore: fails closed to 100 when INTEL_AGENT_URL is not configured, without any network call', async () => {
  const cfg = makeCfg({ intelAgent: { ...makeCfg().intelAgent, url: null } });
  const { fn, calls } = makeScriptedFetch([]);

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.equal(calls.length, 0);
});

// ---------------------------------------------------------------------------
// Budget cap -- derived from the audit chain, scoped per incident
// ---------------------------------------------------------------------------

test('getRiskScore: budget cap blocks a purchase that would exceed MAX_INTEL_SPEND, without attempting payment', async () => {
  const cfg = makeCfg({ maxIntelSpend: 1200 });
  const { fn, calls } = makeScriptedFetch([{ statusCode: 402, body: REQUIREMENT_402 }]); // maxAmountRequired: '1000'

  // Pre-seed 500 already spent on THIS incident -- 500 + 1000 > 1200 cap.
  const { append } = await import('../src/auditlog.mjs');
  append(cfg.auditLogPath, 'INTEL_PURCHASE', { incidentId: 'inc-1', address: SPENDER, amount: '500', failed: false, score: 10 });

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 100);
  assert.ok(result.failClosedReason.includes('exceed MAX_INTEL_SPEND'));
  assert.equal(calls.length, 1, 'must not attempt to pay once the budget cap is hit');
});

test('getRiskScore: budget cap is scoped per incident -- spend on a different incident does not count', async () => {
  const cfg = makeCfg({ maxIntelSpend: 1200 });
  const { fn } = makeScriptedFetch([
    { statusCode: 402, body: REQUIREMENT_402 },
    { statusCode: 200, body: signedScoreBody(8) },
  ]);

  const { append } = await import('../src/auditlog.mjs');
  append(cfg.auditLogPath, 'INTEL_PURCHASE', { incidentId: 'inc-OTHER', address: SPENDER, amount: '900', failed: false, score: 10 });

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 8);
  assert.equal(result.purchased, true);
});

test('getRiskScore: a failed prior purchase does not count against the budget cap', async () => {
  const cfg = makeCfg({ maxIntelSpend: 1200 });
  const { fn } = makeScriptedFetch([
    { statusCode: 402, body: REQUIREMENT_402 },
    { statusCode: 200, body: signedScoreBody(8) },
  ]);

  const { append } = await import('../src/auditlog.mjs');
  append(cfg.auditLogPath, 'INTEL_PURCHASE', { incidentId: 'inc-1', address: SPENDER, amount: '900', failed: true, score: 100 });

  const result = await getRiskScore(SPENDER, { cfg, incidentId: 'inc-1', httpRequestJson: fn });

  assert.equal(result.risk, 8);
  assert.equal(result.purchased, true);
});
