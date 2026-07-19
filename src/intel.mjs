// x402 intel-purchase client (the buyer side of Phase 5).
//
// Calls intel-agent/server.mjs's GET /score/:address. On the first 402, signs
// an EIP-3009 TransferWithAuthorization by hand (node:crypto, via
// attack/crypto.mjs's secp256k1 primitives) and retries with an X-PAYMENT
// header -- see docs/X402-NOTES.md for why this can't go through KeeperHub's
// agentic wallet (KeeperHub only pays into KeeperHub-native endpoints) and is
// therefore this codebase's second deliberate direct-signing exception,
// alongside attack/crypto.mjs. Fail-closed throughout: any failure (agent
// down, payment rejected, signature verification failure, budget exceeded)
// resolves to risk=100, never throws, and is recorded in the audit chain.
//
// NOT wired into responder.mjs's event pipeline yet -- handleEvent() calls
// evaluate() synchronously with no I/O in between, so attaching a live
// spenderRisk requires the caller to await getRiskScore() and set
// event.spenderRisk *before* calling handleEvent(). That wiring is a
// follow-up, not part of this phase's scope (see intel.test.mjs and the
// Phase 5 notes in README.md).

import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { keccak256, hexToBytes, bytesToHex, signRawDigest, privateKeyToAddress } from '../attack/crypto.mjs';
import { verifyPayload } from '../intel-agent/server.mjs';
import { append as appendAudit, readAll as readAudit } from './auditlog.mjs';

export class IntelError extends Error {}

// Best-effort x402 network-string -> EVM chainId map, needed for the EIP-712
// domain. Not confirmed against any canonical x402 network-naming spec (none
// of the sources in X402-NOTES.md published one) -- confirmed only that
// PayAI's facilitator supports "base-sepolia". Extend as real facilitators
// are checked.
const CHAIN_ID_BY_NETWORK = {
  'base-sepolia': 84532,
  base: 8453,
  'ethereum-sepolia': 11155111,
  sepolia: 11155111,
  ethereum: 1,
};

// ---------------------------------------------------------------------------
// HTTP (mirrors keeperhub.mjs's request pattern: http/https by protocol,
// req.setTimeout so a hung connection fails loudly instead of hanging the
// incident response loop forever -- the same bug class fixed in watcher.mjs
// and keeperhub.mjs).
// ---------------------------------------------------------------------------

export function httpRequestJson(urlString, { method = 'GET', headers = {}, timeoutMs = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const transport = url.protocol === 'http:' ? http : https;
    const req = transport.request(url, { method, headers }, (res) => {
      let chunks = '';
      res.on('data', (c) => {
        chunks += c;
      });
      res.on('end', () => {
        let body;
        try {
          body = chunks ? JSON.parse(chunks) : {};
        } catch {
          body = { raw: chunks };
        }
        resolve({ statusCode: res.statusCode, headers: res.headers, body });
      });
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`intel agent request timed out after ${timeoutMs}ms`));
    });
    req.end();
  });
}

// ---------------------------------------------------------------------------
// EIP-712 / EIP-3009 signing
//
// Standard, non-vendor-specific Ethereum encoding (unlike the x402
// facilitator wire format, this is a stable, widely-implemented standard --
// see X402-NOTES.md for what actually needed live verification vs. what's
// safe to build from well-established spec knowledge). Reuses
// attack/crypto.mjs's keccak256/secp256k1 primitives; the EIP-712 digest
// construction itself is new here since it's specific to typed-data signing,
// not the legacy-tx signing crypto.mjs was built for.
// ---------------------------------------------------------------------------

const EIP712_DOMAIN_TYPEHASH = keccak256(
  'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)',
);
const TRANSFER_WITH_AUTH_TYPEHASH = keccak256(
  'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)',
);

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function leftPad32(bytes) {
  if (bytes.length > 32) throw new IntelError('value does not fit in 32 bytes');
  const out = new Uint8Array(32);
  out.set(bytes, 32 - bytes.length);
  return out;
}

function encodeAddressField(address) {
  return leftPad32(hexToBytes(address));
}

function encodeUint256Field(value) {
  const hex = value.toString(16);
  const padded = hex.length % 2 ? '0' + hex : hex;
  return leftPad32(hexToBytes('0x' + padded));
}

function buildDomainSeparator({ name, version, chainId, verifyingContract }) {
  return keccak256(
    concatBytes(
      EIP712_DOMAIN_TYPEHASH,
      keccak256(name),
      keccak256(version),
      encodeUint256Field(BigInt(chainId)),
      encodeAddressField(verifyingContract),
    ),
  );
}

function buildTransferAuthDigest(domainSeparator, auth) {
  const structHash = keccak256(
    concatBytes(
      TRANSFER_WITH_AUTH_TYPEHASH,
      encodeAddressField(auth.from),
      encodeAddressField(auth.to),
      encodeUint256Field(BigInt(auth.value)),
      encodeUint256Field(BigInt(auth.validAfter)),
      encodeUint256Field(BigInt(auth.validBefore)),
      hexToBytes(auth.nonce),
    ),
  );
  return keccak256(concatBytes(hexToBytes('0x1901'), domainSeparator, structHash));
}

// v = 27/28 (not the 0/1 recoveryParity crypto.mjs uses internally) -- the
// standard ecrecover-compatible convention EIP-3009 reference
// implementations (e.g. USDC's FiatTokenV2, via OpenZeppelin's ECDSA
// library) expect for a 65-byte signature.
function toEip3009Signature({ r, s, recoveryParity }) {
  const rHex = r.toString(16).padStart(64, '0');
  const sHex = s.toString(16).padStart(64, '0');
  const v = (27 + recoveryParity).toString(16).padStart(2, '0');
  return '0x' + rHex + sHex + v;
}

// Exported for tests: builds and signs an EIP-3009 authorization against a
// 402 response's payment requirement. Pure given its inputs (randomBytes for
// the nonce is the only non-determinism, matched by the caller passing one
// in during tests).
//
// validAfter = now - 600 (10 minutes in the past, not "0") and
// validBefore = now + maxTimeoutSeconds directly, with no separate
// "validitySeconds" cap: this exactly matches the coinbase/x402 reference
// client's own ExactEvmSchemeV1.createPaymentPayload (confirmed against that
// source 2026-07-18, see X402-NOTES.md). validAfter=0 would likely still
// pass most contracts' validation, but the point of this pass was matching
// the real implementation, not a plausible-looking guess.
export function signAuthorization(payerPrivateKeyHex, requirement, opts = {}) {
  const nowSeconds = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
  const nonce = opts.nonce ?? bytesToHex(randomBytes(32));

  const domainName = requirement.extra?.name;
  const domainVersion = requirement.extra?.version;
  if (!domainName || !domainVersion) {
    throw new IntelError('payment requirement missing extra.name/extra.version -- cannot build EIP-712 domain');
  }
  const chainId = CHAIN_ID_BY_NETWORK[requirement.network];
  if (!chainId) {
    throw new IntelError(`unknown x402 network "${requirement.network}" -- add it to CHAIN_ID_BY_NETWORK`);
  }

  const from = privateKeyToAddress(payerPrivateKeyHex);
  const authorization = {
    from,
    to: requirement.payTo,
    value: String(requirement.maxAmountRequired),
    validAfter: String(nowSeconds - 600),
    validBefore: String(nowSeconds + requirement.maxTimeoutSeconds),
    nonce,
  };

  const domainSeparator = buildDomainSeparator({
    name: domainName,
    version: domainVersion,
    chainId,
    verifyingContract: requirement.asset,
  });
  const digest = buildTransferAuthDigest(domainSeparator, authorization);
  const { r, s, recoveryParity } = signRawDigest(digest, payerPrivateKeyHex);
  const signature = toEip3009Signature({ r, s, recoveryParity });

  return { signature, authorization };
}

// ---------------------------------------------------------------------------
// Budget cap -- derived from the audit chain rather than in-memory state, so
// it survives a restart and can't drift from what's actually recorded
// (same reasoning as responder.mjs's completedKeys idempotency check).
// ---------------------------------------------------------------------------

function sumPriorIntelSpend(auditLogPath, incidentId) {
  let sum = 0n;
  for (const record of readAudit(auditLogPath)) {
    if (record.type === 'INTEL_PURCHASE' && record.payload?.incidentId === incidentId && !record.payload?.failed && record.payload?.amount) {
      sum += BigInt(record.payload.amount);
    }
  }
  return sum;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Buys a risk score for spenderAddress. Never throws -- any failure resolves
// to { risk: 100, failClosedReason }, matching policy.mjs's own fail-closed
// default for a missing spenderRisk (belt and suspenders: the same worst-case
// value whether intel.mjs is never called or fails when called).
export async function getRiskScore(spenderAddress, ctx) {
  const { cfg, incidentId } = ctx;
  const fetchFn = ctx.httpRequestJson ?? httpRequestJson;
  const verify = ctx.verifyPayload ?? verifyPayload;
  const auditLogPath = cfg.auditLogPath;
  let paymentRecord = null;

  // Staged, per-request-lifecycle logging -- added after a live run left a
  // silent gap: the server logged the initial 402 and nothing after, and
  // there was no way to tell whether the client ever built/sent a payment
  // retry at all, or hung somewhere before reaching the network. Every
  // meaningful step between "got the 402" and "got a response to the
  // retry" now logs, so the next hang shows exactly which line was last
  // printed instead of requiring after-the-fact reconstruction. See
  // FAILURE-MODES.md.
  const log = ctx.log ?? ((msg) => console.log(`[intel-buyer] ${new Date().toISOString()} ${msg}`));

  try {
    if (!cfg.intelAgent?.url) throw new IntelError('INTEL_AGENT_URL not configured');

    const scoreUrl = `${cfg.intelAgent.url.replace(/\/$/, '')}/score/${spenderAddress}`;
    log(`requesting score for ${spenderAddress} (no payment attached yet)`);
    const initial = await fetchFn(scoreUrl, { timeoutMs: cfg.intelAgent.requestTimeoutMs });

    let finalResponse;
    if (initial.statusCode === 200) {
      log('received 200 -- no payment required');
      finalResponse = initial;
    } else if (initial.statusCode === 402) {
      log('received 402 -- payment required, reading requirements');
      const requirement = initial.body?.accepts?.[0];
      if (!requirement) throw new IntelError('402 response missing payment requirements');

      const requiredAtomic = BigInt(requirement.maxAmountRequired);
      const spentSoFar = sumPriorIntelSpend(auditLogPath, incidentId);
      const capAtomic = BigInt(cfg.maxIntelSpend || 0);
      if (spentSoFar + requiredAtomic > capAtomic) {
        throw new IntelError(
          `intel purchase of ${requiredAtomic} would exceed MAX_INTEL_SPEND (spent ${spentSoFar}, cap ${capAtomic}) for incident ${incidentId}`,
        );
      }

      if (!cfg.intelAgent.payerPrivateKey) {
        throw new IntelError('INTEL_PAYER_PRIVATE_KEY not configured -- cannot pay for intel');
      }
      log(`building and signing EIP-3009 authorization for ${requiredAtomic} atomic units`);
      const { signature, authorization } = signAuthorization(cfg.intelAgent.payerPrivateKey, requirement);
      log('authorization signed');
      // The X-PAYMENT payload is NOT the bare {signature, authorization}
      // pair -- it's that pair nested under `payload`, alongside sibling
      // x402Version/scheme/network fields (PaymentPayloadV1 in the
      // coinbase/x402 reference SDK's types/v1/index.ts). Confirmed both
      // from that source and by a live /verify call against
      // x402.org/facilitator that only produced a coherent, well-parsed
      // response (payer correctly recovered from the nested authorization)
      // once sent in this exact shape -- see X402-NOTES.md.
      const paymentPayload = {
        x402Version: 1,
        scheme: requirement.scheme ?? 'exact',
        network: requirement.network,
        payload: { signature, authorization },
      };
      const xPaymentHeader = Buffer.from(JSON.stringify(paymentPayload), 'utf8').toString('base64');
      paymentRecord = {
        amount: requirement.maxAmountRequired,
        asset: requirement.asset,
        network: requirement.network,
        payTo: requirement.payTo,
      };

      log(`sending payment retry to ${scoreUrl} (timeout ${cfg.intelAgent.requestTimeoutMs}ms)`);
      const paid = await fetchFn(scoreUrl, {
        headers: { 'X-PAYMENT': xPaymentHeader },
        timeoutMs: cfg.intelAgent.requestTimeoutMs,
      });
      log(`received response to retry: HTTP ${paid.statusCode}`);
      if (paid.statusCode !== 200) {
        throw new IntelError(`intel agent rejected payment: HTTP ${paid.statusCode} ${paid.body?.error ?? ''}`.trim());
      }
      // The real settlement reference (transaction hash, payer, network)
      // comes back via X-PAYMENT-RESPONSE, not the response body -- this
      // was previously never read at all (httpRequestJson dropped response
      // headers entirely), so no INTEL_PURCHASE record ever captured a real
      // on-chain reference despite settlement genuinely succeeding. Decoding
      // it is best-effort and never blocks the purchase: the score itself
      // is already cryptographically verified via its own signature below,
      // independent of this header, so a missing/malformed settlement
      // receipt is a worse audit trail, not a worse guarantee. See
      // FAILURE-MODES.md.
      const settlementHeader = paid.headers?.['x-payment-response'];
      if (settlementHeader) {
        try {
          const settlement = JSON.parse(Buffer.from(settlementHeader, 'base64').toString('utf8'));
          paymentRecord.transaction = settlement.transaction;
          paymentRecord.payer = settlement.payer;
          log(`settlement reference captured: ${settlement.transaction ?? '(none)'}`);
        } catch (err) {
          log(`could not decode X-PAYMENT-RESPONSE header: ${err.message}`);
        }
      } else {
        log('no X-PAYMENT-RESPONSE header in the response -- settlement reference will be missing from the audit record');
      }
      finalResponse = paid;
    } else {
      throw new IntelError(`unexpected HTTP ${initial.statusCode} from intel agent`);
    }

    // publicKeyPem is destructured out but deliberately never used for
    // verification -- trusting a key the response itself supplies would let
    // anyone (a MITM, an impersonating server) sign with their own key and
    // "verify" successfully. Only cfg.intelAgent.publicKeyPem, pinned
    // out-of-band via env, is a valid verification key.
    const { signature: respSig, publicKeyPem: _respPubKey, ...scoreData } = finalResponse.body;
    if (typeof scoreData.score !== 'number' || !Number.isFinite(scoreData.score)) {
      throw new IntelError('intel agent response missing a numeric score');
    }
    if (!cfg.intelAgent.publicKeyPem) {
      throw new IntelError('INTEL_AGENT_PUBLIC_KEY not configured -- cannot verify agent response signature');
    }
    if (!respSig || !verify(cfg.intelAgent.publicKeyPem, scoreData, respSig)) {
      throw new IntelError('intel agent response signature verification failed');
    }
    log(`response signature verified, score=${scoreData.score}`);

    if (paymentRecord) {
      appendAudit(auditLogPath, 'INTEL_PURCHASE', {
        incidentId,
        address: spenderAddress,
        ...paymentRecord,
        score: scoreData.score,
        reasons: scoreData.reasons,
        failed: false,
      });
    }

    return { risk: scoreData.score, reasons: scoreData.reasons ?? [], purchased: Boolean(paymentRecord) };
  } catch (err) {
    const reason = describeError(err);
    log(`failed closed: ${reason}`);
    appendAudit(auditLogPath, 'INTEL_PURCHASE', {
      incidentId,
      address: spenderAddress,
      ...(paymentRecord ?? {}),
      failed: true,
      error: reason,
      score: 100,
    });
    return { risk: 100, failClosedReason: reason, purchased: false };
  }
}

// err.message can be falsy (empty string) for some native/non-Error thrown
// values -- confirmed to happen in practice on a live run (see
// FAILURE-MODES.md), which previously produced an unhelpfully-empty audit
// record and, combined with a separate bug in the CLI script's branching,
// a fail-closed result that printed as if it had succeeded. This always
// produces a non-empty, informative string, falling back through
// .message -> .code -> .name -> String(err) so a future failure of this
// kind is diagnosable from the audit log alone.
function describeError(err) {
  if (err?.message) return err.message;
  if (err?.code) return `${err.name ?? 'Error'} (code: ${err.code})`;
  if (err?.name) return err.name;
  return String(err);
}
