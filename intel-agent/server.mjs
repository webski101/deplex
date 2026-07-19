// helper agent that sells spender risk scores via x402
//
// Standalone: runs as its own process, independent of Deplex's own
// watcher/responder loop. Reuses src/watcher.mjs's RPC plumbing and
// attack/crypto.mjs's keccak256 rather than reimplementing them -- that's a
// monorepo-internal reuse choice, not a dependency on Deplex being "up".
//
// x402 wire format: v1 (X-PAYMENT header, maxAmountRequired field) -- see
// docs/X402-NOTES.md. The /verify and /settle request/response shape below
// is no longer a best-effort guess: confirmed 2026-07-18 against the
// coinbase/x402 reference SDK source AND by live-probing a real, currently
// reachable facilitator (https://x402.org/facilitator, the SDK's own
// hardcoded default) with a deliberately invalid signature and reading its
// actual response. See X402-NOTES.md's "Live verification" section for the
// exact requests/responses this was checked against.

import { createServer } from 'node:http';
import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { rpcCallWithRetry, addressToTopic, decodeAddressFromTopic, APPROVAL_TOPIC } from '../src/watcher.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYPAIR_FILE = join(__dirname, '.keypair.json');
const DENYLIST_FILE = join(__dirname, 'denylist.json');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Number(x) || fallback silently discards a legitimate "0" (OS-assigned
// free port, used by tests to avoid colliding with a real running
// instance) because 0 is falsy -- confirmed the hard way when a test using
// INTEL_AGENT_PORT=0 collided with a real server on the real default port
// instead. Distinguishes "unset" from "explicitly 0".
function parsePort(value, fallback) {
  if (value === undefined || value === '') return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

export function loadConfig(env = process.env) {
  return {
    port: parsePort(env.INTEL_AGENT_PORT, 4021),
    rpcUrl: env.INTEL_AGENT_RPC_URL || env.RPC_URL,
    // Scoring RPC tuning -- see the long comment on approvalFanOut for why
    // this is NOT cosmetic: the original 5000-block lookback at chunkSize=8
    // (watcher.mjs's free-tier-safe default) is 625 eth_getLogs calls,
    // unconditionally, per score request. 200 blocks (~40min on Sepolia's
    // ~12s blocks) keeps the "recent activity" signal while cutting that to
    // ~25 calls. requestSpacingMs defaults lower than watcher.mjs's 250ms
    // (tuned for a long-running poller, not a bounded one-shot HTTP
    // request/response) -- both independently configurable per RPC
    // provider.
    lookbackBlocks: Number(env.INTEL_AGENT_LOOKBACK_BLOCKS) || 200,
    logChunkSize: Number(env.INTEL_AGENT_LOG_CHUNK_SIZE) || 8,
    rpcRequestSpacingMs: env.INTEL_AGENT_RPC_SPACING_MS !== undefined ? Number(env.INTEL_AGENT_RPC_SPACING_MS) : 100,
    // Payment side -- deliberately a DIFFERENT chain than the watched
    // wallet's (Base Sepolia, not Ethereum Sepolia): the intel purchase is
    // an independent economic flow, and Base Sepolia is the x402 ecosystem's
    // own convention (the spec's worked examples use it). See X402-NOTES.md.
    payToAddress: env.INTEL_AGENT_PAY_TO || null,
    priceAtomic: env.INTEL_AGENT_PRICE_ATOMIC || '1000', // 0.001 of a 6-decimal asset, nominal demo price
    assetAddress: env.INTEL_AGENT_ASSET || '0x036CbD53842c5426634e7929541eC2318f3dCF7e', // Base Sepolia USDC per x402 spec's own worked example
    assetName: env.INTEL_AGENT_ASSET_NAME || 'USDC',
    assetVersion: env.INTEL_AGENT_ASSET_VERSION || '2',
    network: env.INTEL_AGENT_NETWORK || 'base-sepolia',
    // The reference coinbase/x402 SDK's own hardcoded default facilitator --
    // confirmed live 2026-07-18, confirmed to accept v1-shaped exact/EVM
    // verify+settle calls for base-sepolia (see X402-NOTES.md). PayAI
    // (facilitator.payai.network) is also live and v1-base-sepolia-capable,
    // documented as a fallback.
    facilitatorUrl: env.FACILITATOR_URL || 'https://x402.org/facilitator',
    maxTimeoutSeconds: 60,
    // Deliberately shorter than intel.mjs's own default requestTimeoutMs
    // (INTEL_AGENT_REQUEST_TIMEOUT_MS, config.mjs default 20000): both used
    // to default to exactly 20000ms, an unresolved race with no ordering
    // guarantee -- if the facilitator call ran long, server and client
    // timeouts could fire at effectively the same instant, and whichever
    // "won" was arbitrary. If the server loses that race, it still produces
    // a proper 402/500 (now logged either way), but the client may have
    // already given up with a generic timeout, hiding the real reason. This
    // gives the server headroom to always finish first and hand back an
    // informative response before the client's patience runs out.
    facilitatorTimeoutMs: Number(env.FACILITATOR_TIMEOUT_MS) || 15000,
  };
}

// ---------------------------------------------------------------------------
// Signing identity: stable across restarts (generated once, persisted), so
// intel.mjs can pin a known public key rather than trusting whatever key
// shows up per-response -- trusting an in-band key would let anyone
// impersonate the agent by just generating their own keypair.
// ---------------------------------------------------------------------------

export function loadOrCreateKeypair(path = KEYPAIR_FILE) {
  if (existsSync(path)) {
    const raw = JSON.parse(readFileSync(path, 'utf8'));
    return raw;
  }
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
  writeFileSync(path, JSON.stringify(raw, null, 2));
  return raw;
}

function canonicalize(obj) {
  // Deterministic JSON: sorted keys, no whitespace -- so signing and
  // verifying hash the exact same bytes regardless of property insertion
  // order on either side.
  if (Array.isArray(obj)) return `[${obj.map(canonicalize).join(',')}]`;
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

export function signPayload(privateKeyPem, payload) {
  const message = Buffer.from(canonicalize(payload), 'utf8');
  const sig = cryptoSign(null, message, privateKeyPem); // Ed25519: no digest algorithm, signs the message directly
  return sig.toString('hex');
}

export function verifyPayload(publicKeyPem, payload, signatureHex) {
  const message = Buffer.from(canonicalize(payload), 'utf8');
  return cryptoVerify(null, message, publicKeyPem, Buffer.from(signatureHex, 'hex'));
}

// ---------------------------------------------------------------------------
// Deterministic risk scoring -- every contributing factor is transparent and
// reproducible from on-chain state + the local denylist. No LLM involved.
// ---------------------------------------------------------------------------

function loadDenylist() {
  if (!existsSync(DENYLIST_FILE)) return new Set();
  try {
    const list = JSON.parse(readFileSync(DENYLIST_FILE, 'utf8'));
    return new Set(list.map((a) => a.toLowerCase()));
  } catch {
    return new Set();
  }
}

async function isContract(rpcUrl, address, cfg) {
  const code = await rpcCallWithRetry(rpcUrl, 'eth_getCode', [address, 'latest'], cfg);
  return code && code !== '0x';
}

// Binary search for the block where the address's code first appears --
// deterministic, and "cheap" in the sense the spec asks for: O(log blocks)
// eth_getCode calls, not a linear scan.
async function findDeploymentBlock(rpcUrl, address, cfg) {
  const latestHex = await rpcCallWithRetry(rpcUrl, 'eth_blockNumber', [], cfg);
  let lo = 0;
  let hi = Number(BigInt(latestHex));
  const hasCodeAt = async (block) => {
    const code = await rpcCallWithRetry(rpcUrl, 'eth_getCode', [address, '0x' + block.toString(16)], cfg);
    return code && code !== '0x';
  };
  if (!(await hasCodeAt(hi))) return null; // not a contract, or not deployed yet
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (await hasCodeAt(mid)) hi = mid;
    else lo = mid + 1;
  }
  return hi;
}

async function estimateAgeDays(rpcUrl, deploymentBlock, cfg, { blockTimeSeconds = 12 } = {}) {
  const latestHex = await rpcCallWithRetry(rpcUrl, 'eth_blockNumber', [], cfg);
  const latest = Number(BigInt(latestHex));
  const blocksAgo = Math.max(0, latest - deploymentBlock);
  return (blocksAgo * blockTimeSeconds) / 86400;
}

// Approval fan-out: how many DISTINCT owners have approved this spender
// recently. Meant to be a "cheap" (bounded, recent-window) eth_getLogs scan,
// not a full-chain crawl -- a legitimate, widely-trusted contract (a DEX
// router, say) accumulates many independent approvals; a freshly deployed
// drainer has few or none.
//
// The ORIGINAL defaults here (lookbackBlocks=5000, chunkSize=8) were NOT
// actually cheap: 5000/8 = 625 chunked eth_getLogs calls, PER SCORE REQUEST,
// unconditionally (this runs regardless of denylist status, contract-vs-EOA,
// or approval history -- confirmed by direct count against a mock RPC: 626
// eth_getLogs calls for a plain EOA with zero approvals). Combined with the
// shared 250ms rpcCallWithRetry spacing gate (inherited from watcher.mjs,
// tuned for a long-running poller avoiding burst-rate limits -- not for a
// synchronous HTTP request/response), that floors a single scoreAddress()
// call at ~156 SECONDS minimum, independent of RPC latency or health.
//
// This is exactly what a live run hit: settlement succeeded, then this scan
// silently ran for minutes past the buyer's 20s timeout, past the server's
// own per-request completion log -- looking indistinguishable from a hang
// even though it was making real, if glacial, progress. See FAILURE-MODES.md.
//
// The caller (scoreAddress, via cfg.lookbackBlocks/cfg.logChunkSize) now
// passes a real lookbackBlocks/chunkSize appropriate for a request-scoped
// scan -- these {}-defaults exist only for direct unit tests of this
// function in isolation.
async function approvalFanOut(rpcUrl, spenderAddress, cfg, { lookbackBlocks = 5000, chunkSize = 8 } = {}) {
  const latestHex = await rpcCallWithRetry(rpcUrl, 'eth_blockNumber', [], cfg);
  const latest = Number(BigInt(latestHex));
  const fromBlock = Math.max(0, latest - lookbackBlocks);
  const owners = new Set();
  for (let start = fromBlock; start <= latest; start += chunkSize) {
    const end = Math.min(start + chunkSize - 1, latest);
    const logs = await rpcCallWithRetry(
      rpcUrl,
      'eth_getLogs',
      [
        {
          topics: [APPROVAL_TOPIC, null, addressToTopic(spenderAddress)],
          fromBlock: '0x' + start.toString(16),
          toBlock: '0x' + end.toString(16),
        },
      ],
      cfg,
    );
    for (const log of logs) owners.add(decodeAddressFromTopic(log.topics[1]).toLowerCase());
  }
  return owners.size;
}

export async function scoreAddress(address, { rpcUrl, denylist, rpcOpts = {}, fanOutOpts = {} }) {
  const addr = address.toLowerCase();
  const reasons = [];
  let score = 0;

  if (denylist.has(addr)) {
    return { address: addr, score: 100, reasons: ['address is on the local denylist'] };
  }

  const contract = await isContract(rpcUrl, addr, rpcOpts);
  if (contract) {
    const deployBlock = await findDeploymentBlock(rpcUrl, addr, rpcOpts);
    const ageDays = deployBlock === null ? 0 : await estimateAgeDays(rpcUrl, deployBlock, rpcOpts);
    if (ageDays < 1) {
      score += 40;
      reasons.push(`contract deployed less than 1 day ago (~${ageDays.toFixed(2)}d)`);
    } else if (ageDays < 7) {
      score += 25;
      reasons.push(`contract deployed less than 7 days ago (~${ageDays.toFixed(1)}d)`);
    } else {
      reasons.push(`contract age ~${Math.floor(ageDays)}d, over the 7-day threshold`);
    }
  } else {
    score += 10;
    reasons.push('spender is an externally-owned account, not a contract');
  }

  // fanOutOpts is NOT optional in effect -- see the comment on
  // approvalFanOut's default lookbackBlocks for why leaving it at {} (the
  // 5000-block default) is a real, confirmed bug, not just a slow path.
  const fanOut = await approvalFanOut(rpcUrl, addr, rpcOpts, fanOutOpts);
  if (fanOut === 0) {
    score += 30;
    reasons.push('no other wallets found approving this spender in the recent scan window');
  } else if (fanOut <= 5) {
    score += 15;
    reasons.push(`only ${fanOut} other wallet(s) found approving this spender recently`);
  } else {
    reasons.push(`${fanOut} other wallets found approving this spender recently, suggesting broader trust`);
  }

  return { address: addr, score: Math.min(100, score), reasons };
}

// ---------------------------------------------------------------------------
// x402 payment requirements + facilitator calls
// ---------------------------------------------------------------------------

function paymentRequirements(cfg, resourcePath) {
  return {
    scheme: 'exact',
    network: cfg.network,
    maxAmountRequired: cfg.priceAtomic,
    asset: cfg.assetAddress,
    payTo: cfg.payToAddress,
    resource: resourcePath,
    description: 'Deplex spender risk score',
    mimeType: 'application/json',
    outputSchema: null,
    maxTimeoutSeconds: cfg.maxTimeoutSeconds,
    extra: { assetTransferMethod: 'eip3009', name: cfg.assetName, version: cfg.assetVersion },
  };
}

function decodeXPaymentHeader(headerValue) {
  const json = Buffer.from(headerValue, 'base64').toString('utf8');
  return JSON.parse(json);
}

// Confirmed live 2026-07-18 against https://x402.org/facilitator (the
// coinbase/x402 reference SDK's own default): POST body is
// { x402Version, paymentPayload, paymentRequirements } -- the top-level
// x402Version alongside the two nested objects, per
// core/src/http/httpFacilitatorClient.ts's actual verify()/settle() methods.
// A live probe without the top-level x402Version got an identical response
// from this particular facilitator (it apparently falls back to
// paymentPayload.x402Version), but the reference client always sends it, so
// this file does too -- other facilitators may not be as lenient.
// /verify response shape { isValid, invalidReason, payer } and /settle
// response shape { success, network, transaction, errorReason, payer } are
// both confirmed byte-for-byte against a real response (see
// X402-NOTES.md), not inferred from source alone.
//
// AbortSignal.timeout(): built into Node 18+ (no dependency), used here
// deliberately -- a request to an external facilitator with no timeout is
// exactly the "silent hang" bug class found and fixed elsewhere in this
// project today (see FAILURE-MODES.md). Same protection, native fetch API.
// cfg.facilitatorTimeoutMs (default 15s, see loadConfig) is deliberately
// shorter than intel.mjs's own client-side request timeout (default 20s)
// so this side of a slow facilitator call always loses the race and gets
// to respond first -- see the comment on facilitatorTimeoutMs above.
async function facilitatorPost(cfg, path, paymentPayload, requirements) {
  const res = await fetch(`${cfg.facilitatorUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ x402Version: paymentPayload.x402Version, paymentPayload, paymentRequirements: requirements }),
    signal: AbortSignal.timeout(cfg.facilitatorTimeoutMs ?? 15000),
  });
  const parsed = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body: parsed };
}

async function facilitatorVerify(cfg, paymentPayload, requirements) {
  const { ok, status, body } = await facilitatorPost(cfg, '/verify', paymentPayload, requirements);
  if (!ok) return { isValid: false, invalidReason: body.invalidReason || `HTTP ${status}` };
  return { isValid: body.isValid === true, invalidReason: body.invalidReason, payer: body.payer };
}

async function facilitatorSettle(cfg, paymentPayload, requirements) {
  const { ok, status, body } = await facilitatorPost(cfg, '/settle', paymentPayload, requirements);
  if (!ok) return { success: false, errorReason: body.errorReason || `HTTP ${status}` };
  return { success: body.success === true, errorReason: body.errorReason, transaction: body.transaction, network: body.network, payer: body.payer };
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

export function createIntelAgentServer(cfg, deps = {}) {
  const keypair = deps.keypair ?? loadOrCreateKeypair();
  const denylist = deps.denylist ?? loadDenylist();
  const verify = deps.facilitatorVerify ?? facilitatorVerify;
  const settle = deps.facilitatorSettle ?? facilitatorSettle;
  // Defaults sourced from cfg (see loadConfig's lookbackBlocks/logChunkSize/
  // rpcRequestSpacingMs comment) rather than watcher.mjs's continuous-poller
  // defaults -- this is a bounded, one-shot scan inside an HTTP
  // request/response, not a long-running background loop, and reusing the
  // wrong defaults is exactly what turned one scoreAddress() call into a
  // multi-minute stall. deps overrides remain for tests.
  const rpcOpts = deps.rpcOpts ?? { requestSpacingMs: cfg.rpcRequestSpacingMs ?? 100 };
  const fanOutOpts = deps.fanOutOpts ?? { lookbackBlocks: cfg.lookbackBlocks ?? 200, chunkSize: cfg.logChunkSize ?? 8 };

  // Every exit point is logged with enough context (method, path, outcome,
  // and the specific reason on failure) to diagnose a live run from this
  // process's own terminal alone -- previously this handler logged nothing
  // at all, which meant "check the server's log" had nothing to check
  // (confirmed the hard way: a live run's actual failure was undiagnosable
  // from this terminal, forcing reconstruction from first principles
  // instead). See FAILURE-MODES.md.
  function log(outcome, detail) {
    console.log(`[intel-agent] ${new Date().toISOString()} ${outcome}${detail ? ' -- ' + detail : ''}`);
  }

  return createServer(async (req, res) => {
    const match = /^\/score\/(0x[0-9a-fA-F]{40})$/.exec(req.url ?? '');
    if (req.method !== 'GET' || !match) {
      log(`404 ${req.method} ${req.url}`);
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    const address = match[1];
    const requirements = paymentRequirements(cfg, req.url);

    const xPayment = req.headers['x-payment'];
    if (!xPayment) {
      log(`402 GET /score/${address}`, 'no X-PAYMENT header');
      res.writeHead(402, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ x402Version: 1, error: 'payment required', accepts: [requirements] }));
      return;
    }

    let paymentPayload;
    try {
      paymentPayload = decodeXPaymentHeader(xPayment);
    } catch (err) {
      log(`400 GET /score/${address}`, `malformed X-PAYMENT header: ${err.message}`);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `malformed X-PAYMENT header: ${err.message}` }));
      return;
    }

    try {
      const verifyResult = await verify(cfg, paymentPayload, requirements);
      if (!verifyResult.isValid) {
        log(`402 GET /score/${address}`, `facilitator verify failed: ${verifyResult.invalidReason || '(no reason given)'}`);
        res.writeHead(402, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ x402Version: 1, error: verifyResult.invalidReason || 'payment invalid', accepts: [requirements] }));
        return;
      }

      const settleResult = await settle(cfg, paymentPayload, requirements);
      if (!settleResult.success) {
        log(`402 GET /score/${address}`, `facilitator settle failed: ${settleResult.errorReason || '(no reason given)'}`);
        res.writeHead(402, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ x402Version: 1, error: settleResult.errorReason || 'settlement failed', accepts: [requirements] }));
        return;
      }

      const result = await scoreAddress(address, { rpcUrl: cfg.rpcUrl, denylist, rpcOpts, fanOutOpts });
      const signature = signPayload(keypair.privateKeyPem, result);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        // X-PAYMENT-RESPONSE, not PAYMENT-RESPONSE: the latter is v2-only per
        // the reference client's header-reading logic
        // (core/src/http/x402HTTPClient.ts getPaymentSettleResponse) -- a v1
        // response uses the X-PAYMENT-RESPONSE fallback it explicitly checks
        // for. Confirmed against that source 2026-07-18.
        'X-PAYMENT-RESPONSE': Buffer.from(
          JSON.stringify({ success: true, transaction: settleResult.transaction, network: settleResult.network, payer: settleResult.payer }),
        ).toString('base64'),
      });
      res.end(JSON.stringify({ ...result, signature, publicKeyPem: keypair.publicKeyPem }));
      log(`200 GET /score/${address}`, `score=${result.score} settlement=${settleResult.transaction ?? '(none)'}`);
    } catch (err) {
      // Previously nothing wrapped this section: an exception here (most
      // likely scoreAddress's RPC calls failing) left the connection open
      // forever with no response -- the buyer's payment had already settled
      // successfully, but they'd only ever see a generic client-side
      // timeout ~20s later with zero indication anything had even been
      // charged. Now it's a real, prompt, diagnosable 500.
      log(`500 GET /score/${address}`, `unhandled error after payment: ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `internal error: ${err.message}` }));
      } else {
        res.end();
      }
    }
  });
}

// pathToFileURL(), not `new URL(argv[1], 'file:')' -- the latter treats
// argv[1] as a URL reference rather than an OS path, so on Windows a
// relative invocation like `node intel-agent/server.mjs` (backslash-free,
// no drive letter, not resolved against cwd) produces
// "file:///intel-agent/server.mjs", which can never equal the real
// import.meta.url ("file:///C:/Users/.../intel-agent/server.mjs"). The
// guard was silently always false: the script loaded, matched nothing, and
// exited cleanly with zero output -- no error, because nothing threw.
// pathToFileURL correctly resolves relative paths against cwd and produces
// the same file:// form import.meta.url uses on every platform.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const cfg = loadConfig();
  if (!cfg.rpcUrl) {
    console.error('RPC_URL (or INTEL_AGENT_RPC_URL) is not set');
    process.exit(1);
  }
  if (!cfg.payToAddress) {
    console.error('INTEL_AGENT_PAY_TO is not set -- this is the address that receives payment, must be set explicitly');
    process.exit(1);
  }
  const server = createIntelAgentServer(cfg);
  server.listen(cfg.port, () => {
    console.log(`[intel-agent] listening on :${cfg.port}, network=${cfg.network}, facilitator=${cfg.facilitatorUrl}`);
  });
}
