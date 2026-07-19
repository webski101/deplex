// detection loop: polls RPC for approvals + transfers

import https from 'node:https';
import http from 'node:http';
import { URL, pathToFileURL } from 'node:url';
import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { isUnlimitedAmount } from './policy.mjs';
import { loadConfig, assertRuntimeConfig } from './config.mjs';
import { sendAlert, startBotListener } from './telegram.mjs';
import { append as appendAudit } from './auditlog.mjs';

// Well-known ERC-20/721 event topics (keccak256 of the canonical signature).
// Hardcoded rather than computed: node:crypto has no raw Keccak (only NIST
// SHA3, a different padding), and these three are the most widely published
// constants in EVM tooling.
export const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
export const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
export const APPROVAL_FOR_ALL_TOPIC = '0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31';
const BALANCE_OF_SELECTOR = '0x70a08231'; // keccak256("balanceOf(address)")[:4]
const DECIMALS_SELECTOR = '0x313ce567'; // keccak256("decimals()")[:4]

// ---------------------------------------------------------------------------
// Raw JSON-RPC client
// ---------------------------------------------------------------------------

export class RpcError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

// Shown verbatim in error messages so a failed parse is diagnosable from the
// log alone. "<empty body>" is the important case: JSON.parse('') is the
// classic silent shape of a rate-limited (429) or blocked response.
export function rawBodySnippet(data, maxLen = 300) {
  if (data.length === 0) return '<empty body>';
  const trimmed = data.slice(0, maxLen).replace(/\s+/g, ' ');
  return data.length > maxLen ? `${trimmed}... (${data.length} chars total)` : trimmed;
}

let requestId = 0;

// No timeout here previously meant a hung TCP connection (firewall silently
// dropping packets, an RPC provider that stops responding mid-connection)
// left this promise NEVER settling -- not rejecting, just hanging forever.
// Since this is runWatcherCycle's very first await, that hang was
// indistinguishable from the process being frozen: no WATCHER_ERROR (nothing
// ever threw), no heartbeat (the cycle never completed), no visible failure
// at all. Confirmed live: the ARMED banner printed, then total silence with
// no output for a long period, on a network that had worked moments before.
const DEFAULT_REQUEST_TIMEOUT_MS = 20_000;

export function rpcCall(rpcUrl, method, params = [], { timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(rpcUrl);
    } catch {
      reject(new Error(`invalid RPC_URL "${rpcUrl}"`));
      return;
    }
    const body = JSON.stringify({ jsonrpc: '2.0', id: ++requestId, method, params });
    const transport = url.protocol === 'http:' ? http : https;
    const req = transport.request(
      url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(
              new RpcError(
                `HTTP ${res.statusCode} from RPC for ${method}; raw body: ${rawBodySnippet(data)}`,
                res.statusCode,
              ),
            );
            return;
          }
          try {
            const parsed = JSON.parse(data);
            if (parsed.error) {
              reject(new RpcError(parsed.error.message || 'RPC error', parsed.error.code));
            } else {
              resolve(parsed.result);
            }
          } catch (err) {
            reject(
              new Error(
                `invalid JSON-RPC response for ${method} (HTTP ${res.statusCode}, ${Buffer.byteLength(data)} bytes): ${err.message}; raw body: ${rawBodySnippet(data)}`,
              ),
            );
          }
        });
      },
    );
    req.on('error', reject);
    // setTimeout's callback fires if no data has been sent/received for
    // timeoutMs -- it does NOT itself abort the request, so destroy() is
    // required; destroy(err) is what actually surfaces the failure via the
    // 'error' handler above, turning a silent hang into a normal, retryable
    // rejection that rpcCallWithRetry's existing backoff already handles.
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`RPC request to ${url.hostname} timed out after ${timeoutMs}ms (method: ${method})`));
    });
    req.write(body);
    req.end();
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function computeBackoffDelay(attempt, baseDelayMs = 500, maxDelayMs = 30000) {
  const cap = Math.min(maxDelayMs, baseDelayMs * 2 ** attempt);
  return Math.floor(Math.random() * cap);
}

// Global throttle gate: at most one RPC request per spacingMs across ALL call
// types. Free-tier providers throttle on burst rate; three parallel getLogs
// streams plus blockNumber/balanceOf calls in one cycle triggers empty-body
// 429s (observed live on Sepolia).
let nextRpcSlotAt = 0;

export function scheduleRpcSlot(nowMs, nextSlotAtMs, spacingMs) {
  const waitMs = Math.max(0, nextSlotAtMs - nowMs);
  const newNextSlotAt = Math.max(nowMs, nextSlotAtMs) + spacingMs;
  return { waitMs, newNextSlotAt };
}

async function acquireRpcSlot(spacingMs) {
  const { waitMs, newNextSlotAt } = scheduleRpcSlot(Date.now(), nextRpcSlotAt, spacingMs);
  nextRpcSlotAt = newNextSlotAt;
  if (waitMs > 0) await sleep(waitMs);
}

export async function rpcCallWithRetry(rpcUrl, method, params, opts = {}) {
  const maxRetries = opts.maxRetries ?? 5;
  // accept both spellings: config.mjs uses baseBackoffMs/maxBackoffMs
  const baseDelayMs = opts.baseBackoffMs ?? opts.baseDelayMs ?? 500;
  const maxDelayMs = opts.maxBackoffMs ?? opts.maxDelayMs ?? 30000;
  const spacingMs = opts.requestSpacingMs ?? 250;
  const timeoutMs = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  let attempt = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    await acquireRpcSlot(spacingMs);
    try {
      return await rpcCall(rpcUrl, method, params, { timeoutMs });
    } catch (err) {
      attempt++;
      if (attempt > maxRetries) throw err;
      await sleep(computeBackoffDelay(attempt, baseDelayMs, maxDelayMs));
    }
  }
}

// ---------------------------------------------------------------------------
// Block-range chunking
// ---------------------------------------------------------------------------

export function computeChunks(fromBlock, toBlock, chunkSize) {
  if (chunkSize <= 0) throw new Error('chunkSize must be positive');
  if (fromBlock > toBlock) return [];
  const chunks = [];
  let start = fromBlock;
  while (start <= toBlock) {
    const end = Math.min(start + chunkSize - 1, toBlock);
    chunks.push([start, end]);
    start = end + 1;
  }
  return chunks;
}

function toHexBlock(n) {
  return '0x' + n.toString(16);
}

async function getLogsChunked(rpcUrl, { address, topics, fromBlock, toBlock, chunkSize }, retryOpts) {
  const chunks = computeChunks(fromBlock, toBlock, chunkSize);
  const allLogs = [];
  for (const [from, to] of chunks) {
    const filter = { topics, fromBlock: toHexBlock(from), toBlock: toHexBlock(to) };
    if (address) filter.address = address;
    const logs = await rpcCallWithRetry(rpcUrl, 'eth_getLogs', [filter], retryOpts);
    allLogs.push(...logs);
  }
  return allLogs;
}

// ---------------------------------------------------------------------------
// Hand-rolled ABI decoding (no ethers, no viem)
// ---------------------------------------------------------------------------

export function addressToTopic(address) {
  return '0x' + address.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}

export function decodeAddressFromTopic(topicHex) {
  const hex = topicHex.replace(/^0x/, '').padStart(64, '0');
  return '0x' + hex.slice(24);
}

export function encodeUint256(value) {
  return '0x' + BigInt(value).toString(16).padStart(64, '0');
}

export function decodeUint256(dataHex) {
  const hex = (dataHex || '0x').replace(/^0x/, '');
  if (hex.length === 0) return 0n;
  return BigInt('0x' + hex);
}

export function decodeBool(dataHex) {
  return decodeUint256(dataHex) !== 0n;
}

function hexToNumber(hex) {
  return Number(BigInt(hex));
}

export function dedupKey(log) {
  return `${log.transactionHash}:${hexToNumber(log.logIndex)}`;
}

export function dedupLogs(logs, seenKeys) {
  const fresh = [];
  const newKeys = new Set();
  for (const log of logs) {
    const key = dedupKey(log);
    if (seenKeys.has(key) || newKeys.has(key)) continue;
    newKeys.add(key);
    fresh.push(log);
  }
  return { fresh, newKeys };
}

export function decodeApprovalLog(log) {
  const owner = decodeAddressFromTopic(log.topics[1]);
  const spender = decodeAddressFromTopic(log.topics[2]);
  const amount = decodeUint256(log.data);
  return {
    type: 'approval',
    kind: 'erc20',
    token: log.address.toLowerCase(),
    owner: owner.toLowerCase(),
    spender: spender.toLowerCase(),
    amount: amount.toString(),
    unlimited: isUnlimitedAmount(amount),
    txHash: log.transactionHash,
    logIndex: hexToNumber(log.logIndex),
    block: hexToNumber(log.blockNumber),
    observedAt: new Date().toISOString(),
  };
}

export function decodeApprovalForAllLog(log) {
  const owner = decodeAddressFromTopic(log.topics[1]);
  const operator = decodeAddressFromTopic(log.topics[2]);
  const approved = decodeBool(log.data);
  return {
    type: 'approval',
    kind: 'nft-operator',
    token: log.address.toLowerCase(),
    owner: owner.toLowerCase(),
    spender: operator.toLowerCase(),
    amount: null,
    approved,
    // a blanket operator approval over an entire NFT collection is the NFT
    // analogue of an unlimited ERC-20 allowance
    unlimited: approved === true,
    txHash: log.transactionHash,
    logIndex: hexToNumber(log.logIndex),
    block: hexToNumber(log.blockNumber),
    observedAt: new Date().toISOString(),
  };
}

export function decodeTransferLog(log) {
  const from = decodeAddressFromTopic(log.topics[1]);
  const to = decodeAddressFromTopic(log.topics[2]);
  const value = decodeUint256(log.data);
  return {
    type: 'transfer',
    token: log.address.toLowerCase(),
    from: from.toLowerCase(),
    to: to.toLowerCase(),
    value: value.toString(),
    txHash: log.transactionHash,
    logIndex: hexToNumber(log.logIndex),
    block: hexToNumber(log.blockNumber),
    observedAt: new Date().toISOString(),
  };
}

export async function getTokenBalance(rpcUrl, tokenAddress, walletAddress, retryOpts) {
  const data = BALANCE_OF_SELECTOR + addressToTopic(walletAddress).slice(2);
  const result = await rpcCallWithRetry(rpcUrl, 'eth_call', [{ to: tokenAddress, data }, 'latest'], retryOpts);
  return decodeUint256(result).toString();
}

// Needed before converting a wei-denominated balance to the decimal string
// KeeperHub's execute_transfer expects (src/keeperhub.mjs's
// weiToDecimalString) -- NOT every ERC-20 uses 18 decimals (USDC uses 6),
// so assuming 18 universally would misconvert a real evacuation amount.
export async function getTokenDecimals(rpcUrl, tokenAddress, retryOpts) {
  const result = await rpcCallWithRetry(rpcUrl, 'eth_call', [{ to: tokenAddress, data: DECIMALS_SELECTOR }, 'latest'], retryOpts);
  return Number(decodeUint256(result));
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

export class CircuitBreaker {
  constructor(threshold = 5) {
    this.threshold = threshold;
    this.consecutiveFailures = 0;
    this.tripped = false;
  }

  recordSuccess() {
    this.consecutiveFailures = 0;
    this.tripped = false;
  }

  // returns true once the breaker has just tripped
  recordFailure() {
    this.consecutiveFailures++;
    if (this.consecutiveFailures >= this.threshold) {
      this.tripped = true;
    }
    return this.tripped;
  }
}

// ---------------------------------------------------------------------------
// State persistence
// ---------------------------------------------------------------------------

export function loadState(path) {
  if (!existsSync(path)) return null;
  const raw = readFileSync(path, 'utf8');
  const parsed = JSON.parse(raw);
  return {
    lastScannedBlock: parsed.lastScannedBlock ?? -1,
    seenLogKeys: new Set(parsed.seenLogKeys || []),
    activeApprovals: parsed.activeApprovals || {},
    balances: parsed.balances || {},
    // Owned by responder.mjs, persisted here so a crash mid-incident and
    // restart resumes the SAME incident id -- otherwise every idempotency
    // key (prefixed by incidentId) would silently change on restart and the
    // audit-chain dedup check would never match, double-firing executions.
    incident: parsed.incident ?? null,
    currentIncidentId: parsed.currentIncidentId ?? null,
  };
}

export function saveState(path, state) {
  const serializable = {
    lastScannedBlock: state.lastScannedBlock,
    seenLogKeys: Array.from(state.seenLogKeys),
    activeApprovals: state.activeApprovals,
    balances: state.balances,
    incident: state.incident ?? null,
    currentIncidentId: state.currentIncidentId ?? null,
  };
  const tmpPath = `${path}.tmp`;
  writeFileSync(tmpPath, JSON.stringify(serializable, null, 2));
  renameSync(tmpPath, path); // renameSync overwrites on Windows too (libuv), giving an atomic-ish swap
}

async function initialState(cfg) {
  const latest = hexToNumber(await rpcCallWithRetry(cfg.rpcUrl, 'eth_blockNumber', [], cfg));
  const startBlock = cfg.startBlock ?? latest;
  return {
    lastScannedBlock: startBlock - 1,
    seenLogKeys: new Set(),
    activeApprovals: {},
    balances: {},
    incident: null,
    currentIncidentId: null,
  };
}

// ---------------------------------------------------------------------------
// Audit stub (Phase 4 replaces this with the real hash-chained log)
// ---------------------------------------------------------------------------

function record(cfg, type, payload) {
  try {
    appendAudit(cfg.auditLogPath, type, payload);
  } catch (err) {
    console.error(`[audit] failed to append to ${cfg.auditLogPath}: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// One polling cycle
// ---------------------------------------------------------------------------

export async function runWatcherCycle(cfg, state, emit) {
  const latest = hexToNumber(await rpcCallWithRetry(cfg.rpcUrl, 'eth_blockNumber', [], cfg));
  const safeLatest = Math.max(latest - cfg.confirmations, 0);
  const fromBlock = state.lastScannedBlock + 1;
  if (fromBlock > safeLatest) {
    return state;
  }

  const ownerTopic = addressToTopic(cfg.watchedWallet);
  const range = { fromBlock, toBlock: safeLatest, chunkSize: cfg.chunkSize };

  // Sequential, not Promise.all: three parallel chunked streams burst past
  // free-tier rate limits (the global throttle would serialize them anyway,
  // but sequential keeps failure attribution per-stream clean).
  const approvalLogsRaw = await getLogsChunked(cfg.rpcUrl, { topics: [APPROVAL_TOPIC, ownerTopic], ...range }, cfg);
  const approvalForAllLogsRaw = await getLogsChunked(cfg.rpcUrl, { topics: [APPROVAL_FOR_ALL_TOPIC, ownerTopic], ...range }, cfg);
  const transferLogsRaw = await getLogsChunked(cfg.rpcUrl, { topics: [TRANSFER_TOPIC, ownerTopic], ...range }, cfg);

  const { fresh: approvalLogs, newKeys: k1 } = dedupLogs(approvalLogsRaw, state.seenLogKeys);
  const { fresh: approvalForAllLogs, newKeys: k2 } = dedupLogs(approvalForAllLogsRaw, state.seenLogKeys);
  const { fresh: transferLogs, newKeys: k3 } = dedupLogs(transferLogsRaw, state.seenLogKeys);

  const events = [
    ...approvalLogs.map(decodeApprovalLog),
    ...approvalForAllLogs.map(decodeApprovalForAllLog),
    ...transferLogs.map(decodeTransferLog),
  ].sort((a, b) => a.block - b.block || a.logIndex - b.logIndex);

  for (const event of events) {
    if (event.type !== 'approval') continue;
    const key = `${event.token}:${event.spender}`;
    if (event.amount === '0' || event.approved === false) {
      delete state.activeApprovals[key];
    } else {
      state.activeApprovals[key] = {
        token: event.token,
        spender: event.spender,
        kind: event.kind,
        amount: event.amount,
        unlimited: event.unlimited,
        txHash: event.txHash,
        block: event.block,
      };
    }
  }

  for (const token of cfg.trackedTokens) {
    state.balances[token] = await getTokenBalance(cfg.rpcUrl, token, cfg.watchedWallet, cfg);
  }

  state.lastScannedBlock = safeLatest;
  state.seenLogKeys = new Set([...k1, ...k2, ...k3]);

  // Persist before emitting: if the process dies between the two, a restart
  // resumes past this range and never re-emits what was already recorded as
  // seen -- the one gap is that an event could be marked seen without having
  // actually been printed yet, which is an acceptable tradeoff against
  // re-emitting duplicates on every crash.
  saveState(cfg.stateFilePath, state);
  record(cfg, 'OBSERVATION', {
    fromBlock,
    toBlock: safeLatest,
    approvalCount: approvalLogs.length,
    approvalForAllCount: approvalForAllLogs.length,
    transferCount: transferLogs.length,
  });

  for (const event of events) {
    record(cfg, 'EVENT', event);
    // Awaited, not fire-and-forget: emit() now drives responder.handleEvent,
    // which mutates the shared walletState.incident and must run
    // sequentially (nonce sanity) rather than racing across events.
    await emit(event);
  }

  // Second save: the first saveState() above ran before emit(), so it can't
  // see incident/currentIncidentId mutations handleEvent just made. Losing
  // those on a crash here would mint a fresh incident id on restart and
  // silently break the idempotency check they exist for.
  saveState(cfg.stateFilePath, state);

  return state;
}

// ---------------------------------------------------------------------------
// Long-running loop
// ---------------------------------------------------------------------------

export async function startWatcher(cfg, { onEvent = () => {}, alert = () => {}, state: preloaded = null } = {}) {
  // Callers (main) may preload state so the same object is shared with the
  // panic listener and responder; runWatcherCycle mutates it in place, so
  // object identity is preserved across cycles.
  let state = preloaded ?? loadState(cfg.stateFilePath) ?? (await initialState(cfg));
  saveState(cfg.stateFilePath, state);
  const breaker = new CircuitBreaker(cfg.circuitThreshold);
  let running = true;

  while (running) {
    try {
      state = await runWatcherCycle(cfg, state, onEvent);
      breaker.recordSuccess();
    } catch (err) {
      const tripped = breaker.recordFailure();
      record(cfg, 'WATCHER_ERROR', { message: err.message, consecutiveFailures: breaker.consecutiveFailures });
      if (tripped) {
        running = false;
        // Alert delivery must never mask the circuit trip itself: an
        // unconfigured Telegram already no-ops inside sendAlert, and a
        // configured-but-unreachable one only logs here.
        try {
          await alert(
            `Deplex watcher circuit tripped after ${breaker.consecutiveFailures} consecutive failures: ${err.message}`,
          );
        } catch (alertErr) {
          console.error(`[alert] failed to deliver circuit-trip alert: ${alertErr.message}`);
        }
      }
    }
    if (running) await sleep(cfg.pollMs);
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main() {
  const cfg = loadConfig();

  // Policy compiles first: enforcement rules are the reason this process
  // exists, so a broken policy file is a startup error, not a warning.
  const { compile } = await import('./policy.mjs');
  const policyText = readFileSync(cfg.policyFile, 'utf8');
  const { rules, errors, config: policyConfig } = compile(policyText);
  if (errors.length > 0) {
    for (const e of errors) console.error(`${cfg.policyFile}:${e.line}: ${e.message}`);
    throw new Error(`policy file has ${errors.length} error(s), refusing to start`);
  }

  // Env wins over policy-file directives; directives fill gaps.
  if (!cfg.watchedWallet && policyConfig.watchWallet) cfg.watchedWallet = policyConfig.watchWallet.toLowerCase();
  if (!cfg.safeAddress && policyConfig.safeAddress) cfg.safeAddress = policyConfig.safeAddress.toLowerCase();
  assertRuntimeConfig(cfg);

  // Without KeeperHub credentials + a safe address there is nothing safe to
  // execute -- run the full pipeline in DRY_RUN instead of crashing, but say
  // so unmissably: a silently-disarmed incident responder is the worst bug.
  if (!cfg.dryRun && (!cfg.keeperHub.apiKey || !cfg.safeAddress)) {
    cfg.dryRun = true;
    console.error(
      '[deplex] WARNING: enforcement DISABLED (forced DRY_RUN) -- set KEEPERHUB_API_KEY and SAFE_ADDRESS to arm execution',
    );
  }

  const { KeeperHubClient } = await import('./keeperhub.mjs');
  const { handleEvent } = await import('./responder.mjs');
  const client = new KeeperHubClient(cfg.keeperHub);
  const alert = (text) => sendAlert(cfg.telegram, text);

  const state = loadState(cfg.stateFilePath) ?? (await initialState(cfg));

  // Allowlist = policy directives + the safe address (evacuation transfers
  // to the safe address must not themselves read as suspicious outbound).
  state.allowlist = [...policyConfig.allowlist, ...(cfg.safeAddress ? [{ address: cfg.safeAddress, label: 'safe address' }] : [])];

  const ctx = { rules, cfg, client, walletState: state, alert };

  const emit = async (event) => {
    // single-token percent fallback for transfer.out.value rules
    state.balance = event.token ? state.balances[event.token] ?? null : null;
    const result = await handleEvent(event, ctx);
    if (result.executed) saveState(cfg.stateFilePath, state);
  };

  if (cfg.telegram.botToken && cfg.telegram.chatId) {
    const onPanic = (panicEvent) => {
      record(cfg, 'EVENT', panicEvent);
      emit(panicEvent).catch((err) => {
        console.error(`[responder] panic handling failed: ${err.message}`);
      });
    };

    // Fail-closed (docs/BOT-SECRETS.md): only wire up /setkey if
    // DEPLEX_BOT_MASTER_KEY is present and well-formed. If it's missing,
    // requireMasterKey() throws here, onSetKey stays undefined, and
    // telegram.mjs's dispatcher refuses to store anything it receives --
    // the rest of the watcher (panic listener included) still starts fine.
    let onSetKey;
    try {
      const { requireMasterKey, setSecret } = await import('./botsecrets.mjs');
      const { isAllowedConfigKey, isValidConfigValue, ALLOWED_CONFIG_KEYS, updateEnvFile, launchDetachedApply } =
        await import('./liveconfig.mjs');
      const masterKey = requireMasterKey(process.env);

      onSetKey = async ({ name, value }) => {
        // Only names on the fixed allowlist are recognized as real Deplex
        // config -- anything else is rejected outright rather than quietly
        // stored as if it meant something (docs/BOT-SECRETS.md).
        if (!isAllowedConfigKey(name)) {
          await sendAlert(
            cfg.telegram,
            `❌ "${name}" is not a recognized Deplex config key -- rejected, nothing stored or applied. Allowed: ${ALLOWED_CONFIG_KEYS.join(', ')}`,
          );
          return;
        }
        if (!isValidConfigValue(value)) {
          await sendAlert(
            cfg.telegram,
            `❌ "${name}": value rejected (empty, or contains a newline -- would corrupt ${cfg.liveConfig.envFilePath}'s line structure). Nothing stored or applied.`,
          );
          return;
        }

        setSecret(cfg.botSecretsPath, masterKey, name, value);

        try {
          updateEnvFile(cfg.liveConfig.envFilePath, name, value);
        } catch (err) {
          await sendAlert(
            cfg.telegram,
            `❌ Stored "${name}" encrypted, but failed to update ${cfg.liveConfig.envFilePath}: ${err.message}. Service NOT restarted -- previous config still active.`,
          );
          return;
        }

        await sendAlert(cfg.telegram, `⏳ ${name} updated on disk. Restarting the service now -- I'll confirm health shortly.`);

        // Handed off to a detached helper from here -- see
        // src/liveconfig.mjs's top comment for why this process can't
        // safely wait for and verify its own restart.
        try {
          await launchDetachedApply(name);
        } catch (err) {
          await sendAlert(
            cfg.telegram,
            `❌ ${name}: config updated, but failed to launch the restart/verify step (${err.message}). Run \`systemctl restart ${cfg.liveConfig.serviceName}\` manually and confirm it comes back healthy.`,
          );
        }
      };
    } catch (err) {
      console.error(`[telegram] /setkey disabled: ${err.message}`);
    }

    startBotListener(cfg.telegram, { onPanic, onSetKey }).catch((err) => {
      console.error(`[telegram] bot listener crashed: ${err.message}`);
    });
  }

  console.log(
    `[deplex] watching ${cfg.watchedWallet} on chain ${cfg.chainId} | rules: ${rules.length} | enforcement: ${cfg.dryRun ? 'DRY_RUN' : 'ARMED'}`,
  );
  await startWatcher(cfg, { onEvent: emit, alert, state });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
