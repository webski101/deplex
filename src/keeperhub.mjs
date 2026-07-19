// KeeperHub MCP client (JSON-RPC over HTTP)
//
// Field names below are CONFIRMED against the live tools/list schema
// (dumped via scripts/dump-tools.mjs, 2026-07-16) -- snake_case throughout,
// which contradicts the static docs' camelCase-ish names. See
// docs/KEEPERHUB-NOTES.md "Schema resolution". Notables:
// - execute_contract_call: function_args is a JSON-STRINGIFIED array
// - both execution tools accept an optional idempotency_key (server-side
//   dedup on top of our audit-chain check)
// - get_direct_execution_status({ execution_id }) is the status pairing for
//   these two direct-execution tools

import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';

const PROTOCOL_VERSION = '2024-11-05';
const CLIENT_INFO = { name: 'deplex', version: '0.1.0' };

// MCP servers may reply to a session-carrying request as if the session were
// gone (expired/rotated) using any of several shapes depending on the
// server's HTTP framework. Treated as "re-init and retry once", not fatal.
const SESSION_EXPIRED_HINTS = [/session/i, /unauthorized/i, /unauthenticated/i];

// Tools whose completion means "nothing further will change" for polling
// purposes. Deliberately an allowlist of known-PENDING states rather than
// known-terminal ones: an unrecognized status is treated as terminal so
// pollExecution() surfaces it promptly instead of silently spinning past a
// status string this file doesn't know about yet -- pollTimeoutMs is the
// backstop either way. UNCONFIRMED against real KeeperHub status values.
const PENDING_STATUSES = new Set(['pending', 'processing', 'submitted', 'queued', 'in_progress', 'running']);

export class KeeperHubError extends Error {
  constructor(message, { code, httpStatus, toolError } = {}) {
    super(message);
    this.code = code;
    this.httpStatus = httpStatus;
    this.toolError = toolError;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseSseMessages(text) {
  const messages = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trimEnd();
    if (!line.startsWith('data:')) continue;
    const payload = line.slice(5).trim();
    if (!payload) continue;
    try {
      messages.push(JSON.parse(payload));
    } catch {
      // ignore malformed SSE data lines
    }
  }
  return messages;
}

let requestId = 0;

export class KeeperHubClient {
  constructor(cfg) {
    this.apiKey = cfg.apiKey;
    this.mcpUrl = cfg.mcpUrl;
    this.pollIntervalMs = cfg.pollIntervalMs ?? 3000;
    this.pollTimeoutMs = cfg.pollTimeoutMs ?? 120000;
    this.requestTimeoutMs = cfg.requestTimeoutMs ?? 20000;
    // Opt-in raw-request logging (DEPLEX_DEBUG_KEEPERHUB=1). Logs the exact
    // outgoing payload for execute_* calls -- so a units/shape mismatch is
    // inspectable directly, instead of only visible as a server-side error.
    this.debug = cfg.debug ?? process.env.DEPLEX_DEBUG_KEEPERHUB === '1';
    this.sessionId = null;
    this.initPromise = null;
  }

  // Raw JSON-RPC transport. isNotification=true sends no id and ignores the
  // response body (MCP notifications get no reply).
  async rpcRequest(method, params, { isNotification = false } = {}) {
    if (!this.apiKey) {
      throw new KeeperHubError('KEEPERHUB_API_KEY is not set');
    }
    const body = JSON.stringify({
      jsonrpc: '2.0',
      ...(isNotification ? {} : { id: ++requestId }),
      method,
      params,
    });

    const url = new URL(this.mcpUrl);
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${this.apiKey}`,
      'Content-Length': Buffer.byteLength(body),
    };
    if (this.sessionId) headers['Mcp-Session-Id'] = this.sessionId;

    const transport = url.protocol === 'http:' ? http : https;
    const { statusCode, responseHeaders, data } = await new Promise((resolve, reject) => {
      const req = transport.request(url, { method: 'POST', headers }, (res) => {
        let chunks = '';
        res.on('data', (c) => {
          chunks += c;
        });
        res.on('end', () => {
          resolve({ statusCode: res.statusCode, responseHeaders: res.headers, data: chunks });
        });
      });
      req.on('error', reject);
      // Same gap as watcher.mjs's rpcCall had (see its comment): with no
      // timeout, a hung connection to the MCP endpoint left this promise
      // never settling -- silently blocking every execution call forever,
      // no error, nothing. destroy(err) is what actually surfaces it via
      // the 'error' handler above.
      req.setTimeout(this.requestTimeoutMs, () => {
        req.destroy(new Error(`KeeperHub request timed out after ${this.requestTimeoutMs}ms (method: ${method})`));
      });
      req.write(body);
      req.end();
    });

    const returnedSessionId = responseHeaders['mcp-session-id'];
    if (returnedSessionId) this.sessionId = returnedSessionId;

    if (isNotification) {
      if (statusCode >= 400) {
        throw new KeeperHubError(`notification ${method} rejected with HTTP ${statusCode}`, { httpStatus: statusCode });
      }
      return null;
    }

    if (statusCode >= 400) {
      throw new KeeperHubError(`HTTP ${statusCode} calling ${method}: ${data.slice(0, 300) || '<empty body>'}`, {
        httpStatus: statusCode,
      });
    }

    const contentType = responseHeaders['content-type'] || '';
    let messages;
    if (contentType.includes('text/event-stream')) {
      messages = parseSseMessages(data);
    } else {
      try {
        messages = [JSON.parse(data)];
      } catch (err) {
        throw new KeeperHubError(`invalid JSON-RPC response for ${method}: ${err.message}; raw: ${data.slice(0, 300)}`);
      }
    }

    const message = messages.find((m) => m.id === requestId) || messages[messages.length - 1];
    if (!message) {
      throw new KeeperHubError(`no JSON-RPC response found for ${method}`);
    }
    if (message.error) {
      throw new KeeperHubError(message.error.message || `${method} failed`, { code: message.error.code });
    }
    return message.result;
  }

  // Idempotent, concurrency-safe: parallel callers awaiting the same init
  // share one in-flight request instead of racing separate handshakes.
  async ensureSession() {
    if (this.sessionId) return;
    if (!this.initPromise) {
      this.initPromise = this._initSession().finally(() => {
        this.initPromise = null;
      });
    }
    await this.initPromise;
  }

  async _initSession() {
    await this.rpcRequest('initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: CLIENT_INFO,
    });
    await this.rpcRequest('notifications/initialized', {}, { isNotification: true });
  }

  isSessionExpiredError(err) {
    const text = `${err.message} ${err.code ?? ''}`;
    return err.httpStatus === 401 || err.httpStatus === 403 || SESSION_EXPIRED_HINTS.some((re) => re.test(text));
  }

  // Every public call goes through here: ensures a session exists, and on a
  // session-shaped failure, re-inits exactly once and retries. Anything else
  // (validation errors, network errors) propagates immediately.
  async call(method, params) {
    await this.ensureSession();
    try {
      return await this.rpcRequest(method, params);
    } catch (err) {
      if (!this.isSessionExpiredError(err)) throw err;
      this.sessionId = null;
      await this.ensureSession();
      return this.rpcRequest(method, params);
    }
  }

  async listTools() {
    const result = await this.call('tools/list', {});
    return result?.tools ?? [];
  }

  async callTool(name, args) {
    const result = await this.call('tools/call', { name, arguments: args });
    if (result?.isError) {
      const text = (result.content || []).map((c) => c.text).filter(Boolean).join(' ');
      throw new KeeperHubError(`tool ${name} returned an error: ${text || '<no detail>'}`, { toolError: true });
    }
    if (result?.structuredContent !== undefined) return result.structuredContent;
    const textBlock = (result?.content || []).find((c) => c.type === 'text');
    if (textBlock) {
      try {
        return JSON.parse(textBlock.text);
      } catch {
        return textBlock.text;
      }
    }
    return result;
  }
}

function normalizeExecutionResult(raw) {
  return {
    status: raw?.status ?? raw?.state ?? null,
    txHash: raw?.txHash ?? raw?.transactionHash ?? raw?.tx_hash ?? null,
    explorerUrl: raw?.explorerUrl ?? raw?.explorer_url ?? null,
    gasUsed: raw?.gasUsed ?? raw?.gas_used ?? null,
    trace: raw?.trace ?? raw?.logs ?? null,
    executionId: raw?.executionId ?? raw?.execution_id ?? raw?.id ?? null,
    raw,
  };
}

export async function searchActions(client, query) {
  return client.callTool('search_protocol_actions', { query });
}

// abiFragment: a single ABI function fragment object, e.g.
// { name: 'approve', type: 'function', inputs: [...], outputs: [...] }.
// The abi field is optional server-side (omittable for verified contracts),
// but we always send it: incident response regularly touches attacker-
// deployed, unverified token contracts, and supplying the fragment keeps
// behavior identical for both.
export async function executeContractCall(client, { chain, to, abiFragment, args = [], value, idempotencyKey }) {
  const payload = {
    chain_id: chain,
    contract_address: to,
    function_name: abiFragment.name,
    // per live schema: BOTH function_args and abi are JSON-stringified,
    // never raw arrays -- function_args confirmed via dump-tools.mjs, abi
    // confirmed via a live "abi expected a string, got an array" rejection.
    // Don't assume any array-typed field here is safe until it's been hit.
    function_args: JSON.stringify(args),
    abi: JSON.stringify([abiFragment]),
  };
  // `value` is the native-ETH amount for a payable call, and it follows the
  // SAME decimal-string convention as execute_transfer's `amount` -- NOT wei.
  // Confirmed live: a payable deposit() with value:"1000000000000000" (0.001
  // ETH in wei) failed "insufficient balance" against a wallet holding 0.098
  // ETH, because the raw integer was read as 10^15 whole ETH. Callers still
  // pass wei (consistent with the rest of this codebase); native ETH is
  // always 18 decimals, so the conversion is fixed here.
  if (value !== undefined) payload.value = weiToDecimalString(value, 18);
  if (idempotencyKey) payload.idempotency_key = idempotencyKey;
  if (client.debug) console.error(`[keeperhub debug] execute_contract_call payload: ${JSON.stringify(payload)}`);
  const result = await client.callTool('execute_contract_call', payload);
  return normalizeExecutionResult(result);
}

// execute_transfer's amount is a human-readable decimal string ("0.1"), NOT
// wei -- confirmed live: passing a raw wei integer got read as that many
// whole tokens and rejected as an absurd balance ("Need: 1000000000000000.0").
// Every value this codebase otherwise carries around (getTokenBalance,
// eth_getBalance, activeApprovals) is wei, by design -- exact integers, no
// float precision loss. So the conversion happens ONCE, here, at the one
// boundary that needs decimal strings, via BigInt integer division (never
// Number/parseFloat, which would silently lose precision on real balances).
export function weiToDecimalString(weiValue, decimals = 18) {
  const wei = BigInt(weiValue);
  const divisor = 10n ** BigInt(decimals);
  const whole = wei / divisor;
  const fraction = wei % divisor;
  const fractionStr = fraction.toString().padStart(decimals, '0').replace(/0+$/, '');
  return fractionStr ? `${whole}.${fractionStr}` : `${whole}`;
}

// decimals: defaults to 18 (correct for native ETH and most ERC-20 tokens,
// including WETH -- the only tokens this project has exercised so far).
// Callers transferring a token with different decimals (e.g. USDC's 6) MUST
// pass the real value -- see src/watcher.mjs's getTokenDecimals.
export async function executeTransfer(client, { chain, token, to, amount, decimals = 18, idempotencyKey }) {
  const payload = { chain_id: chain, to_address: to, amount: weiToDecimalString(amount, decimals) };
  if (token) payload.token_address = token; // omit entirely for native transfers
  if (idempotencyKey) payload.idempotency_key = idempotencyKey;
  if (client.debug) console.error(`[keeperhub debug] execute_transfer payload: ${JSON.stringify(payload)}`);
  const result = await client.callTool('execute_transfer', payload);
  return normalizeExecutionResult(result);
}

// get_direct_execution_status is the status pairing for execute_transfer /
// execute_contract_call specifically (confirmed via live schema dump);
// get_execution belongs to execute_workflow.
export async function getExecution(client, executionId) {
  const result = await client.callTool('get_direct_execution_status', { execution_id: executionId });
  return normalizeExecutionResult(result);
}

export function isTerminalStatus(status) {
  if (!status) return false;
  return !PENDING_STATUSES.has(String(status).toLowerCase());
}

export async function pollExecution(client, executionId, opts = {}) {
  const intervalMs = opts.intervalMs ?? client.pollIntervalMs;
  const timeoutMs = opts.timeoutMs ?? client.pollTimeoutMs;
  const startedAt = Date.now();
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const status = await getExecution(client, executionId);
    if (isTerminalStatus(status.status)) return status;
    if (Date.now() - startedAt > timeoutMs) {
      throw new KeeperHubError(
        `execution ${executionId} did not reach terminal status within ${timeoutMs}ms (last status: ${status.status})`,
      );
    }
    await sleep(intervalMs);
  }
}
