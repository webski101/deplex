// env loading, addresses, thresholds

import { readFileSync } from 'node:fs';

function parseAddressList(value) {
  if (!value) return [];
  return value.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}

function parseIntEnv(value, fallback) {
  const n = Number(value);
  return value !== undefined && value !== '' && Number.isFinite(n) ? n : fallback;
}

// A PEM has literal newlines, awkward to hand-transcribe into a single-line
// env value correctly -- INTEL_AGENT_PUBLIC_KEY_FILE lets the caller instead
// point straight at intel-agent's own .keypair.json (or a raw .pem file),
// removing that manual, error-prone reformatting step for a live run.
// Wrapped in try/catch so loadConfig() keeps its "never throws" contract --
// a missing/bad file just means intelAgent.publicKeyPem stays null, and
// intel.mjs's own fail-closed path (INTEL_AGENT_PUBLIC_KEY not configured)
// handles that the same way a genuinely-unset value would.
function loadIntelAgentPublicKey(env) {
  if (env.INTEL_AGENT_PUBLIC_KEY) return env.INTEL_AGENT_PUBLIC_KEY.replace(/\\n/g, '\n');
  if (env.INTEL_AGENT_PUBLIC_KEY_FILE) {
    try {
      const raw = readFileSync(env.INTEL_AGENT_PUBLIC_KEY_FILE, 'utf8');
      try {
        const parsed = JSON.parse(raw);
        if (parsed.publicKeyPem) return parsed.publicKeyPem;
      } catch {
        // not JSON -- fall through and treat it as a raw PEM file
      }
      return raw;
    } catch {
      return null;
    }
  }
  return null;
}

// loadConfig() never throws so other modules (and tests) can inspect the
// shape of config without a fully-populated environment. Use
// assertRuntimeConfig() before actually starting the watcher.
export function loadConfig(env = process.env) {
  return {
    rpcUrl: env.RPC_URL || null,
    chainId: env.CHAIN_ID || '11155111', // Sepolia by default
    pollMs: parseIntEnv(env.POLL_MS, 4000),
    watchedWallet: env.WATCHED_WALLET ? env.WATCHED_WALLET.toLowerCase() : null,
    safeAddress: env.SAFE_ADDRESS ? env.SAFE_ADDRESS.toLowerCase() : null,
    trackedTokens: parseAddressList(env.TRACKED_TOKENS),
    startBlock: env.START_BLOCK ? parseIntEnv(env.START_BLOCK, null) : null,
    stateFilePath: env.STATE_FILE || './deplex-state.json',
    auditLogPath: env.AUDIT_LOG_FILE || './deplex-audit.jsonl',
    policyFile: env.POLICY_FILE || './policies/default.policy',
    // Free-tier RPC plans commonly cap eth_getLogs ranges hard (10 blocks is
    // the tightest observed, on Alchemy free tier). Default under that cap;
    // raise LOG_CHUNK_SIZE on paid plans or self-hosted nodes.
    chunkSize: parseIntEnv(env.LOG_CHUNK_SIZE, 8),
    // Minimum gap between ANY two RPC requests (shared gate across all call
    // types). 250ms = 4 req/s: conservative for free tiers, which throttle on
    // burst rate, not just volume. Lower it on paid plans via env.
    requestSpacingMs: parseIntEnv(env.RPC_REQUEST_SPACING_MS, 250),
    // Per-attempt hard cap on an RPC HTTP request. Without this, a hung TCP
    // connection (firewall silently dropping packets, a provider that stops
    // responding mid-connection) left the request promise NEVER settling --
    // confirmed live as a silent watcher hang with no error, no heartbeat,
    // nothing. This is what turns that into a normal, retryable failure.
    requestTimeoutMs: parseIntEnv(env.RPC_REQUEST_TIMEOUT_MS, 20000),
    confirmations: parseIntEnv(env.CONFIRMATIONS, 2),
    circuitThreshold: parseIntEnv(env.CIRCUIT_THRESHOLD, 5),
    maxRetries: parseIntEnv(env.RPC_MAX_RETRIES, 5),
    baseBackoffMs: parseIntEnv(env.RPC_BASE_BACKOFF_MS, 500),
    maxBackoffMs: parseIntEnv(env.RPC_MAX_BACKOFF_MS, 30000),
    dryRun: env.DRY_RUN === '1',
    // Atomic units of whatever asset the intel agent prices in (e.g. USDC has
    // 6 decimals -- "1000" atomic = $0.001), enforced per-incident against
    // the sum of that incident's prior INTEL_PURCHASE records. See intel.mjs.
    maxIntelSpend: parseIntEnv(env.MAX_INTEL_SPEND, 0),
    intelAgent: {
      url: env.INTEL_AGENT_URL || null,
      // PEM, pinned out-of-band -- deliberately NOT trusted from the
      // agent's own response body (see intel.mjs's verification comment for
      // why: a response can carry any publicKeyPem it likes, so verifying
      // against a self-supplied key would authenticate nothing). Set
      // directly (supports literal \n escapes) or via
      // INTEL_AGENT_PUBLIC_KEY_FILE pointing at intel-agent/.keypair.json.
      publicKeyPem: loadIntelAgentPublicKey(env),
      // Deplex's own funded x402 payer key (EVM, secp256k1) -- distinct from
      // KeeperHub's agentic wallet, which per KEEPERHUB-NOTES.md cannot pay
      // third-party x402 endpoints. This is the one other deliberate,
      // narrowly-scoped direct-signing exception besides attack/crypto.mjs;
      // see README's constraints section.
      payerPrivateKey: env.INTEL_PAYER_PRIVATE_KEY || null,
      requestTimeoutMs: parseIntEnv(env.INTEL_AGENT_REQUEST_TIMEOUT_MS, 20000),
    },
    // Phase 6 demo only: a pre-deployed, publicly mintable-or-owned Sepolia
    // ERC-721 for the multi-vector attack demo. Deliberately no default --
    // we won't guess/hardcode an NFT contract address we haven't
    // independently verified is live (see attack/drainer.mjs).
    attackNftContract: env.ATTACK_NFT_CONTRACT || null,
    // Deliberately Deplex-prefixed with no fallback to generic TELEGRAM_*
    // names: this machine runs other bots, and silently inheriting another
    // bot's token from a shared shell would cross-wire alerts.
    telegram: {
      botToken: env.DEPLEX_TELEGRAM_BOT_TOKEN || null,
      chatId: env.DEPLEX_TELEGRAM_CHAT_ID || null,
    },
    keeperHub: {
      apiKey: env.KEEPERHUB_API_KEY || null,
      mcpUrl: env.KEEPERHUB_MCP_URL || 'https://app.keeperhub.com/mcp',
      pollIntervalMs: parseIntEnv(env.KEEPERHUB_POLL_MS, 3000),
      pollTimeoutMs: parseIntEnv(env.KEEPERHUB_POLL_TIMEOUT_MS, 120000),
      // Per-HTTP-request cap, distinct from pollTimeoutMs (which bounds the
      // whole poll-until-terminal-status loop across many requests).
      requestTimeoutMs: parseIntEnv(env.KEEPERHUB_REQUEST_TIMEOUT_MS, 20000),
    },
  };
}

export function assertRuntimeConfig(cfg) {
  const missing = [];
  if (!cfg.rpcUrl) missing.push('RPC_URL');
  if (!cfg.watchedWallet) missing.push('WATCHED_WALLET');
  if (missing.length) {
    throw new Error(`missing required environment variable(s): ${missing.join(', ')}`);
  }
}

export function assertResponderConfig(cfg) {
  const missing = [];
  if (!cfg.keeperHub.apiKey) missing.push('KEEPERHUB_API_KEY');
  if (!cfg.safeAddress) missing.push('SAFE_ADDRESS');
  if (missing.length) {
    throw new Error(`missing required environment variable(s): ${missing.join(', ')}`);
  }
}
