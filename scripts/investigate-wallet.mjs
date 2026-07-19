// One-shot diagnostic: which wallet does KeeperHub actually execute FROM?
// Usage:  node scripts/investigate-wallet.mjs
// Needs:  KEEPERHUB_API_KEY in env.
//
// Exists because EVACUATE failed with "Insufficient ETH balance. Have: 0.0,
// Need: 0.148..." against a watched wallet that verifiably holds ~0.148
// Sepolia ETH on Etherscan -- strong signal that execute_transfer /
// execute_contract_call execute from a KeeperHub-managed wallet, not from
// an arbitrary address we merely name as a parameter. This script checks
// directly rather than assuming: prints tool schemas first (so we're not
// guessing call shapes either), then attempts the calls and prints raw
// results. One tool failing must not stop the others from reporting.

import { KeeperHubClient } from '../src/keeperhub.mjs';
import { loadConfig } from '../src/config.mjs';

const cfg = loadConfig();
if (!cfg.keeperHub.apiKey) {
  console.error('KEEPERHUB_API_KEY is not set');
  process.exit(1);
}

const client = new KeeperHubClient(cfg.keeperHub);
const tools = await client.listTools();

const WATCHED_WALLET = process.env.WATCHED_WALLET || '(WATCHED_WALLET not set)';
console.log(`Watched wallet under investigation: ${WATCHED_WALLET}\n`);

function printSchema(name) {
  const tool = tools.find((t) => t.name === name);
  console.log(`\n${'='.repeat(70)}\n## ${name} -- schema\n`);
  if (!tool) {
    console.log('NOT FOUND in tools/list');
    return false;
  }
  console.log(JSON.stringify(tool.inputSchema ?? tool, null, 2));
  return true;
}

async function tryCall(name, args, label = 'result') {
  console.log(`\n-- calling ${name}(${JSON.stringify(args)}) --`);
  try {
    const result = await client.callTool(name, args);
    console.log(`${label}:`, JSON.stringify(result, null, 2));
    return result;
  } catch (err) {
    console.log(`ERROR calling ${name}: ${err.message}`);
    return null;
  }
}

// 1. Full tool list, so we can see what's actually available (names only --
// full schemas dumped below for the ones we're about to call).
console.log(`# ${tools.length} tools total:\n`);
console.log(tools.map((t) => `- ${t.name}`).join('\n'));

// 2. Schemas for the tools in question, before calling them.
const hasListIntegrations = printSchema('list_integrations');
const hasGetWalletIntegration = printSchema('get_wallet_integration');
const hasToolsDocumentation = printSchema('tools_documentation');

// 3. list_integrations first -- if it returns wallet entries, use them to
// call get_wallet_integration correctly instead of guessing an id shape.
let integrations = null;
if (hasListIntegrations) {
  integrations = await tryCall('list_integrations', {}, 'list_integrations result');
}

// 4. get_wallet_integration -- param name is "integrationId" (camelCase),
// confirmed by a live validation error against the snake_case
// "integration_id" every other tool in this file uses. Inconsistent with
// the rest of the surface; logged in docs/ONBOARDING-TEARDOWN.md.
// CLI arg > list_integrations' first result > no-args fallback.
if (hasGetWalletIntegration) {
  const explicitId = process.argv[2] || null;
  const candidateId =
    explicitId ??
    integrations?.integrations?.[0]?.id ??
    integrations?.[0]?.id ??
    integrations?.wallets?.[0]?.id ??
    null;
  if (candidateId) {
    console.log(`\n(using integration id: ${candidateId}${explicitId ? ' -- from CLI arg' : ' -- from list_integrations'})`);
    await tryCall('get_wallet_integration', { integrationId: candidateId }, 'get_wallet_integration result');
  } else {
    console.log('\n(no integration id available -- trying get_wallet_integration with no args)');
    await tryCall('get_wallet_integration', {}, 'get_wallet_integration result (no args)');
  }
}

// 5. tools_documentation -- the docs page's own pointer for "authoritative,
// always-current" schema/behavior detail.
if (hasToolsDocumentation) {
  await tryCall('tools_documentation', {}, 'tools_documentation result');
}

console.log(`\n${'='.repeat(70)}\nDone. Paste this whole output back.`);
