// One-shot diagnostic: dump KeeperHub's authoritative tool schemas.
// Usage:  node scripts/dump-tools.mjs
// Needs:  KEEPERHUB_API_KEY in env (KEEPERHUB_MCP_URL optional override).
//
// Exists to resolve the two UNCONFIRMED field names in src/keeperhub.mjs
// (execute_contract_call's call-arguments field, execute_transfer's ERC-20
// token field) against the live server instead of guessing from docs.

import { KeeperHubClient } from '../src/keeperhub.mjs';
import { loadConfig } from '../src/config.mjs';

const FOCUS = ['execute_contract_call', 'execute_transfer', 'get_direct_execution_status'];

const cfg = loadConfig();
if (!cfg.keeperHub.apiKey) {
  console.error('KEEPERHUB_API_KEY is not set');
  process.exit(1);
}

const client = new KeeperHubClient(cfg.keeperHub);
const tools = await client.listTools();

console.log(`# ${tools.length} tools exposed by ${cfg.keeperHub.mcpUrl}\n`);
console.log(tools.map((t) => `- ${t.name}`).join('\n'));

for (const name of FOCUS) {
  const tool = tools.find((t) => t.name === name);
  console.log(`\n${'='.repeat(70)}\n## ${name}\n`);
  if (!tool) {
    console.log('NOT FOUND in tools/list');
    continue;
  }
  console.log(JSON.stringify(tool.inputSchema ?? tool, null, 2));
}

// Focused unit-convention check: for each numeric-ish field, print its
// description verbatim so wei-vs-decimal is settled from the schema itself,
// not inferred. Motivated by execute_transfer.amount (decimal, not wei) and
// execute_contract_call.value (same -- confirmed only after a live failure).
console.log(`\n${'='.repeat(70)}\n## Numeric field units (verbatim descriptions)\n`);
const UNIT_FIELDS = {
  execute_transfer: ['amount'],
  execute_contract_call: ['value', 'function_args', 'gas_limit_multiplier', 'priority_fee_gwei'],
};
for (const [toolName, fields] of Object.entries(UNIT_FIELDS)) {
  const tool = tools.find((t) => t.name === toolName);
  const props = tool?.inputSchema?.properties ?? {};
  for (const f of fields) {
    const spec = props[f];
    console.log(`- ${toolName}.${f}: ${spec ? JSON.stringify({ type: spec.type, description: spec.description }) : 'NOT IN SCHEMA'}`);
  }
}
