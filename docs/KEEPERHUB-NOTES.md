# KeeperHub Integration Notes

Summarized from live fetches of:
- https://docs.keeperhub.com/ai-tools/mcp-server
- https://docs.keeperhub.com/ai-tools/agentic-wallet

Fetched: 2026-07-15. Re-fetch before Phase 3 if any of this feels stale — do not build against memory of this file alone.

## Environment variables (Deplex-side, KeeperHub-related)

Pulled directly from `src/config.mjs`/`src/keeperhub.mjs` — kept in sync with the code, not maintained separately from it.

| Var | Default | Purpose |
|---|---|---|
| `KEEPERHUB_API_KEY` | none (required to arm enforcement) | Bearer token, `kh_...` prefix |
| `KEEPERHUB_MCP_URL` | `https://app.keeperhub.com/mcp` | MCP endpoint override |
| `KEEPERHUB_POLL_MS` | `3000` | Interval between `get_direct_execution_status` polls |
| `KEEPERHUB_POLL_TIMEOUT_MS` | `120000` | Overall cap on the poll-until-terminal-status loop |
| `KEEPERHUB_REQUEST_TIMEOUT_MS` | `20000` | Per-HTTP-request cap — closes the silent-hang gap, see `FAILURE-MODES.md` |
| `DEPLEX_DEBUG_KEEPERHUB` | unset (off) | Set to `1` to log the exact outgoing `execute_contract_call`/`execute_transfer` payload before it's sent — added after the `value`-units bug below cost a live failure to diagnose without it |

## MCP endpoint

- Aggregate server: `https://app.keeperhub.com/mcp`
- Per-workflow servers: `https://app.keeperhub.com/mcp/w/<slug>`

## Session / auth flow

Two supported methods:

1. **OAuth 2.1** — metadata discoverable at `/.well-known/oauth-authorization-server`. Access tokens expire after 1 hour; refresh tokens last 30 days.
2. **API key** — organization key prefixed `kh_`, sent as a Bearer token:
   `Authorization: Bearer kh_your_key_here`

Organization scoping follows whichever org was active at OAuth approval, or whichever org created the API key. Deplex will use the API key method (`KEEPERHUB_API_KEY` env var per Phase 3 spec) since there's no interactive browser step in a headless watcher process.

## Tool names (verbatim from docs)

**Protocol actions**
- `search_protocol_actions` — discovers available actions across supported protocols
- `execute_protocol_action` — executes an action using an `actionType` string, e.g. `"aave-v3/supply"`

**Transfers / direct execution**
- `execute_transfer` — native or ERC-20 token transfers
- `execute_contract_call` — arbitrary smart contract interactions (this is what Deplex will use for `approve(spender, 0)` revocations)
- `execute_check_and_execute` — conditional on-chain logic

**Execution status**
- `execute_workflow` — triggers manual workflow execution, returns an execution ID
- `get_execution` — combined status + step-by-step logs, single call
- `get_direct_execution_status` — status/tx-hash lookup specifically for direct executions (`execute_transfer` / `execute_contract_call` / `execute_check_and_execute`)

Phase 3 spec named a `getExecution(id)` wrapper — map that to `get_direct_execution_status` for transfer/contract-call executions, or `get_execution` for workflow executions. **Ambiguous: docs don't spell out which status tool pairs with which execution tool** — verify empirically against a real Sepolia call before wiring `responder.mjs`, don't assume.

## Networks (chain ID strings)

`"1"` Ethereum mainnet, `"11155111"` Sepolia, `"8453"` Base, `"42161"` Arbitrum, `"137"` Polygon.

Phase 2 targets Sepolia (`"11155111"`) first, per the build plan.

## Gas sponsorship

**Not documented.** The MCP docs say nothing about gas estimation or sponsorship for `execute_transfer` / `execute_contract_call` / `execute_protocol_action`. Assume KeeperHub handles gas server-side (the agentic-wallet docs describe a facilitator paying gas for x402/MPP payment settlement specifically, not for protocol-action execution) — **do not assume this extends to revocation/evacuation txs** until confirmed by a real Phase-3 execution. Flagged in the teardown log below.

## x402 / agentic wallet (for Phase 5 intel purchases)

- Settlement is **x402 on Base USDC** (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) or **MPP on Tempo USDC.e** (`0x20C000000000000000000000B9537D11c60E8b50`).
- x402: agent signs an EIP-3009 `TransferWithAuthorization`; the x402 facilitator submits the tx and pays gas — only the USDC amount debits the wallet.
- MPP (Tempo): agent signs an authorization for the MPP facilitator to settle the USDC.e transfer; facilitator pays Tempo network fees.
- Discovery/execution meta-tools: `search_workflows` (find workflows by category/tag) and `call_workflow` (execute by slug). On a `402` response, "the wallet intercepts the challenge, signs through the server-side proxy ..., and the call retries transparently."
- **Gap**: docs only describe agent-to-KeeperHub-workflow payment (calling a KeeperHub-hosted paid workflow). They do **not** describe agent-to-third-party-agent payment — which is exactly the intel-agent shape in Phase 5 (Deplex paying `intel-agent/server.mjs`, a service *we* wrote, not a KeeperHub workflow). Confirm before Phase 5 whether the agentic wallet's x402 client can pay an arbitrary third-party 402 endpoint, or whether it's KeeperHub-workflow-only — this determines whether `intel.mjs` can reuse the agentic wallet at all or needs to speak raw x402 itself.

## RESOLVED — agentic wallet does not support third-party x402 endpoints

**Verdict: KeeperHub-native workflows only.** Confirmed 2026-07-15 directly against primary sources (fetched myself, not inferred):

- Source: `https://raw.githubusercontent.com/KeeperHub/agentic-wallet/main/README.md` (repo verified via `https://api.github.com/repos/KeeperHub/agentic-wallet` — id `1217446004`, org `KeeperHub`, not a fork, public, created 2026-04-21).
- The README's "Reality check" section, verbatim: *"This wallet pays **KeeperHub-listed workflows** at `/api/mcp/workflows/<slug>/call` URLs. Generic non-KH x402 endpoints throw `UNSUPPORTED_RECIPIENT` today — that's deferred until per-call principal-authorization (AP2) lands."*
- `call_workflow`'s actual signature is `{ slug: string, body?, paymentHint?: "auto"|"x402"|"mpp", responseFormat? }` — it takes a workflow **slug**, never an arbitrary URL. There is no generic pay-any-endpoint tool in the agentic wallet MCP surface (only `call_workflow`, `balance`, `info`, `feedback`).
- Note: `docs.keeperhub.com/ai-tools/agentic-wallet` itself is vaguer ("auto-pays any x402 or MPP 402 challenge you direct it at") and reads as broader support — treating the GitHub README as authoritative since it's more specific and explicitly self-correcting ("Reality check").

**Architecture consequence for Phase 5:** `intel-agent/server.mjs` stays a bare `node:http` server exactly as specced — no redesign needed there. But `src/intel.mjs` (the buyer side) **cannot** route the x402 payment through KeeperHub's agentic wallet, since `intel-agent` is not a KeeperHub-listed workflow. KeeperHub's own README points to the `x402-fetch` npm package as the fallback for third-party endpoints — not usable here under the zero-npm-dependency constraint. Instead, `intel.mjs` must hand-roll the x402 client side: sign an EIP-3009 `TransferWithAuthorization` with `node:crypto` and submit it to a generic x402 facilitator's verify/settle endpoints per the open x402 spec, independent of KeeperHub. This is consistent with the project's existing hand-rolled-crypto pattern (ABI decoding in `watcher.mjs`, hash chaining in `auditlog.mjs`) — more implementation work in Phase 5, no change to the zero-dependency constraint or to `intel-agent/`'s shape.

## Phase 3 refetch (2026-07-15) — re-confirmed against live docs before building keeperhub.mjs

Re-fetched `https://docs.keeperhub.com/ai-tools/mcp-server` per standing instruction ("if docs contradict notes, re-fetch, update, flag"). Endpoint, auth flow, and tool name list from Phase 0 are all still accurate — no drift there. But this pass pulled concrete parameter names that Phase 0's summary didn't surface, and they **don't match the build-prompt's assumed shape**:

| Build-prompt assumed | Docs actually say |
|---|---|
| `executeContractCall({ chain, to, abiFragment, args })` | `execute_contract_call`: `network`, `contractAddress`, `abi`, `abiFunction` — **no field for the call's actual arguments** (e.g. `approve`'s `spender`/`amount`) is documented anywhere |
| `executeTransfer({ chain, token, to, amount })` | `execute_transfer`: `network`, `recipientAddress`, `amount` — **no `token`/`tokenAddress` field documented**, despite the tool description explicitly saying "Transfer native **or ERC20** tokens" |

I pushed a second, more targeted fetch asking specifically for the full JSON schema / example request bodies for these two tools. The page does not contain them. It does contain this, verbatim, which is the actual documented answer to the gap:

> "Call `tools_documentation` (or `list_action_schemas`) at runtime for the authoritative, always-current set."

So this isn't undocumented-and-guessable — it's **intentionally not statically documented**, with an explicit runtime discovery mechanism pointed to instead. Standard MCP also mandates every compliant server expose `tools/list`, which returns each tool's JSON Schema `inputSchema` — a second, protocol-level (not KeeperHub-specific) way to get the same answer.

**Decision**: `keeperhub.mjs` implements `listTools()` (standard MCP `tools/list`) so the authoritative schema is fetchable at runtime once a real `KEEPERHUB_API_KEY` is available. `executeContractCall`/`executeTransfer` are implemented now with a best-effort inner shape (`args` for call arguments, `tokenAddress` for the optional ERC-20 leg of a transfer — both chosen for consistency with common Web3-tooling convention, not because they're confirmed), each flagged UNCONFIRMED in code comments and logged as a runtime warning on every call until verified. Low risk to proceed this way: a wrong field name against a schema-validated MCP tool should bounce with a clear validation error naming the expected field, not silently misfire — so the Phase 3 milestone's first live call doubles as the schema confirmation step. Real request/response gets pasted into this file the moment that happens.

## Schema resolution (2026-07-16) — live `tools/list` dump via scripts/dump-tools.mjs

The runtime schema settles both UNCONFIRMED fields, and contradicts the static docs' field naming wholesale — the live surface is **snake_case**, the docs used camelCase-ish names that don't exist on the wire:

| Tool | Live schema (authoritative) | Static docs said |
|---|---|---|
| `execute_contract_call` | required: `contract_address`, `chain_id`, `function_name`; optional: `function_args` (**JSON-stringified array**, not a raw array), `abi`, `value`, `gas_limit_multiplier`, `priority_fee_gwei`, `idempotency_key` | `network`, `contractAddress`, `abi`, `abiFunction` |
| `execute_transfer` | required: `chain_id`, `to_address`, `amount`; optional: `token_address` (omit for native), `idempotency_key` | `network`, `recipientAddress`, `amount` |
| `get_direct_execution_status` | `execution_id`; confirmed as the status pairing for the two direct-execution tools (`get_execution` belongs to `execute_workflow`) | ambiguous pairing |

Notes:
- `function_args` being a JSON **string** is the sharpest trap — a raw array is the natural guess and both the docs and MCP convention point that way. `execute_contract_call`'s `abi` field turned out to need the same treatment (also a JSON string, not a raw array) — confirmed live on 2026-07-16, see the teardown log.
- `abi` is optional for verified contracts; Deplex always sends the single relevant fragment anyway, since incident response regularly touches attacker-deployed unverified tokens.
- `idempotency_key` (both execution tools) gives server-side dedup on top of Deplex's audit-chain check; `responder.mjs` passes its actionKey (`incidentId:ACTION:target`) through.
- Gas knobs exist (`gas_limit_multiplier`, `priority_fee_gwei`) — so gas is estimated server-side with client-side multipliers available. Whether it's *sponsored* (or paid from the org's wallet integration) is still not stated anywhere; observe on the first live execution.
- **`execute_transfer`'s `amount` AND `execute_contract_call`'s `value` are human-readable decimal strings** (e.g. `"0.1"`), **not wei.** `amount` confirmed live 2026-07-16 (raw wei `"1000000000000000"` read as that many whole tokens, "Need: 1000000000000000.0"). `value` confirmed live 2026-07-17 the same way: a payable `deposit()` with `value:"1000000000000000"` (0.001 ETH in wei) failed "insufficient balance" against a wallet holding 0.098 ETH, because 10^15 was read as whole ETH. Every value this codebase otherwise carries (balances, approval amounts) is wei, by design — exact integers, no float precision loss — so the conversion happens once, centrally, inside `keeperhub.mjs` (`weiToDecimalString`, BigInt-based, decimals-aware) for both fields; callers keep passing wei. **`execute_contract_call`'s `function_args` uint256 values remain raw wei/smallest-unit integer strings** (they're ABI-encoded, a different path) — the decimal convention applies specifically to native-currency amount fields (`amount`, `value`).
  - ⚠️ *This entry originally asserted `value` "remains wei-denominated, unaffected" — that was an **unverified assumption written as fact**, and it was wrong. Cost a live deposit failure to catch. Lesson recorded in the teardown log.*

`src/keeperhub.mjs` and tests updated to these exact names on 2026-07-16.

## Resolved at the live milestone (2026-07-16)

- **Gas is sponsored.** The milestone REVOKE's raw execution result included `"sponsored":true` (`gasUsed:"46383"`, `effectiveGasPrice:"1134645244"`) — confirmed for `execute_contract_call`; not yet independently confirmed for `execute_transfer`, but no reason to expect it differs.
- **Real status strings observed:** `EXECUTION_SUBMITTED` and terminal `EXECUTION_RESULT` both used `"completed"` for success. Our `SUCCESS_STATUSES`/`PENDING_STATUSES` sets in `keeperhub.mjs`/`responder.mjs` didn't include `"completed"` as a *pending* value (correct — no change needed), and `isSuccessStatus` already listed `"completed"` (correct, matched on the first real attempt). Still-unconfirmed: the exact failure-status vocabulary (we've only observed `"failed"` so far, from the pre-fix EVACUATE attempt).

## Open questions — still open

- Whether gas sponsorship extends to `execute_transfer` the same way it's confirmed for `execute_contract_call`.
- Full failure/edge-case status vocabulary beyond `"failed"`/`"completed"`.
