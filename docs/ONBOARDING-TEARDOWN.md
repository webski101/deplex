# KeeperHub Onboarding / Teardown — Bounty Submission

Scoped strictly to friction integrating **KeeperHub itself** — schema mismatches, undocumented
fields, the wallet-custody architecture discovery. Deplex's own bugs and the x402/facilitator
saga live in [FAILURE-MODES.md](FAILURE-MODES.md) instead; nothing here is about our code being
wrong, only about where KeeperHub's documentation and its live behavior diverged, and what it
cost to find out.

Every entry follows the same structure: **what we tried**, **where we got stuck**, **what the
docs said vs. what was actually true**, and a **proposed fix**. Entries are grouped by theme, not
strict chronological order, but each keeps its original timestamp so the sequence of discovery is
still visible.

## Summary: the six findings that would have saved the most time

In order of how much live-debugging time each one cost, if KeeperHub fixes nothing else:

1. **The wallet-custody model isn't documented anywhere** (#6 below) — the single most
   consequential gap in the whole integration. Cost a full architecture-level detour before
   realizing detection and response would need to run against different wallets in the demo.
2. **Static docs' field names don't match the live schema at all** (#3) — camelCase in the docs,
   snake_case on the wire, for the two most safety-critical tools in the surface.
3. **Two silent wei-vs-decimal unit traps** (#4, #5) — the only non-integer numeric convention on
   an otherwise integer-everywhere API, undocumented, and costly enough that we got the *second*
   instance wrong too, after already having been burned by the first.
4. **Array-typed parameters silently require JSON-stringification** (#3b) — `function_args` and
   `abi` both reject real JSON arrays with no clear guidance that a string encoding is expected.
5. **No documented pairing between execution tools and their status/poll tools** (#1).
6. **Gas sponsorship for direct executions is unstated** (#2) — safety-critical for anything that
   might need to execute unattended.

---

## 1. Tool surface: what's missing or ambiguous

**2026-07-15 — Status-tool pairing is unclear.**
*Tried:* wire `responder.mjs` to poll for execution status after submitting a revoke/evacuate.
*Stuck:* the MCP docs list three execution-triggering tools (`execute_transfer`,
`execute_contract_call`, `execute_check_and_execute`) and *two* status tools (`get_execution`,
`get_direct_execution_status`), with no stated mapping between them. `execute_workflow` also
returns "an execution ID," undocumented whether that ID space is shared with the direct-execution
tools or separate.
*Docs vs. reality:* resolved only by dumping the live `tools/list` schema and testing empirically
against a real Sepolia call — `get_direct_execution_status` is the correct pairing for all three
direct-execution tools; `get_execution` belongs to `execute_workflow`.
*Proposed fix:* a table in the MCP docs mapping each `execute_*` tool to its status/poll tool,
with one end-to-end worked example per row.

**2026-07-15 — No confirmation-timeout or polling convention documented.**
*Tried:* decide a sane polling interval/timeout for `get_direct_execution_status`.
*Stuck:* neither doc states a recommended interval, a timeout, or what a stuck/pending execution
looks like versus a genuinely failed one — needed to decide when the responder should treat a
revocation as failed-and-escalate rather than still-pending.
*Proposed fix:* document typical latency ranges per network and the full list of terminal vs.
non-terminal status values.

**2026-07-15 — Gas sponsorship undocumented for execution tools.**
*Tried:* determine whether a revocation could fail if the watched wallet held zero native gas
token.
*Stuck:* the agentic-wallet docs describe a facilitator paying gas for x402/MPP *payment
settlement* specifically. Nothing states whether `execute_contract_call`/`execute_transfer`/
`execute_protocol_action` are gas-sponsored, or require the calling wallet to hold native gas
token — safety-critical, since an incident-response revocation silently failing on an empty gas
tank is exactly the failure mode this whole project exists to prevent.
*Docs vs. reality:* **resolved at the live milestone** — the first real execution's raw result
included `"sponsored":true` (`gasUsed:"46383"`, a real `effectiveGasPrice`), confirmed for
`execute_contract_call`. Not independently confirmed for `execute_transfer`, though there's no
reason to expect it differs.
*Proposed fix:* an explicit statement in the MCP docs — "gas for direct executions is/is not
sponsored; if not, the calling wallet must hold native gas token on \<networks\>."

## 2. Schema mismatches: static docs vs. the live wire

**2026-07-15 — `execute_contract_call`/`execute_transfer` parameter schemas not statically
documented.**
*Tried:* build `keeperhub.mjs` against the documented parameter names.
*Stuck:* `docs.keeperhub.com/ai-tools/mcp-server` names top-level fields
(`network`/`contractAddress`/`abiFragment` for calls; `network`/`recipientAddress`/`amount` for
transfers) but never shows the field for passing the call's actual arguments (e.g. `approve`'s
`spender`/`amount`), nor a token-address field for `execute_transfer`'s ERC-20 leg — despite that
tool's own description explicitly saying it handles ERC-20, not just native currency.
*Docs vs. reality:* the docs page does contain the actual fix, verbatim: "Call
`tools_documentation` (or `list_action_schemas`) at runtime for the authoritative, always-current
set." So this is intentionally not statically documented, with a real runtime-discovery pointer —
but anyone reading only the static page (the natural first stop) hits a wall on exactly the two
highest-stakes tools in the surface, with no strong signal to go try runtime discovery instead.
*Proposed fix:* a full worked JSON request/response example directly on the docs page for these
two tools, even if illustrative rather than exhaustive, or a much more prominent placement of the
"call `tools_documentation` at runtime" pointer — right next to each tool's entry, not left
implicit.

**2026-07-16 — Static docs' field names don't match the live `tools/list` schema at all.**
*Tried:* followed the docs page's own advice and dumped the runtime schema.
*Stuck/found:* every documented field name for the two direct-execution tools is wrong on the
wire:

| Tool | Live schema (authoritative) | Static docs said |
|---|---|---|
| `execute_contract_call` | required: `contract_address`, `chain_id`, `function_name`; optional: `function_args` (**JSON-stringified array**, not a raw array), `abi`, `value`, `gas_limit_multiplier`, `priority_fee_gwei`, `idempotency_key` | `network`, `contractAddress`, `abi`, `abiFunction` |
| `execute_transfer` | required: `chain_id`, `to_address`, `amount`; optional: `token_address` (omit for native), `idempotency_key` | `network`, `recipientAddress`, `amount` |
| `get_direct_execution_status` | `execution_id`; confirmed as the status pairing for both direct-execution tools | ambiguous pairing (see above) |

Not just naming drift — camelCase vs. the wire's snake_case, wholesale, on the two tools that
matter most for an incident-response use case.
*Proposed fix:* generate the docs from the same source of truth as the `tools/list` schema (or at
minimum a CI check that documented names match), plus an explicit call-out on `function_args`'
string-encoding with a worked example. **Positive note worth keeping**: `idempotency_key` on both
execution tools is exactly what an incident-response integrator needs, and was easy to adopt once
discovered — it simply isn't mentioned in the static docs at all.

**2026-07-16 — `abi` needs the same JSON-stringification trap as `function_args`, discovered the
same way.**
*Tried:* pass `execute_contract_call`'s `abi` field as a real JSON array, same as every other
array-typed parameter encountered elsewhere in this integration.
*Stuck:* rejected — "abi expected a string, got an array." A second array-typed parameter on the
*same tool* with the same undocumented string-encoding requirement as `function_args`, costing a
second live attempt on top of the first.
*Proposed fix:* either accept real JSON arrays (the standard MCP/JSON-RPC convention, and how
every other array-typed parameter encountered elsewhere behaves), or state the string-encoding
requirement once, clearly, for the tool as a whole — not leave each field to fail independently.

**2026-07-16 — `get_wallet_integration`'s id parameter is camelCase, inconsistent with the rest
of the surface.**
*Tried:* infer `get_wallet_integration`'s parameter name from the snake_case pattern already
confirmed on `execute_contract_call`, `execute_transfer`, and `get_direct_execution_status`.
*Stuck:* wrong — this one tool's parameter is `integrationId`, not `integration_id`, breaking the
pattern the first three tools had just established.
*Proposed fix:* a single documented naming convention enforced across the whole tool surface — a
lint rule in KeeperHub's own tool-schema generation would catch this class of drift
automatically.

## 3. Unit conventions: the one inconsistency that cost two live failures

**2026-07-17 — `execute_transfer`'s `amount` is a decimal string, not wei — the one field on the
whole surface that isn't an integer.**
*Tried:* pass `amount` as a wei integer, consistent with every other numeric-ish field confirmed
elsewhere (`function_args` uint256 values, balances/approvals tracked internally — all raw
integers in the token's smallest unit).
*Stuck:* silently wrong. `amount` wants a human-readable decimal string (`"0.1"`); passing a raw
wei integer doesn't error clearly — it's interpreted as that many *whole tokens* and rejected with
a balance error that reads like an unrelated problem (`"Need: 1000000000000000.0"` looks like a
huge-number bug, not a units mismatch). A related zero-balance failure was initially misdiagnosed
entirely on "the wallet has no ETH" grounds, because with balance genuinely at zero the error
looked identical either way — the units bug only became visible once balance was nonzero and the
"want" number was obviously nonsensical for what should've been a tiny transfer.
*Proposed fix:* state the unit convention per numeric field in the schema itself (`amount:
decimal string, e.g. "0.1"` vs. `function_args[uint256]: integer string, smallest unit`) rather
than leaving every field's convention to be independently discovered. A validation error reading
"expected decimal string, got integer-looking value larger than total supply" would also have
surfaced this in one attempt instead of two.

**2026-07-17 — `execute_contract_call`'s `value` is ALSO decimal ETH, not wei — and an
assumption recorded as fact hid it.**
*Tried:* after fixing `amount` above, recorded in project notes that `execute_contract_call`'s
`value` "remains wei-denominated, unaffected" — and a prior version of this very teardown log
listed `value` as a confirmed raw-integer field.
*Stuck:* **neither was true, and neither was ever actually tested.** `value` follows the exact
same decimal-ETH convention as `amount`. It surfaced as a payable `deposit()` failing "insufficient
balance" against a wallet provably holding 50x the requested amount, because
`value:"1000000000000000"` (0.001 ETH in wei) was read as 10^15 whole ETH.
*Docs vs. reality:* the single wei-vs-decimal inconsistency in this API (only native-currency
amount fields are decimal; ABI-encoded `function_args` stay integer) is easy to get wrong
per-field — but the deeper failure was ours: writing an unverified inference into notes in the
*same authoritative voice* as things actually confirmed live, so it read as settled and
propagated into a second document unchallenged.
*Process fix adopted on our side:* project notes now visibly flag corrected assumptions (⚠️
marker) instead of silently overwriting them, and `scripts/dump-tools.mjs` prints each numeric
field's verbatim schema description on request, so units are read from the source next time.
*Proposed fix on KeeperHub's side:* per-field unit annotations in the tool schema itself (e.g.
`value: "native amount, decimal string like \"0.1\""`), which a runtime schema dump would then
surface directly instead of requiring a live failure to discover.

## 4. Architecture-level: wallet custody

**2026-07-16 — KeeperHub executes from a wallet it/you manage, not an arbitrary externally-owned
wallet you merely name. Not documented anywhere.**
*Tried:* point Deplex's `WATCHED_WALLET` at an address and assume `execute_transfer`/
`execute_contract_call` could sign revocation/evacuation transactions on that wallet's behalf.
*Stuck:* those tools sign using whatever wallet is connected as your KeeperHub account's *wallet
integration* (in our case `0x2A1f47…`, `isManaged:false` — self-custodied, connected via some
flow, not Turnkey-vaulted) — a separate address from any `contract_address`/`to_address` target
parameter passed in. Passing an arbitrary watched EOA as a target does **not** make KeeperHub
sign from it.
*Docs vs. reality:* this isn't documented anywhere on the MCP-server or agentic-wallet pages —
both describe target/recipient parameters without ever stating that the *source* of execution is
a separately-connected integration, resolvable only via `get_wallet_integration`/
`list_integrations` — tools not mentioned on either docs page at all; we only knew to call them
because they surfaced in a raw `tools/list` dump.
*Why this is the single most consequential finding in this entire log:* for an incident-response
tool specifically, this determines whether the tool can act on the wallet it's supposed to be
protecting *at all*. It forced a real architecture decision: the demo's "attacker" approval had to
be planted programmatically through KeeperHub itself (`scripts/plant-approval.mjs`) rather than
manually via MetaMask as the pure-detection test did, since MetaMask holds a key KeeperHub's
integration wallet doesn't share — meaning detection and response, in the milestone demo, ended up
exercising different wallets under the hood, a meaningfully different trust story than "one
wallet, watched and defended end to end." Full technical consequences and Deplex's own scope
statement about this: [FAILURE-MODES.md](FAILURE-MODES.md#a-wallet-deplex-can-detect-into-but-not-defend-keeperhubs-custody-model).
*Proposed fix:* a single sentence, prominently placed on the `execute_transfer`/
`execute_contract_call` docs: "these tools sign using your connected wallet integration (see
`list_integrations`), not the target address you pass." Would have saved a full live-debugging
detour and a genuine architecture-level surprise discovered mid-build rather than during design.

## 5. Adjacent, not KeeperHub's fault, but worth noting for anyone reproducing this project

**2026-07-15 — Free-tier `eth_getLogs` range cap not obviously discoverable.**
Not a KeeperHub issue — this is the RPC provider layer — but worth flagging for anyone
reproducing this project on a free-tier provider: the block-range limit (10 blocks on the
provider used here) only surfaces as a runtime JSON-RPC error message, not anywhere in
KeeperHub's own docs or setup guidance. A starter template's default chunk size should ship
conservative (under 10) rather than assume a paid-tier range, since free tier is the realistic
default for a hackathon judge spinning this up cold.

**2026-07-15 — Agent-to-third-party x402 payments unspecified (resolved, see below).**
*Tried:* determine whether Deplex's x402 intel-purchase flow (Phase 5) could reuse KeeperHub's
agentic wallet to pay a third-party endpoint we wrote ourselves (`intel-agent/server.mjs`), rather
than hand-rolling x402 client-side.
*Stuck initially:* the agentic-wallet docs only describe paying a KeeperHub-*hosted* paid workflow
(`search_workflows`/`call_workflow`); they don't say whether the same wallet can be pointed at an
arbitrary third-party 402 challenge.
*Resolved, confirmed against a primary source:* KeeperHub's own GitHub README
(`KeeperHub/agentic-wallet`, verified via the GitHub API as a real, non-fork, public repo), in its
own "Reality check" section, states verbatim: *"This wallet pays **KeeperHub-listed workflows**
at `/api/mcp/workflows/<slug>/call` URLs. Generic non-KH x402 endpoints throw
`UNSUPPORTED_RECIPIENT` today."* `call_workflow`'s actual signature takes a workflow `slug`, never
an arbitrary URL — there's no generic pay-any-endpoint tool in the agentic-wallet MCP surface at
all.
*Docs vs. reality:* the static docs page (`docs.keeperhub.com/ai-tools/agentic-wallet`) reads
notably broader than this — "auto-pays any x402 or MPP 402 challenge you direct it at" — and
would have led an integrator to a dead end. The GitHub README is more specific and
self-correcting, and was treated as authoritative.
*Consequence for Deplex:* `intel-agent/server.mjs` (the seller) needed no redesign, but
`src/intel.mjs` (the buyer) could not route payment through KeeperHub at all — it hand-rolls the
x402 client side instead (EIP-3009 signing via `node:crypto`, submission to a generic
facilitator), which is where the whole [FAILURE-MODES.md](FAILURE-MODES.md) x402 saga comes from.
*Proposed fix:* either document a generic "pay any x402 endpoint" primitive if one is ever added,
or make the static docs page match the GitHub README's own "Reality check" scoping exactly, so
integrators don't spend a research pass discovering the static page overstates what's actually
supported.

## Open questions — still open, not yet confirmed either way

- Whether gas sponsorship extends to `execute_transfer` the same way it's confirmed for
  `execute_contract_call` (only the latter has been exercised live).
- The full failure/edge-case status vocabulary for direct executions beyond `"failed"`/
  `"completed"` — only those two terminal values have been observed.
