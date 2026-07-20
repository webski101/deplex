# Deplex

**An onchain incident-response agent that executes, not just alerts.** Deplex watches a wallet
for dangerous approvals and outbound transfers, decides deterministically (a controlled-English
policy compiler, never an LLM) what tier of response is warranted, and — through KeeperHub, with
no direct signing anywhere in this codebase but two narrow, disclosed exceptions — actually
revokes the approval or evacuates the funds. Every decision and execution is appended to a
SHA-256 hash-chained audit log that verifies identically in Node and in a browser. Built for the
KeeperHub "Agents Onchain" hackathon (Jul 27 – Aug 13, 2026).

**Three real transactions on public testnets back every claim below** — not simulated, not
mocked: see [Verified onchain](#verified-onchain). Live dashboard, no setup required:
**[deplex.vercel.app](https://deplex.vercel.app)**.

## 60-second quickstart (zero credentials needed)

Two things a stranger can run immediately after cloning, with nothing configured — no RPC URL,
no API key, no wallet:

```bash
git clone <this-repo> && cd deplex
node --test test/*.test.mjs        # ~191 tests, zero network calls, ~1 second
node scripts/dashboard-server.mjs  # open http://localhost:4022
```

The dashboard needs no live watcher running: with no `deplex-state.json`/`deplex-audit.jsonl`
present (the state file is gitignored; a fresh clone won't have one), it automatically falls back
to `dashboard/demo-data/` — the **real** captured history from the three transactions below, not
synthetic fixtures — and its "CHAIN VERIFY" panel runs the real `verifyChain()` function against
all 2532 real audit records live in your browser via `crypto.subtle`. This fallback was directly
tested (file hidden, confirmed 404, confirmed the dashboard still renders full real data) before
this claim was written.

To run Deplex against a real wallet with real enforcement, see
[Environment variables](#environment-variables) — that part needs an RPC URL and a KeeperHub API
key, which a 60-second quickstart deliberately can't hand you.

## Verified onchain

### Milestone (Phase 3, hand-executed) — Sepolia, 2026-07-16

A synthetic unlimited WETH approval (standing in for a phishing-signed one — see
[FAILURE-MODES.md](docs/FAILURE-MODES.md) for why it couldn't be planted via MetaMask) was
granted to a labeled attacker address; Deplex detected it, decided REVOKE ALL (tier 2 —
`high-risk-unknown-spender` + `unlimited-approval-unknown-spender` both fired), and executed
`approve(spender, 0)` through KeeperHub autonomously. Decision to on-chain completion: ~12
seconds. Gas was KeeperHub-sponsored (`sponsored:true` in the execution result).

| What | Tx | KeeperHub execution id |
|---|---|---|
| Attack — unlimited WETH approval planted | [`0xa7b725f2…bc525e`](https://sepolia.etherscan.io/tx/0xa7b725f2139fd41ad8e1458d4037eb8ad98d37bacace0c1b119d14d232bc525e) | — |
| Defense — Deplex-executed `approve(spender, 0)` | [`0x868ad975…9065fb`](https://sepolia.etherscan.io/tx/0x868ad9758435eeb739f13ca402b3f6d6eac7415c7f9fbef7a4698b39bd9065fb) | `ky4gk1ba5et69yb9i7wq4` |

Incident id: `7328f6bc-ccda-40bd-a7a9-106fddcee9f0` — full decision + execution trail in
`deplex-audit.jsonl`.

### Scripted attack/defense race (Phase 6, `attack/run-demo.mjs`) — Sepolia, 2026-07-17

Distinct from the milestone above: this run is fully scripted end to end (`attack/drainer.mjs` +
`attack/crypto.mjs` plant the approval and attempt the drain with an independent throwaway key;
no manual steps), and the outcome is verified against on-chain ground truth rather than trusted
from the script's own report — see
[FAILURE-MODES.md](docs/FAILURE-MODES.md#a-reverted-drain-is-not-by-itself-proof-deplex-won-fixed)
for why that verification exists. Three independent signals agreed: the revoke transaction's
calldata decoded to the correct spender, the drain attempt reverted on-chain, and a direct
post-hoc `allowance()` query (not inferred from the revert) read zero.

| What | Tx | Block |
|---|---|---|
| Defense — Deplex-executed `approve(spender, 0)` | [`0x80122d57…affcb5d47`](https://sepolia.etherscan.io/tx/0x80122d57c8b7272c2a7bb53d61805772807df53dd77fc486231c3a5affcb5d47) | 11295766 |
| Attack — drain attempt, reverted | [`0xde1b2dcc…52f2636`](https://sepolia.etherscan.io/tx/0xde1b2dccb7b75f00adff78711330242eb9b2ac292bedecdca79477df152f2636) | 11295767 |

One block apart, defense first — and independently confirmed, not just observed.

### x402 intel purchase (Phase 5) — Base Sepolia, 2026-07-18

`src/intel.mjs` signed an EIP-3009 `TransferWithAuthorization` by hand (`node:crypto`, secp256k1
— this codebase's second and final direct-signing exception, see Constraints below) for 0.001
USDC, sent it via `X-PAYMENT` to `intel-agent/server.mjs`, which verified and settled it through
the real `x402.org/facilitator` on Base Sepolia. Round trip (402 → sign → paid retry → verified
response) completed in 14 seconds. Independently confirmed on BaseScan, not just trusted from the
audit log's own record — same discipline as Phase 3/6's on-chain verification.

Getting here surfaced five real bugs in one evening, each found by evidence rather than guessed
at, with intermediate theories tested and discarded along the way — full trail, organized by
category rather than chronology, in [FAILURE-MODES.md](docs/FAILURE-MODES.md).

| What | Tx | Payer |
|---|---|---|
| x402 settlement — 0.001 USDC via EIP-3009 `transferWithAuthorization` | [`0xddc75d72…3d76c1`](https://sepolia.basescan.org/tx/0xddc75d7206d654aaa800c94b64008a16d5d31deb10111e2e178e73befa3d76c1) | `0x97deecb8…67e2d7` |

Incident id: `5004c325-18da-45ad-a644-00d50c6f70fe` — spender risk score `55`
(`"contract deployed less than 7 days ago (~1.9d)"`,
`"no other wallets found approving this spender in the recent scan window"`), full purchase +
score trail in `deplex-audit.jsonl`.

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │  policies/*.policy  (controlled-English)     │
                    └───────────────────┬───────────────────────────┘
                                         │ compile() -- src/policy.mjs
                                         ▼
  RPC (read-only)        ┌──────────────────────────┐        KeeperHub MCP
  ─────────────────▶     │  src/watcher.mjs          │        (execution only)
  polls Approval/         │  detect → evaluate()      │────────────────────▶
  Transfer events          │  → escalate → execute     │      approve(0) /
                          └─────────────┬──────────────┘      transfer()
                                        │ every observation, decision,
                                        │ execution, reset
                                        ▼
                          ┌──────────────────────────┐
                          │  src/auditlog.mjs          │  SHA-256 hash-chained,
                          │  + src/auditchain.mjs      │  append-only, verifies
                          │  (zero-dep, browser-safe)  │  identically in Node
                          └─────────────┬──────────────┘  and a real browser
                                        │
                        ┌───────────────┼────────────────────┐
                        ▼                                    ▼
          ┌───────────────────────┐            ┌───────────────────────────┐
          │  dashboard/ (Phase 7)  │            │  intel-agent/ (Phase 5)    │
          │  5-panel incident room,│            │  x402 risk-score seller,   │
          │  reads the same files, │            │  paid by src/intel.mjs     │
          │  verifies the same     │            │  (hand-rolled EIP-3009 --  │
          │  chain client-side     │            │  KeeperHub can't pay a     │
          └───────────────────────┘            │  third-party x402 endpoint)│
                                                └───────────────────────────┘

  attack/ (Phase 6) -- independent throwaway-key attacker simulator, races
  the real loop above end to end; verifies its own PASSED verdict against
  on-chain ground truth rather than trusting its own report.
```

**Why this shape:** detection is read-only and needs no privileged credential at all — anyone can
run `watcher.mjs` against any address. Decisions are made by `policy.mjs`, a deterministic
compiler with no LLM anywhere in the enforcement path (an LLM, if wired in at all, may only ever
generate a human-readable summary of an already-made decision — never make one). Every
consequential action funnels through KeeperHub, which is the only component in this codebase
authorized to sign a transaction that moves value on the *watched* wallet's behalf — the two
narrow exceptions (`attack/crypto.mjs`'s independent demo attacker key, and `src/intel.mjs`'s
x402 payment signing, forced by KeeperHub's own architecture not paying third-party endpoints)
are disclosed, scoped, and never touch the watched wallet itself. The audit chain and the
dashboard that verifies it share the *exact same* verification code, not a reimplementation —
`src/auditchain.mjs` has zero Node-specific imports specifically so it can be imported verbatim
by a browser.

## Project constraints

- **Zero npm dependencies.** Node 20+ built-ins only: `node:http`, `node:https`, `node:crypto`, `node:test`, `node:fs`, `child_process`.
- **ES modules (`.mjs`).** Runs on Windows CMD and Linux.
- **Enforcement logic is 100% deterministic.** LLMs may only generate human-readable incident summaries, never decisions.
- **Every onchain action goes through KeeperHub.** No direct signing anywhere in this codebase, with two narrow, deliberate exceptions: `attack/crypto.mjs` (the demo attacker simulator, an independent throwaway key by design) and `src/intel.mjs` (x402 payment for threat-intel purchases — KeeperHub's agentic wallet only pays into KeeperHub-native endpoints and throws `UNSUPPORTED_RECIPIENT` for third-party x402 recipients, confirmed in KeeperHub's own GitHub README; see [KEEPERHUB-NOTES.md](docs/KEEPERHUB-NOTES.md) and [X402-NOTES.md](docs/X402-NOTES.md)). Both sign with `node:crypto` only, never an npm wallet library.

## What this does and does not protect against

Stated in full, with evidence, in [FAILURE-MODES.md](docs/FAILURE-MODES.md) — the short version:
Deplex protects a wallet that has a KeeperHub integration connected to it (or delegated signing
rights) against unlimited/high-risk approvals and large outbound transfers, with a tamper-evident
record of everything it decided and did. It does **not** turn an arbitrary MetaMask address with
no KeeperHub integration into something it can defend (detection still works; response doesn't),
does not guarantee winning the revocation race against a sufficiently fast real attacker, and
does not defend against a gradual, threshold-aware drain. None of this is hidden in the demo.

## Audit chain & dual-ledger verification

Every observation, decision, execution, escalation, and reset is appended to a SHA-256
hash-chained, append-only log (`deplex-audit.jsonl`). Each record is
`{ seq, ts, type, payload, prevHash, hash }` where `hash = SHA-256(seq + ts + type + JSON(payload)
+ prevHash)` and the genesis `prevHash` is 64 zeros. Altering, deleting, reordering, or inserting
any record breaks the chain from that point on; `verifyChain()` walks it and returns the exact
`brokenAt` index. This logic lives in `src/auditchain.mjs` with zero Node dependencies and runs
identically under `node:crypto` (server-side, synchronous) and WebCrypto (`crypto.subtle`, in
Node ≥20 and in a real browser) — the [dashboard](dashboard/)'s chain-verify panel imports this
file verbatim (a regression test enforces the two copies stay byte-identical) and was confirmed
running correctly in an actual browser tab: **2532 real records, valid, in ~30ms**, with a
"simulate tampering" control that mutates a scratch copy and confirms the same function catches it
(`hash mismatch`) in ~15ms.

**Dual-ledger cross-check:** every `EXECUTION_RESULT` record embeds KeeperHub's own execution id
(e.g. `ky4gk1ba5et69yb9i7wq4`) alongside the resulting `txHash`. Deplex's audit chain and
KeeperHub's independent execution ledger can be cross-verified against each other by any auditor:
Deplex's chain proves *what was decided and when* (tamper-evident), KeeperHub's ledger proves
*what was executed on-chain*, with the execution id as the join key between them. Neither party
can unilaterally rewrite the shared record of an incident — a claim Deplex can't fake without
also forging KeeperHub's ledger, and vice versa.

Verify the live log any time: `node scripts/migrate-audit.mjs` (verifies if already chained), or
open the [dashboard](dashboard/) and click RUN VERIFICATION.

## How this maps to judging criteria

| Category | Evidence |
|---|---|
| **Does it execute onchain via KeeperHub? Working transactions, not mockups.** | Two real `approve(spender, 0)` revocations, executed autonomously through KeeperHub's `execute_contract_call`, on Sepolia — both in [Verified onchain](#verified-onchain) above: the Phase 3 milestone (`0x868ad975…9065fb`, KeeperHub execution id `ky4gk1ba5et69yb9i7wq4`, `sponsored:true`) and the Phase 6 scripted attack race (`0x80122d57…affcb5d47`), the second independently confirmed against on-chain ground truth (decoded calldata, a reverted drain, a directly-queried zero allowance) rather than trusted from a script's own report. Both link to a transaction, not a screenshot. |
| **Use of KeeperHub surfaces (MCP server, CLI, x402, MPP, workflow builder, audit trail).** | **MCP server**: `src/keeperhub.mjs` is a from-scratch JSON-RPC/MCP client — `execute_contract_call`, `execute_transfer`, `get_direct_execution_status`, and a raw `tools/list` schema dump used to *discover* the real wire format after the static docs turned out wrong (see `docs/ONBOARDING-TEARDOWN.md`). `list_integrations`/`get_wallet_integration` were called live (`scripts/investigate-wallet.mjs`) specifically to uncover KeeperHub's wallet-custody model. **Audit trail**: every `EXECUTION_RESULT` embeds KeeperHub's own execution id alongside Deplex's independent hash-chained record — a genuine dual-ledger cross-check, not just a log line (see below). **x402**: investigated deeply enough to find KeeperHub's own agentic wallet does *not* support paying a third-party x402 endpoint (`UNSUPPORTED_RECIPIENT`, confirmed against KeeperHub's own GitHub README) — documented in `docs/KEEPERHUB-NOTES.md`, and Deplex's own `intel-agent/` marketplace (Phase 5) hand-rolls x402 as a direct, disclosed consequence of that finding, with a real settled Base Sepolia payment. **Not used, stated plainly rather than glossed over**: KeeperHub's CLI, MPP (Tempo USDC.e settlement — the same third-party-workflow-only limitation as x402 applies, per `KEEPERHUB-NOTES.md`, and wasn't separately re-tested), and the workflow builder (`search_workflows`/`call_workflow`) — Deplex never calls a KeeperHub-hosted workflow, since its executions are direct contract calls/transfers, not workflow invocations. |
| **Reliability and observability — failure modes, retries, gas handling, audit trail.** | This is what [`docs/FAILURE-MODES.md`](docs/FAILURE-MODES.md) is. Retries: `rpcCallWithRetry` with exponential backoff plus a circuit breaker that trips the watcher loop after repeated consecutive failures rather than spinning forever. Gas: `gas_limit_multiplier`/`priority_fee_gwei` knobs used, `sponsored:true` confirmed live, and two real wei-vs-decimal unit traps in KeeperHub's own execution API found and fixed (a live gap in the actual `EVACUATE` damage-control path, not a demo-only bug). Audit trail: SHA-256 hash-chained, append-only, `verifyChain()` running identically in Node and a real browser, cross-referenced against KeeperHub's own execution ledger by id. Beyond KeeperHub-specific reliability: ten real failure modes found and fixed across the whole project — a silent RPC/KeeperHub hang, a Windows-specific process-that-never-starts bug, a reverted-drain verdict that wasn't actually testing what it claimed to, a "cheap" scan that was secretly ~156 seconds, a settlement that left no audit trace — each with a root cause, a fix, and a regression test that fails against the old code. |
| **Originality and real-world usefulness — would anyone actually run this?** | Unlimited token approvals are the most common real-world drain vector; Deplex is an agent that *revokes* one autonomously instead of paging a human to react in time. Fail-closed by design throughout: a missing risk score, an unreachable dependency, or an ambiguous condition all resolve to the more defensive outcome, never the more permissive one. The x402 intel marketplace (an agent paying another agent, in real USDC, for a deterministic risk score before deciding how hard to react) is a genuinely novel mechanism for this space, not a bolted-on payment demo — and its own attacker simulator verifies its win condition against independently-queried on-chain state rather than trusting its own report, specifically because a security demo that can't fail isn't proving anything. |
| **Integration quality and developer experience — how cleanly is it built?** | Zero npm dependencies: keccak256, RLP encoding, secp256k1 signing, and EIP-712 typed-data hashing are all hand-rolled and cross-checked against `node:crypto`'s own verify or published test vectors, not trusted by inspection. 191 automated tests, zero flaky/skipped, run in under a second with zero external network calls. Clean separation of concerns (detection, decision, execution, audit, and the x402 marketplace are five independent modules/processes, not one tangled loop). Config fails loud, not silent — `DRY_RUN` forces itself on with an unmissable warning if enforcement credentials are missing, rather than quietly doing nothing. Runs identically on Windows and Linux, including a Windows-specific startup bug found and fixed live (see FAILURE-MODES.md). A public, judge-runnable dashboard live at **[deplex.vercel.app](https://deplex.vercel.app)** ([source](dashboard/)) that needs zero credentials to show real historical proof, and a zero-build-step static site to boot. |

## Status

- Phase 1 (policy compiler): done, tested.
- Phase 2 (detection watcher): done, verified live on Sepolia — real MetaMask approval detected, decoded, and deduped across restart.
- Phase 3 (KeeperHub execution): done, verified live on Sepolia — see Verified Onchain above.
- Phase 4 (audit chain): done, tested — SHA-256 hash chaining, tamper-detection pinpoints the exact record, browser + Node verification via shared code.
- Phase 5 (x402 intel agent): done, verified live end to end — see Verified Onchain above. Five real bugs found and fixed getting there; full trail in [FAILURE-MODES.md](docs/FAILURE-MODES.md). `src/intel.mjs` is not yet wired into `responder.mjs`'s event pipeline — `handleEvent()` calls `evaluate()` synchronously with no I/O in between, so attaching a live `event.spenderRisk` needs a caller to `await getRiskScore()` first; a follow-up, not required for this phase's scope.
- Phase 6 (attack simulator): done, verified live on Sepolia end to end — see Verified Onchain above.
- Phase 7 (incident-room dashboard): done, tested in a real browser — live at [deplex.vercel.app](https://deplex.vercel.app), source in [dashboard/](dashboard/), see also the Audit chain section above.
- Phase 8 (docs, video, submission): this pass. [FAILURE-MODES.md](docs/FAILURE-MODES.md), [ONBOARDING-TEARDOWN.md](docs/ONBOARDING-TEARDOWN.md), and [DEMO-SCRIPT.md](DEMO-SCRIPT.md) all finalized alongside this README.

## Environment variables

Required: `RPC_URL`, `WATCHED_WALLET`. To arm enforcement: `KEEPERHUB_API_KEY`, `SAFE_ADDRESS` (without both, Deplex forces DRY_RUN and says so loudly). Optional: `CHAIN_ID` (default Sepolia), `POLL_MS`, `TRACKED_TOKENS` (comma-separated), `LOG_CHUNK_SIZE` (default 8, free-tier safe), `RPC_REQUEST_SPACING_MS` (default 250), `RPC_REQUEST_TIMEOUT_MS` (default 20000 — caps a single RPC HTTP request so a hung connection fails fast instead of stalling the watcher silently, see FAILURE-MODES.md), `KEEPERHUB_REQUEST_TIMEOUT_MS` (default 20000, same protection for KeeperHub calls), `POLICY_FILE`, `STATE_FILE`, `AUDIT_LOG_FILE`, `DRY_RUN=1`, `DEPLEX_TELEGRAM_BOT_TOKEN`, `DEPLEX_TELEGRAM_CHAT_ID`, `KEEPERHUB_MCP_URL`. Attack demo only: `ATTACK_DELAY_MS` (default 25000), `ATTACK_NFT_CONTRACT` (enables the every-6th-run NFT vector, unset by default).

x402 intel agent (Phase 5): `MAX_INTEL_SPEND` (atomic units of the intel agent's priced asset, per-incident cap, default 0 — no purchases until set), `INTEL_AGENT_URL` (Deplex-side, where `src/intel.mjs` sends requests), `INTEL_AGENT_PUBLIC_KEY` (the agent's Ed25519 PEM, pinned out-of-band — supports `\n`-escaped env values) or `INTEL_AGENT_PUBLIC_KEY_FILE` (points straight at `intel-agent/.keypair.json`, avoiding manual PEM reformatting), `INTEL_PAYER_PRIVATE_KEY` (Deplex's own funded x402 payer key, EVM/secp256k1 — see the direct-signing exception above), `INTEL_AGENT_REQUEST_TIMEOUT_MS` (default 20000). Running `intel-agent/server.mjs` itself (a separate process): `INTEL_AGENT_PORT` (default 4021), `INTEL_AGENT_RPC_URL` (falls back to `RPC_URL`), `INTEL_AGENT_PAY_TO` (required — the address that receives payment), `INTEL_AGENT_PRICE_ATOMIC` (default `1000`), `INTEL_AGENT_ASSET`/`INTEL_AGENT_ASSET_NAME`/`INTEL_AGENT_ASSET_VERSION` (default Base Sepolia USDC, `"USDC"`, `"2"`), `INTEL_AGENT_NETWORK` (default `base-sepolia`), `FACILITATOR_URL` (default `https://x402.org/facilitator`, the coinbase/x402 reference SDK's own default — confirmed live and wire-compatible, see X402-NOTES.md), `FACILITATOR_TIMEOUT_MS` (default 15000 — deliberately under the client's 20000ms default, see FAILURE-MODES.md), `INTEL_AGENT_LOOKBACK_BLOCKS` (default 200 — the approval fan-out scan's recent-activity window; was 5000, see FAILURE-MODES.md for why that was a real bug, not just a slow default), `INTEL_AGENT_LOG_CHUNK_SIZE` (default 8, free-tier `eth_getLogs` range safety), `INTEL_AGENT_RPC_SPACING_MS` (default 100 — a bounded one-shot scan doesn't need the main watcher's 250ms poller-tuned spacing). `node scripts/mock-facilitator.mjs` runs a local, always-approving facilitator stub (no real settlement) for isolating the client↔agent path during diagnosis, independent of any real facilitator's availability.

Run: `node src/watcher.mjs` from the repo root. Attack demo (needs the watcher already running separately): `node attack/run-demo.mjs`. Intel agent (standalone, own process): `node intel-agent/server.mjs`. Dashboard, local dev (reads the watcher's live `deplex-state.json`/`deplex-audit.jsonl`): `node scripts/dashboard-server.mjs`, then open `http://localhost:4022` (`DASHBOARD_PORT` to change it). Dashboard, static/Vercel: deployed at **[deplex.vercel.app](https://deplex.vercel.app)** — `dashboard/` deploys as-is with `vercel.json` (`outputDirectory: dashboard`, no build command) — falls back to the baked `dashboard/demo-data/` automatically since there's no live server to read from.
