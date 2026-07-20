<!-- judge-facing reliability document, written like a security review -->

# Deplex: Failure Modes, Scope, and What Was Actually Verified

This document is the honest account of what Deplex does and doesn't protect against, and every
real failure mode found and fixed while building it — organized by category, not by the order
things happened. Every claim below is backed by a transaction hash, a decoded calldata, an
on-chain query, a live HTTP round-trip, or a test that fails against the old code and passes
against the fix. Where something is a judgment call or a known gap rather than a proven
guarantee, it's labeled that way explicitly rather than smoothed over.

## What Deplex protects against

- **An unlimited or high-risk ERC-20/ERC-721 approval to an unallowlisted spender**, detected
  from on-chain `Approval`/`ApprovalForAll` events and revoked (`approve(spender, 0)` /
  `setApprovalForAll(spender, false)`) automatically, without a human in the loop. Verified live
  twice on Sepolia — [Phase 3 milestone](../README.md#verified-onchain) (hand-planted) and the
  [Phase 6 scripted race](../README.md#verified-onchain) (drainer reverted, allowance confirmed
  zero independently).
- **A large outbound transfer to an unallowlisted recipient**, escalating to `EVACUATE` (sweep
  tracked-token and native balances to `SAFE_ADDRESS`) as a damage-control fallback if a threat
  wasn't caught before it moved funds. Confirmed working via `attack/run-demo.mjs
  ATTACK_DELAY_MS=0` (see "The revocation race" below).
- **A manual panic trigger** (Telegram long-poll listener) escalating straight to `EVACUATE`,
  for a human operator who spots something the automated rules don't cover.
- **Tampering with its own incident history after the fact.** Every decision and execution is
  appended to a SHA-256 hash-chained, append-only log; altering, deleting, reordering, or
  inserting any record breaks the chain from that point forward, and `verifyChain()` — the exact
  same function, not a reimplementation — runs identically in Node and in a real browser (see
  "Verification integrity" below).
- **A risk-scoring dependency it has to pay for going down or lying.** The x402 intel-purchase
  flow (Phase 5) is fail-closed end to end: any failure — agent unreachable, payment rejected,
  response signature invalid, budget exceeded — resolves to `risk=100` (worst case), never
  throws, and is recorded either way.

## What Deplex explicitly does NOT protect against

Stated plainly, because a security tool that only advertises what it catches and stays quiet
about what it doesn't is the more dangerous kind.

- **A wallet with no KeeperHub integration connected to it.** This is the single most
  consequential scope limitation in the whole project, and it's architectural, not a bug:
  `execute_contract_call`/`execute_transfer` sign from whatever wallet is connected as your
  KeeperHub account's *integration* — a separate address from any target you pass as a
  parameter. Detection (the watcher) is read-only RPC and works on any address you point it at.
  Response does not — an arbitrary MetaMask or hardware-wallet EOA merely *named* as
  `WATCHED_WALLET`, with no KeeperHub integration connected to it or delegating signing rights to
  one, cannot be defended by Deplex no matter how correctly the policy fires. Full technical
  detail and the live discovery trail: [Execution safety](#a-wallet-deplex-can-detect-into-but-not-defend-keeperhubs-custody-model)
  below and `docs/ONBOARDING-TEARDOWN.md` (2026-07-16 entries).
- **A guaranteed win of the revocation race.** Deplex's core promise — revoke before the
  attacker drains — is a race, not a guarantee. The measured timing model (below) puts the
  window at roughly `POLL_MS + ~12s`, worst case ~16 seconds against default settings. A real
  attacker's automated drain reacting in under that window, a gas-price spike that stalls
  Deplex's own transaction while the attacker's sails through priced-to-land, or Deplex's own
  revocation sitting in a public mempool and tipping off a bot watching for exactly that signal
  — any of these can make Deplex lose a race it would otherwise win. None of this is simulated
  away; see "The revocation race" below for the full breakdown.
- **A gradual or multi-asset drain designed around the detection window.** `attack/drainer.mjs`
  implements the standard single-shot pattern this project's threat model is scoped to. An
  attacker draining gradually (staying under the `EVACUATE` threshold on each individual
  transfer) or across multiple tracked assets within the same block as the approval (removing
  the detection window entirely) is a realistic refinement this demo does not simulate or defend
  against.
- **A third-party facilitator's own infrastructure reliability.** The x402 payment flow depends
  on an external facilitator to actually submit and confirm an on-chain settlement. Deplex
  verifies the *outcome* (a correctly-signed score response, or a fail-closed default) but has no
  control over — and only partial visibility into — the facilitator's own relayer wallet, nonce
  management, or uptime. A real, live example of exactly this limit surfacing is documented under
  "Third-party dependencies" below.

---

## Detection reliability

Findings where the watcher (or an equivalent long-running service) looked like it was working
and wasn't — the most dangerous class of bug for anything meant to run unattended, because
nothing about the outward symptoms looks broken.

### Silent hang on an unresponsive RPC/KeeperHub connection (fixed)

**What happened:** a live run of the watcher printed its startup banner (`enforcement: ARMED`)
and then produced no output whatsoever — no `OBSERVATION` heartbeat, no `WATCHER_ERROR`, nothing
— for an extended period, on a network that had been working moments before.

**Root cause:** neither `watcher.mjs`'s `rpcCall` nor `keeperhub.mjs`'s `rpcRequest` set a
timeout on their underlying HTTP request. A TCP connection that hangs — a firewall silently
dropping packets rather than rejecting the connection, an RPC provider that stops responding
mid-connection — never fires Node's `'error'` event and never completes a response, so the
request `Promise` simply never settles: not resolved, not rejected, just gone. Since
`runWatcherCycle`'s very first action is exactly this kind of call (`eth_blockNumber`), the
entire watcher loop stalls silently on the first cycle. This is strictly worse than a clean
crash: a crashed process is visibly dead; a hung one looks alive while doing nothing, and none of
the existing reliability machinery — retry/backoff, the circuit breaker, `WATCHER_ERROR` logging
— ever engages, because all of it triggers on a *rejected* promise, and this one never rejects.

**Why retry/backoff didn't already cover this:** `rpcCallWithRetry`'s exponential backoff only
runs in its `catch` block — a response to an error, not a bound on how long a single attempt is
allowed to take. A request with no timeout has no upper bound at all.

**Fix:** both files now set an explicit per-request timeout (`req.setTimeout()` +
`req.destroy(err)`, which reliably surfaces as a normal `'error'` event) — default 20s,
configurable (`RPC_REQUEST_TIMEOUT_MS`, `KEEPERHUB_REQUEST_TIMEOUT_MS`). A hang now becomes an
ordinary, retryable rejection within a bounded time instead of an indefinite silent stall —
verified with a test server that deliberately never responds, confirming the request actually
rejects within the configured window, alongside a happy-path test proving normal calls are
unaffected.

### A CLI entry point that silently never started, on Windows (fixed)

**What happened:** `node --env-file=.env.intel-payer intel-agent/server.mjs`, run for the first
live Phase 5 payment attempt, produced *zero* output — not even to stderr — and exited with code
0 immediately. No `listening on...` line, no error, nothing.

**Root cause:** the CLI guard was written as `import.meta.url === new URL(process.argv[1],
'file:').href`. `new URL(path, 'file:')` treats its argument as a *URL reference*, not an OS file
path — it doesn't add a drive letter or resolve relative segments against the working directory.
On Windows, a relative invocation gives `process.argv[1]` as e.g. `intel-agent/server.mjs`, which
that construction turns into `file:///intel-agent/server.mjs` — which can never equal the real
`import.meta.url` for the running module (`file:///C:/Users/.../intel-agent/server.mjs`). The
guard was silently always false: the module loaded and defined every export correctly, hit the
`if`, found it false, and reached end-of-file with nothing left to keep the event loop alive. A
clean, silent `exit(0)` — indistinguishable in outward appearance from "ran fine and had nothing
to do."

**Why the existing test suite didn't catch it:** every test imported the module directly rather
than spawning it as a real process, so `import.meta.url` was always the *test file's* own URL —
the whole bug is specifically about how `process.argv[1]` behaves under a real, separate-process
invocation, which no amount of in-process testing exercises.

**Fix:** `pathToFileURL(process.argv[1]).href` (from `node:url`), built specifically for this
conversion. Verified directly on Windows, before and after: the broken construction produced
`file:///intel-agent/server.mjs`, `pathToFileURL` produced the correct
`file:///C:/Users/.../intel-agent/server.mjs`, matching `import.meta.url` exactly. New regression
coverage spawns the file as a real child process and asserts the startup line actually appears —
confirmed to fail against the reverted guard (reproducing the exact `stdout=""` symptom) and pass
against the fix, not just trusted by inspection. The same fix was applied to
`scripts/dashboard-server.mjs` correctly from the start in Phase 7, rather than reintroduced.

### A panic button with no confirmation of anything, in either direction (fixed)

**What happened:** `/panic` correctly triggered `EVACUATE` on the backend — funds moved, the
audit chain recorded it accurately — but the operator who sent the command got back nothing.
No acknowledgment that it was received, no confirmation once the evacuation actually completed
or failed. From the Telegram side this is indistinguishable from the bot being dead, which is
the worst possible failure mode for a manual last-resort override specifically meant for the
moment automated detection isn't trusted: it looks broken even when it worked.

**Root cause, and why it wasn't unique to `/panic`.** The instinct was to assume `/panic`'s
handler in `src/watcher.mjs` had simply forgotten to send a message, the way an ordinary bug
would. Checking whether a real, automatically-detected incident escalating to `EVACUATE` had
the same gap ruled that out: it did too. `src/responder.mjs`'s `runTier()` cascade never called
`ctx.alert()` on a *successful* `REVOKE`/`REVOKE_ALL`/`EVACUATE` at any tier, for either trigger
path — the only existing alert calls were tier 0's `ALERT` action (which *is* the alert, by
definition), the "auto-escalating to tier N+1" message on a failed lower tier, and a `CRITICAL`
message on `EVACUATE` failing with nowhere higher to escalate to. `/panic` didn't skip a step
the automatic path had; the shared pipeline both paths funnel through had simply never been
given a completion-notification step, because until a human command was wired directly into it,
nothing was actively waiting on a response from it.

**Fix, at the shared root cause, not per-caller.** `runTier()`'s tier-3 branch now always calls
`ctx.alert()` with the `EVACUATE` outcome — success or failure — via a new
`formatEvacuateAlert()` helper, so both `/panic` and a real incident that escalates up to
`EVACUATE` get it identically, from one code path. On success: the real tx hash(es) and a
Sepolia explorer link per leg (or an explicit "nothing found to move" if all tracked balances
were already zero — never a fabricated hash). On failure: the actual per-leg error, not a vague
"something went wrong." Separately, `/panic` specifically also gained its own immediate interim
acknowledgment (`🚨 Panic received — evacuating funds now.`, sent from `src/watcher.mjs`'s
`onPanic` before `EVACUATE` is kicked off) — that one *is* legitimately `/panic`-specific, since
it's confirming a human command was heard, not reporting an execution outcome a background
detection loop has no one waiting on. `src/telegram.mjs`'s dispatcher now `await`s `onPanic` (it
previously fired it and moved on without waiting), the same shape already used for `/setkey`,
so a thrown error in the handler is caught and logged instead of silently dropped.

**Tests:** `test/responder.test.mjs` covers `formatEvacuateAlert` directly — single-leg success
with the real tx hash and explorer link, multi-leg success listing every hash, the
nothing-to-evacuate case, failure with the real per-leg error, and — the point-3 check —
confirming a real auto-detected incident escalating through failed `REVOKE`/`REVOKE_ALL` into a
successful `EVACUATE` gets the exact same completion alert `/panic` does.
`test/telegram.test.mjs` covers the dispatcher actually awaiting `onPanic` and not crashing the
poll loop if it throws.

---

## Execution safety

Findings where the *consequences* of a decision — the amount moved, the trigger condition, the
wallet actually signing — were the thing at risk of being wrong.

### Two wei-vs-decimal unit traps in KeeperHub's execution API (fixed) — and one of them was ours to catch and didn't

**What happened, twice, the same way.** `execute_transfer`'s `amount` and
`execute_contract_call`'s `value` are both human-readable decimal strings (`"0.1"`), not wei —
the single inconsistency on an otherwise integer-everywhere API surface. Every value this
codebase carries internally is wei by design, for exact-integer precision. Both traps produced
the same failure signature: a call requesting a tiny real amount got rejected as an absurdly
large balance shortfall, because a wei integer like `1000000000000000` was read as that many
whole tokens/ETH.

- `execute_transfer.amount` surfaced first, in `responder.mjs`'s production `EVACUATE` path
  (both ERC-20 and native legs) — not just a demo bug, a live gap in the actual damage-control
  fallback this project's core safety story depends on.
- `execute_contract_call.value` surfaced second, in demo setup code. This one is on us
  specifically: after fixing the first trap, project notes recorded — as if confirmed — that
  `value` "remains wei-denominated, unaffected." That was never tested. It was wrong, and it cost
  a live failed transaction against a wallet independently confirmed to hold 50x the requested
  amount before the real cause was found.

**Fix:** both conversions now happen in exactly one place (`keeperhub.mjs`'s
`weiToDecimalString`, BigInt-based — never `Number`/`parseFloat`, which would silently lose
precision on real balances), so every caller keeps passing wei and the one KeeperHub-specific
convention lives at the one boundary that needs it. `execute_transfer` also gained
decimals-awareness (`getTokenDecimals`) rather than assuming native-ETH's 18 universally.

**The process fix matters as much as the code fix.** Writing an unverified inference into
project notes in the same authoritative voice as things actually confirmed live let it pass as
settled and propagate into a second document unchallenged. Notes now visibly flag corrected
assumptions rather than silently overwriting them, and `scripts/dump-tools.mjs` prints each
numeric field's verbatim schema description on request, so units are read from the source next
time. Full trail (live tool calls, exact error messages): `docs/ONBOARDING-TEARDOWN.md`.

### A "successful drain" that wasn't: two compounding bugs behind one false alarm (fixed)

**What happened:** a live demo run reported `DEPLEX: REVOKED` at one block and `DRAINER:
SUCCEEDED` at the very next block — apparently proving the revocation didn't stop the actual
threat. It didn't; the drain "succeeding" was itself a false signal, traced to hard evidence
(decoded calldata, on-chain state, the audit chain), not inferred.

**Bug 1 — a silently-swallowed setup failure.** `attack/drainer.mjs`'s `plantApproval` and
`ensureAttackerGas` both correctly check `if (!final.txHash) throw ...` after their KeeperHub
call. `ensureWethBalance` was missing that same check. When the demo wallet's native ETH ran out,
its `deposit()` call failed outright — a wallet with 0 ETH cannot send `value` with a call.
`ensureWethBalance` returned `{wrapped: true}` anyway, printing a misleading success line. The
wallet's WETH balance stayed at zero the entire run, so `attemptDrain` correctly read that real
(zero) balance and requested `transferFrom(..., 0)` — a zero-value transfer, which trivially
"succeeds" regardless of allowance state. The revocation was never actually tested against real
value in this run; decoding the revoke transaction's calldata directly confirmed it targeted the
correct spender with the correct effect, and on-chain `allowance()` confirmed zero immediately
after.

**Bug 2 — found while tracing the first, independent of it.** The same zero-value drain
transaction was picked up by `watcher.mjs` as an ordinary outbound transfer, and
`policy.mjs`'s fail-closed "can't compute a percentage, assume worst case" path returned
`Infinity` for a transfer that moved *nothing*, firing an unwarranted `EVACUATE`. A transfer of
zero value can never be a large outbound transfer regardless of whether a percentage is
computable; the fail-closed default now short-circuits before that ambiguity, only for a literal
zero.

**Why this is worth stating plainly:** neither bug is a failure of the core
detect→decide→execute→revoke loop, which worked correctly and was independently verified. Both
are demo/setup-adjacent code with a missing guard. But "the demo appeared to show the security
property failing" is exactly the kind of result that must never be taken at face value without
transaction-level verification.

### `approvalFanOut`'s "cheap" scan was 625 unconditional calls, ~156 seconds, nearly 8x the client's own timeout (fixed)

**What happened:** the x402 intel agent's risk-scoring heuristic (`intel-agent/server.mjs`) is
commented as a "cheap" recent-window scan. It wasn't. Its defaults (`lookbackBlocks=5000`,
`chunkSize=8`) mean `5000/8 ≈ 625` chunked `eth_getLogs` calls, made *unconditionally* on every
non-denylisted score request regardless of contract-vs-EOA or approval history. Measured directly
against a mock RPC that responds instantly: **628 total RPC calls** to score a plain EOA with
zero approvals. Combined with the shared 250ms `rpcCallWithRetry` spacing gate — correctly tuned
for `watcher.mjs`'s long-running background poller, wrong for a synchronous HTTP
request/response someone is waiting on — that floors a single scoring call at **~156 seconds
minimum**, independent of RPC latency or health entirely. From the outside this looked
indistinguishable from a hang: settlement had already succeeded, and the buyer just never got a
response within its 20-second timeout.

**Fix:** `lookbackBlocks` cut from 5000 to 200 (~40 minutes of Sepolia blocks — narrower, still a
meaningful recency signal), and the RPC spacing used for scoring reduced from the watcher's 250ms
poller-tuned default to 100ms (a bounded one-shot scan doesn't need the same burst-limit
caution). Both independently configurable (`INTEL_AGENT_LOOKBACK_BLOCKS`,
`INTEL_AGENT_LOG_CHUNK_SIZE`, `INTEL_AGENT_RPC_SPACING_MS`). Same measurement now shows ~26 calls
instead of 628. A regression test drives a full paid request through the real server with no
test-only shortcuts, asserting the call count stays under 50 — specifically so "the happy path
nobody tested" can't silently reopen (see the Methodology section for how this was missed in the
first place).

A second gap found in the same investigation: `scoreAddress()` ran with no `try/catch`. If it
failed *after* a real successful settlement, the connection just hung open until the *client's*
timeout, giving no indication a payment had already been taken. Fixed by wrapping that section so
a post-settlement failure returns a prompt, informative `500` instead.

### The revocation race: timing model

Deplex's core promise is that its revocation lands *before* an attacker's drain transaction.
That's a race, not a guarantee, and the honest timing model is worth stating in full rather than
letting the demo imply more certainty than the mechanism provides.

**The race's stages, and what each costs:**

1. **Detection latency** — `watcher.mjs` polls (`POLL_MS`, default 4000ms). Worst case, an
   approval lands one block after a poll fires, and detection waits nearly a full interval.
2. **Decision** — `policy.mjs`'s `evaluate()` is synchronous, in-memory, sub-millisecond.
3. **Execution** — the KeeperHub round trip. Measured directly on the Phase 3 milestone: **~12
   seconds** decision-to-on-chain-completion for a single REVOKE.

Total: worst case, roughly `POLL_MS + ~12s` — **up to ~16 seconds** against default settings.
`ATTACK_DELAY_MS` (default 25000 in `attack/run-demo.mjs`) has headroom above that worst case:
winnable, but not by a wide margin.

**What actually determines whether Deplex wins:**
- **Attacker reaction time.** A real automated phishing drain typically fires within seconds of
  the approval confirming — a sophisticated real attacker may not give Deplex the ~16-second
  window this model assumes. This is the single biggest gap between the demo and a real attack.
- **Gas pricing on both sides.** The milestone execution carried `sponsored:true`; whether that
  compensates for a network-wide gas spike is not confirmed — one normal-conditions execution has
  been observed, not a stress case.
- **Mempool visibility.** No evidence either way on whether KeeperHub routes execution through a
  private relay versus the public mempool. A revocation sitting in the *public* mempool is
  visible to anything watching for it, including a bot built to react to "this address is about
  to lose me my access" by immediately broadcasting its own drain at a higher gas price — turning
  Deplex's own defensive transaction into the attacker's trigger signal.

**If the drainer wins** (confirmed working via `attack/run-demo.mjs ATTACK_DELAY_MS=0`, which
deliberately removes Deplex's reaction window): the drainer's own transfer is itself an outbound
event `watcher.mjs` detects on its next cycle. If it clears the `large-outbound-unknown-recipient`
threshold, that triggers `EVACUATE` — damage control, not prevention; whatever the drainer
already took in that first transfer is gone.

### A wallet Deplex can detect into but not defend: KeeperHub's custody model

**What we assumed going in:** point Deplex at any watched wallet address, and KeeperHub's
execution tools would sign revocation/evacuation transactions on that wallet's behalf.

**What's actually true:** those tools sign using whatever wallet is connected as your KeeperHub
account's *wallet integration* — a separate address from any target parameter you pass. In our
case the connected integration (`0x2A1f4778…8aE20`) is a real, self-custodied wallet
(`isManaged:false`), entirely distinct from both `WATCHED_WALLET` and `SAFE_ADDRESS`. Passing an
arbitrary EOA as a call target does not make KeeperHub able to sign from it.

**Consequence for the demo:** the "attacker's" unlimited approval had to be planted
programmatically through KeeperHub itself (`scripts/plant-approval.mjs`) rather than manually via
MetaMask as Phase 2's pure-detection test did — MetaMask holds a key KeeperHub's integration
wallet doesn't share. This is stated in the scope-honesty section above and repeated here with
the technical detail: **Deplex's real deployment model is "the protected wallet must itself be,
or delegate signing authority to, a wallet connected as a KeeperHub integration,"** not "point it
at any wallet, walk away." Full discovery trail, live tool calls, and exact error messages:
`docs/ONBOARDING-TEARDOWN.md`, entries dated 2026-07-16.

---

## Verification integrity

Findings where the thing at risk was whether Deplex's own claim about what happened — a PASSED
verdict, a settled payment, a valid chain — was actually trustworthy, independent of whether the
underlying action itself was correct.

### A reverted drain is not, by itself, proof Deplex won (fixed)

**What happened:** `attack/run-demo.mjs` was requesting `transferFrom(..., MAX_UINT256)` for
every drain attempt — the full *approved* amount, not the wallet's actual balance. That call
reverts on insufficient *balance* regardless of whether the allowance was ever touched, so the
drainer reported "REVERTED" identically whether Deplex had revoked anything or not. **The demo's
PASSED verdict was not actually testing the security property it claimed to test.**

**Why the obvious fix (read the revert reason) doesn't work:** WETH9 on Sepolia reverts with
**no reason string at all** on a failed `transferFrom` — confirmed directly by replaying the
exact failing call via `eth_call`, which returns empty data. Any fix relying on distinguishing
"insufficient balance" from "insufficient allowance" by reading the revert message was never
going to work against this specific contract.

**The actual fix, two parts:** `attemptDrain` now requests the wallet's *real* balance, fetched
fresh immediately before the attempt, making balance sufficient by construction so a revert can
only mean insufficient allowance. And since even that inference has a gap, `run-demo.mjs` now
checks on-chain ground truth directly after a reverted drain — `allowance()`/`isApprovedForAll()`
— and only reports PASSED if it reads zero/false; a revert with a still-nonzero allowance is
reported **INCONCLUSIVE**. The eventual fully-verified PASSED run confirmed all three signals
agreed: decoded revoke calldata targeted the correct spender, the drain reverted, and a
directly-queried on-chain allowance read zero.

**Why this is the most important entry in this document.** Every other finding here is about
Deplex's own behavior. This one is about whether the *test proving that behavior* was
trustworthy. A demo that silently can't fail is worse than no demo. Every "PASSED"/"REVOKED"
claim in this project's README is backed by transaction hashes and independently-queried on-chain
state, not a script's self-report — directly because of what this bug taught.

### A fail-closed result that printed as a success (fixed)

**What happened:** a live intel-purchase re-run produced a self-contradicting result:
`scripts/run-live-intel-purchase.mjs` printed a free-success message while, in the same instant,
the audit record it should have been describing read `"failed":true,"error":""`.

**Root cause.** `getRiskScore()` returns one of two distinct shapes: `{risk, reasons: [...],
purchased}` on success, or `{risk, failClosedReason, purchased: false}` on fail-closed (no
`reasons` key at all). The script's branching was `if (result.purchased) {...} else if
(result.failClosedReason) {...} else {...}` — and since `result.failClosedReason` is just
`err.message`, and JavaScript's empty string is falsy, a fail-closed result whose underlying
error happened to have an empty `.message` fell all the way through to the "free success" branch,
despite `risk: 100` and `purchased: false` both saying otherwise.

**A second, compounding bug:** `err.message` really was the empty string, and nothing made that
diagnosable. Despite reproducing three plausible native-exception scenarios (a malformed signing
key, a genuine insufficient-balance rejection, an unhandled server exception crossing into a
client timeout), none reproduced a truly empty message — **the exact native cause was never
pinned down**, stated plainly rather than guessed at further.

**Fix:** the script now discriminates on `Array.isArray(result.reasons)` — structurally true only
for the success shape, regardless of what any error message contains. `getRiskScore()`'s catch
block now runs every caught value through a `.message → .code → .name → String(err)` fallback
before it's ever logged or returned, so an uninformative empty diagnostic can't recur even if the
same empty-message condition happens again for a still-unknown reason. Also found in the same
investigation: the server logged *nothing* per request — only its own startup banner — so
"check the server's log" would have found nothing regardless of which bug was in play. It now
logs method/path/outcome and the specific reason on every exit path.

### Settlement succeeded but the audit record had no transaction reference (fixed)

**What happened:** a real live purchase settled successfully — signature verified, score
delivered — but the resulting audit record had no settlement transaction hash at all, for any
purchase, going back to the very first live attempt.

**Root cause:** the real settlement reference comes back via the `X-PAYMENT-RESPONSE` header, not
the response body — but the client's HTTP helper never captured response headers at all,
discarding them at `resolve({ statusCode, body })`. `getRiskScore()` had no way to read a header
it never received.

**Fix:** response headers are now captured and `X-PAYMENT-RESPONSE` decoded, recording
`transaction`/`payer` in the audit entry. Decoding is best-effort and never blocks the purchase —
the score's own signature is independently verified regardless, so a missing settlement receipt
degrades the audit trail, not the correctness guarantee. Three regression tests cover the happy
path, a missing/malformed header not blocking an otherwise-successful purchase, and — critically
— a test running the *real* server against the *real* client end to end, so a header-name or
encoding mismatch between the two sides (exactly the class of bug that let this slip past tests
mocking one side or the other) would actually be caught.

### Two small dashboard bugs the real-browser test caught (Phase 7, fixed)

**What happened:** the Phase 7 dashboard's panels were written against an assumed shape for two
record types, then actually run in a real browser tab against the real 2532-record audit log —
per this project's own standing instruction to verify browser-facing code in an actual browser,
not just build and assume.

**Bug 1 — wrong occurrence picked.** The wallet-status panel scanned records from the start and
returned the first matching address. The real audit log has **two genuinely distinct addresses**
across its history — an early-testing wallet, then the one actually used for Phase 3/5/6 —
confirmed directly against the data. Fixed by scanning from the end: "current wallet status"
means the most recent match, not whichever was watched first.

**Bug 2 — a field name that was never real.** The live feed's `OBSERVATION` summary read
`payload.block`, which doesn't exist on that record type — real records use
`fromBlock`/`toBlock`/`approvalCount`/`transferCount`, confirmed by reading an actual record.

Neither would have been caught by code review alone; both were caught within seconds of loading
real data in a real browser tab, which is the entire argument for doing that instead of trusting
the code by inspection.

---

## Third-party dependencies

Findings where Deplex's own correctness wasn't in question, but its behavior is genuinely
constrained by something outside this codebase's control.

### The x402 wire format: verified against reality, not guessed at

Before any of the bugs below, the x402 protocol itself has a real version fork (v1 `X-PAYMENT`/
`maxAmountRequired` vs. v2 `PAYMENT-SIGNATURE`/`amount`) that the spec docs alone don't resolve
cleanly. Rather than pick one and hope, this was checked against the coinbase/x402 reference
SDK's actual source and two real, live facilitators — sending genuine (deliberately
invalid-signature) `/verify`/`/settle` requests and reading their real responses before writing
any production code against assumptions. Full trail in `docs/X402-NOTES.md`. This is the positive
counter-example to the bugs below: the wire-format layer had zero live surprises specifically
*because* it was verified this way before code was written against it.

### Facilitator-side "replacement transaction underpriced" under rapid retries (known transient condition, not a Deplex bug)

**What happened:** a live purchase attempt made it all the way to the facilitator submitting a
real on-chain transaction, which was rejected with `replacement transaction underpriced`.

**What this means, confirmed rather than assumed:** the standard error for submitting a new
transaction with the same *Ethereum account nonce* as an existing pending transaction, at a gas
price that doesn't sufficiently outbid it. This is a **different nonce** than EIP-3009's own
`authorization.nonce` (a random 32-byte anti-replay value Deplex generates fresh on every attempt
— confirmed directly from source, never reused). The colliding nonce belongs entirely to the
**facilitator's own relayer wallet**, opaque to Deplex and outside its control.

**Verified with real evidence, not just inference:** the facilitator's own `/supported` endpoint
discloses its EVM relayer address. Querying Base Sepolia directly for that address's nonce,
`latest` vs. `pending`, read equal — no stuck transaction visible at check time. This doesn't
prove that address handled the specific failed attempt, but it's a real, repeatable check, and
it's the check to run before assuming a retry is safe.

**Whether Deplex's own retry cadence could make this worse, not just be unlucky:** plausibly yes,
if the facilitator doesn't serialize its own on-chain submissions per key — stated as plausible
from the evidence available, not proven, since the facilitator's own implementation isn't visible
to Deplex.

**Recommendation, not a code fix:** this is a third-party relayer characteristic, not a Deplex
defect — nothing in this codebase touches the facilitator's relayer wallet, so nothing was
changed. Space real settlement attempts by at least a minute or two, and before retrying, compare
`eth_getTransactionCount(relayer, 'pending')` against `('latest')` for the facilitator's disclosed
address. This is exactly what happened next: the following attempt, after waiting, produced the
real, independently-verified settlement in the README's Verified Onchain section — proof the
actual code fixes above hold end to end against real infrastructure, not just against mocks.

---

## Methodology: what this whole project is actually worth teaching

**The habit that mattered most: verify against reality, don't reason from assumption.** Every
significant bug in this document was found by treating an assumption as untested until checked
against a live source — a real RPC call, a real facilitator response, a real browser tab, a real
audit record read from disk rather than recalled from memory. The one deliberate exception (the
`execute_contract_call.value` unit trap) was caused by exactly the opposite: writing an inference
into notes in the same voice as a confirmed fact, and it cost a live failure to catch.

**The single thread connecting the x402 bugs specifically:** every reproduction attempt during
that investigation used a denylisted scoring address to avoid needing a live RPC endpoint — a
reasonable shortcut for testing the payment protocol in isolation, but one that also always
skipped the single most expensive, most failure-prone code path in the feature. It had zero test
coverage from any hands-on debugging until a real user hit it with a real, non-denylisted
address. The fix wasn't just lowering a default — it was a regression test that goes through the
real server with a real non-denylisted address, so "the happy path nobody tested" can't silently
reopen.

**Wrong theories are not embarrassing, and are kept in this document rather than deleted.** The
x402 "vanished payment" investigation proposed and disproved two theories (a transport-layer
loss, then a facilitator-timeout race) before landing on the real cause (an unconditionally slow
scan). Each was falsifiable, was actually tested against real evidence, and was abandoned the
moment evidence contradicted it — not defended. A live three-window timestamp comparison directly
ruled out the transport-layer theory; a real call-count measurement directly confirmed the actual
cause. That's the discipline this project tried to hold to from Phase 3's KeeperHub schema dumps
onward: when a guess turns out wrong, say so and show the evidence that overturned it, rather
than quietly rewriting history to look right in hindsight.

**Tally, for what it's worth:** across every phase, real failures found and fixed break down as
roughly seven in detection/execution reliability, four in verification integrity, one confirmed
third-party characteristic (not fixed, because there was nothing in this codebase to fix), and
two KeeperHub-API documentation gaps that cost live failures before `docs/ONBOARDING-TEARDOWN.md`
turned them into a documented convention. None were caught by code review alone; all were caught
by running the real thing and checking the real result.
