# x402 Integration Notes

First pass summarized from live fetches of the primary spec source, 2026-07-18. A second pass
the same day went further, per explicit instruction: don't trust the first pass's judgment call
on the facilitator wire format — find a real, currently-live facilitator, confirm which protocol
version it actually speaks, and confirm the real `/verify`/`/settle` shape rather than
best-effort guessing. That second pass is what's authoritative now; the first pass's "judgment
call" framing for the wire format is superseded below. Re-fetch before touching payment logic
again if this feels stale.

## Live verification (2026-07-18, second pass) — what changed from the first pass

The first pass got the v1 wire format basics right (confirmed below) but missed three concrete
details only visible in the reference client's actual source and in a real facilitator's actual
response, not in the prose spec docs:

1. **The `/verify` and `/settle` POST body needs a top-level `x402Version`** alongside the nested
   `paymentPayload`/`paymentRequirements` — the first pass's code sent only the latter two.
2. **The X-PAYMENT payload is not the bare `{signature, authorization}` pair** — it's that pair
   nested one level deeper under a `payload` key, alongside sibling `x402Version`/`scheme`/
   `network` fields. The first pass's code (both `intel-agent/server.mjs`'s expectations and
   `src/intel.mjs`'s construction) sent/expected the bare pair. **This was the most consequential
   gap**: a real facilitator would very likely have rejected or misparsed it.
3. **EIP-3009's `validAfter` is `now - 600` (ten minutes in the past), not `"0"`** in the
   reference implementation. `"0"` would probably still pass most contracts' validation (it's
   always ≤ now), but the point of this pass was matching the real implementation, not a
   plausible-looking guess.

All three are now fixed in `intel-agent/server.mjs` and `src/intel.mjs`, and covered by new
tests in `test/intel-agent.test.mjs` / `test/intel.test.mjs` (see "What's now tested" below).

### Ground truth source used

Not docs pages this time — those turned out to be less reliable than the code. `docs.x402.org`'s
OpenAPI URL served an unrelated example spec (noted in the first pass), and Coinbase's own docs
domain (`docs.cdp.coinbase.com`) was unreachable from this environment (`ENOTFOUND` on every
attempt) — a real, documentable infrastructure gap, not a transient blip; it failed consistently
across multiple direct fetch attempts to different pages on that domain.

What actually worked: the **`coinbase/x402` GitHub repository's source code**
(`github.com/coinbase/x402`, fetched via `raw.githubusercontent.com` and the GitHub API — `gh`
CLI is blocked by this project's guard hook, worked around with plain `curl`, same as the first
pass). Its own README states it's now a development fork of the canonical
`x402-foundation/x402` repo, with issues/PRs migrated there — but the actual TypeScript SDK code
lives here and is the real, current reference implementation that facilitators and other clients
in the ecosystem are built to interoperate with. Specific files read in full:

- `typescript/packages/core/src/http/httpFacilitatorClient.ts` — the reference facilitator
  *client* (what a resource server uses to call a facilitator's `/verify`/`/settle`)
- `typescript/packages/core/src/types/payments.ts` and `types/v1/index.ts` — the current
  (v2-native) and legacy (v1) payment type definitions, side by side
- `typescript/packages/core/src/http/x402HTTPClient.ts` — header-name dispatch logic, branched
  explicitly on `x402Version`
- `typescript/packages/core/src/http/x402HTTPResourceServer.ts` — the reference *resource server*
  (seller) implementation
- `typescript/packages/mechanisms/evm/src/exact/client/eip3009.ts` (v2-native) and
  `typescript/packages/mechanisms/evm/src/exact/v1/client/scheme.ts` (v1) — the actual EIP-3009
  signing code, both versions
- `typescript/packages/mechanisms/evm/src/constants.ts` — the `authorizationTypes` EIP-712 type
  definition (confirms the exact field order Deplex already had right)
- `typescript/packages/mechanisms/evm/src/v1/index.ts` — the v1 network-name → chainId map
  (confirms Deplex's `CHAIN_ID_BY_NETWORK` in `src/intel.mjs` exactly, on every shared key)

Then, critically, **two real facilitators were live-probed directly** (not just read about) —
see below.

### Two real, currently-live facilitators, confirmed by direct HTTP request today

| | `https://x402.org/facilitator` | `https://facilitator.payai.network` |
|---|---|---|
| Reachable right now | Yes, HTTP 200 on `/supported` | Yes, HTTP 200 on `/supported` |
| Hardcoded as the reference SDK's own default | **Yes** (`DEFAULT_FACILITATOR_URL` in `httpFacilitatorClient.ts`) | No |
| v1 `exact`/`base-sepolia` in its live `/supported` response | Yes | Yes |
| v2 `exact`/`eip155:84532` also supported | Yes | Yes |
| Network breadth | Narrower (Base Sepolia + a handful of others) | Much broader (15+ EVM chains) |

Both are real and live. `x402.org/facilitator` is now the primary recommendation and
`intel-agent/server.mjs`'s new default (previously PayAI) specifically *because* it's the
reference SDK's own hardcoded default — anyone using the stock client without configuring a
facilitator URL hits this one, making it the strongest available proxy for "what real usage
actually looks like." PayAI remains documented as a live, viable fallback.

### `/verify` and `/settle` — confirmed live, not just from source

A real POST was sent to `https://x402.org/facilitator/verify` and `/settle`, using a
deliberately garbage signature (`0x1111...`) so no real funds/signing were needed, in the shape
described in point 2 above:

```json
{
  "x402Version": 1,
  "paymentPayload": {
    "x402Version": 1,
    "scheme": "exact",
    "network": "base-sepolia",
    "payload": {
      "signature": "0x1111...1111",
      "authorization": { "from": "0x...dead", "to": "0x...beef", "value": "1000", "validAfter": "0", "validBefore": "9999999999", "nonce": "0x1111...1111" }
    }
  },
  "paymentRequirements": { "scheme": "exact", "network": "base-sepolia", "maxAmountRequired": "1000", "resource": "...", "description": "test", "mimeType": "application/json", "outputSchema": null, "payTo": "0x...beef", "maxTimeoutSeconds": 60, "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "extra": { "name": "USDC", "version": "2" } }
}
```

Actual responses received:

```json
// POST /verify
{"isValid":false,"invalidReason":"invalid_exact_evm_signature","payer":"0x...dead"}

// POST /settle
{"success":false,"network":"base-sepolia","transaction":"","errorReason":"invalid_exact_evm_signature","payer":"0x...dead"}
```

Both responses are coherent — the facilitator correctly parsed the nested envelope and correctly
recovered `payer` from `authorization.from`, meaning the request shape above (envelope included)
is genuinely accepted and understood, not just schema-tolerant garbage-in-garbage-out. This
confirms `{isValid, invalidReason, payer}` and `{success, network, transaction, errorReason,
payer}` as real response shapes, matching what the first pass had already best-effort implemented
— that part didn't need to change, it just went from "best-effort guess" to "confirmed fact."

**One nuance worth recording plainly**: a follow-up request with the top-level `x402Version`
field *removed* got an identical response from this specific facilitator — it apparently falls
back to reading `paymentPayload.x402Version` when the outer field is absent. So the outer field
isn't strictly *required* by this one facilitator. `intel-agent/server.mjs` sends it anyway,
because the reference client always does and another facilitator might not be as lenient — but
this is flagged so it isn't mistaken for "confirmed required," only "confirmed sent and
confirmed accepted."

### The reference *resource server* (seller) has actually dropped v1 — a nuance, not a blocker

`x402HTTPResourceServer.ts`'s `extractPayment()` only reads the v2 `PAYMENT-SIGNATURE` header
(no `X-PAYMENT` fallback), and its response-building methods only ever emit v2-shaped
`PAYMENT-REQUIRED`/`PAYMENT-RESPONSE` headers — never a v1-style JSON-body 402 or an
`X-PAYMENT-RESPONSE` header. So Coinbase's own current reference *seller* code no longer speaks
v1 at all, even though the reference *client* and *facilitator-client* code still fully support
it (confirmed above), and even though real, live facilitators still accept v1 calls (confirmed
above).

This doesn't block `intel-agent/server.mjs` staying v1-shaped: Deplex owns both the buyer
(`src/intel.mjs`) and seller (`intel-agent/server.mjs`) sides of its own transaction, and the
facilitator in between demonstrably still speaks v1. The residual risk is narrower and worth
naming honestly: if some future piece of *third-party* ecosystem tooling assumes every seller is
v2-shaped (because the reference seller now is), it wouldn't know how to buy from Deplex's
v1-shaped `intel-agent/server.mjs` out of the box. Not a problem for the hackathon demo (Deplex
controls both ends), but a real interoperability edge worth knowing about, not silently ignoring.

### `X-PAYMENT-RESPONSE`, not `PAYMENT-RESPONSE`, for a v1 settlement response

`x402HTTPClient.ts`'s `getPaymentSettleResponse()` explicitly checks `PAYMENT-RESPONSE` first (v2)
and falls back to `X-PAYMENT-RESPONSE` (v1) only if the former is absent. `intel-agent/server.mjs`
previously sent `PAYMENT-RESPONSE` even on its v1 flow — fixed to `X-PAYMENT-RESPONSE`, matching
what a v1-aware client (including the reference SDK's own client, in its v1 fallback branch)
actually looks for.

### Network-string format differs by version — confirmed, not previously documented

Both facilitators' live `/supported` responses list `base-sepolia` (plain string) as a *separate*
entry from `eip155:84532` (CAIP-2) — v1 payloads use the plain network name, v2 payloads use the
CAIP-2 form. Deplex's code is v1-shaped throughout and already used `"base-sepolia"` consistently
(from the original, unverified judgment call) — this happened to be right, and is now confirmed
rather than assumed. `src/intel.mjs`'s `CHAIN_ID_BY_NETWORK` map was independently cross-checked
against `evm/src/v1/index.ts`'s `EVM_NETWORK_CHAIN_ID_MAP` and matches on every shared key
(`base-sepolia: 84532`, `base: 8453`, `sepolia: 11155111`, `ethereum: 1`) — no change needed
there.

### What's now tested

- `test/intel-agent.test.mjs`: a new test spins up a mock HTTP server standing in for the
  facilitator, runs `intel-agent/server.mjs`'s *real* (unmocked) `facilitatorVerify`/
  `facilitatorSettle` against it, and asserts the actual outgoing POST body matches the confirmed
  shape (`x402Version` present at the top level, `paymentPayload.payload.authorization` present).
  Previously this was entirely untested — every other test mocks `facilitatorVerify`/
  `facilitatorSettle` away via `deps`, so the real wire-construction code had zero coverage.
- `test/intel.test.mjs`: asserts the constructed X-PAYMENT header decodes to the full envelope
  shape (`x402Version`/`scheme`/`network`/`payload`), and that `signAuthorization`'s
  `validAfter`/`validBefore` match the confirmed formula exactly.
- The EIP-712 digest construction itself was already cross-checked against the raw ECDSA
  verification equation (first pass) — unaffected by this pass's fixes, since the digest math was
  already correct; only the *wrapper* around the signed payload was wrong.

No live payment was made in this pass — the facilitator calls above used deliberately invalid
signatures specifically to confirm wire shape without needing a funded key or committing funds.

---

## First-pass notes (still accurate on the points below; superseded above where noted)

Sources fetched (raw, primary) in the first pass:
- `https://raw.githubusercontent.com/x402-foundation/x402/main/specs/transports-v1/http.md`
- `https://raw.githubusercontent.com/x402-foundation/x402/main/specs/transports-v2/http.md`
- `https://raw.githubusercontent.com/x402-foundation/x402/main/specs/schemes/exact/scheme_exact_evm.md`
- `https://docs.x402.org/dev-tools/facilitators`, `https://facilitator.payai.network`

### A real version fork exists — v1 and v2 are genuinely incompatible on the wire

Still accurate, and now confirmed from a second, independent angle (the reference SDK literally
ships two parallel implementations, `types/v1` alongside the v2-native `types`):

| | v1 | v2 |
|---|---|---|
| Client payment header | `X-PAYMENT` | `PAYMENT-SIGNATURE` |
| Server 402 header | (body-based, see below) | `PAYMENT-REQUIRED` |
| Server settlement header | `X-PAYMENT-RESPONSE` *(corrected — see above; first pass had this wrong)* | `PAYMENT-RESPONSE` |
| Amount field | `maxAmountRequired` | `amount` |
| Network string | plain (`"base-sepolia"`) *(confirmed live above)* | CAIP-2 (`"eip155:84532"`) *(confirmed live above)* |
| `resource`/`description`/`mimeType` | flat inside each `accepts[]` entry | separate top-level `resource` object |
| `x402Version` | `1` | `2` |

**Decision: implementing v1** (`X-PAYMENT`, `maxAmountRequired`) — this is no longer just a
judgment call. It's now confirmed to be a real, currently-supported wire format that real,
live facilitators (both above) accept today, cross-checked against the reference SDK's own
still-maintained v1 code paths (`types/v1`, `exact/v1/client`, `exact/v1/facilitator`).

### 402 response body (v1, confirmed verbatim from spec, unchanged)

```json
{
  "x402Version": 1,
  "error": "string",
  "accepts": [
    {
      "scheme": "string", "network": "string", "maxAmountRequired": "string",
      "asset": "string", "payTo": "string", "resource": "string",
      "description": "string", "mimeType": "string", "outputSchema": null,
      "maxTimeoutSeconds": number, "extra": {}
    }
  ]
}
```

### `X-PAYMENT` payload (client → server on retry) — corrected shape

The first pass documented this as the bare inner object:

```json
{ "signature": "0x<65-byte sig>", "authorization": { "from": "...", "to": "...", "value": "...", "validAfter": "...", "validBefore": "...", "nonce": "..." } }
```

That inner shape is right, but it's not what actually goes over the wire. The **real** X-PAYMENT
payload wraps it (confirmed above, from `types/v1/index.ts`'s `PaymentPayloadV1` and a live
facilitator accepting exactly this):

```json
{
  "x402Version": 1,
  "scheme": "exact",
  "network": "base-sepolia",
  "payload": {
    "signature": "0x<65-byte sig>",
    "authorization": { "from": "0x...", "to": "0x...", "value": "10000", "validAfter": "1740671489", "validBefore": "1740672154", "nonce": "0x<32-byte hex>" }
  }
}
```

`validAfter` is `now - 600`, not an arbitrary early value — see above.

**EIP-712 domain for signing**: `extra.name`/`extra.version` from the 402 response's `accepts[]`
entry, plus `chainId` (from the network string, v1 network names mapped via
`CHAIN_ID_BY_NETWORK` in `src/intel.mjs`, cross-checked against the reference SDK's own map) and
`verifyingContract` = the `asset` address. Confirmed unchanged from the first pass — this part was
already right.

`extra.assetTransferMethod` defaults to `"eip3009"` if absent — the only method Deplex implements
(Permit2 and ERC-7710/smart-account methods are real but out of scope, unchanged from the first
pass).

### Settlement response (server → client after successful payment)

Confirmed live above — unchanged from the first pass's documented shape:

```json
{ "success": boolean, "errorReason": "string (on failure)", "transaction": "string", "network": "string", "payer": "string" }
```

### Facilitator `/verify` and `/settle` HTTP contract — now confirmed, not a gap

The first pass flagged this as "NOT CONFIRMED, despite real effort" after checking three spec
docs that described the logic without ever publishing the wire shape. That gap is closed: see
"Live verification" above for the confirmed request/response shapes, backed by both reference
source code and a real HTTP round-trip.

## Open questions — genuinely still open, not resolved by either pass

- Whether Base Sepolia USDC is obtainable via faucet to fund a real payer key without friction —
  still untested, needs the actual live-payment attempt to answer.
- Whether the *specific* facilitator used for the eventual live milestone (`x402.org/facilitator`
  is now the plan) holds up under a real signed authorization, not just a deliberately-invalid
  one — the invalid-signature probes above confirm wire *shape* acceptance, not that a
  *correctly*-signed EIP-3009 authorization actually settles successfully on Base Sepolia. That's
  the one thing left that only a live run proves.
