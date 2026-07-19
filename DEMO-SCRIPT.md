# Demo video shot list — 90 seconds

Built entirely around real, already-proven moments — every timestamp/tx hash below is on tape or
in `deplex-audit.jsonl` right now, not staged for the camera. Nothing in this script requires a
new live run to work; the attack-race and dashboard segments can both be re-recorded from
existing data if a fresh take is wanted, but neither needs to be.

| Time | Visual | Narration / on-screen text | Source |
|---|---|---|---|
| 0:00–0:08 | Title card: `DEPLEX` on a terminal background, then the one-liner from the README typing out. | *"Most onchain agents watch, and alert. Deplex watches, decides, and acts."* | — |
| 0:08–0:15 | Cut to the **policy file** (`policies/default.policy`) on screen for 2–3 seconds, then to `src/policy.mjs` compiling it (dashboard's POLICY panel, `✓ compiled clean — 4 rule(s), zero errors`). | *"Every decision is deterministic — a controlled-English policy, compiled and checked, never an LLM in the loop."* | Dashboard, Phase 7 |
| 0:15–0:45 | **The attack race.** Split screen or fast cut: terminal running `attack/run-demo.mjs` (or a replay of its real logged output), then straight to BaseScan/Etherscan showing the two real transactions **one block apart** — defense first. Zoom on block numbers: `11295766` (defense) → `11295767` (attack, reverted). | *"This is real. An independent attacker — its own throwaway key, no special access — plants an unlimited approval, then tries to drain the wallet. Deplex's revoke lands first. One block apart. And it's not Deplex's own word for it — the drain reverting, the correct spender in the revoke calldata, and a direct on-chain allowance query all agree, independently."* | [Verified onchain](README.md#verified-onchain) — defense `0x80122d57…affcb5d47`, attack `0xde1b2dcc…52f2636` |
| 0:45–0:48 | Quick cut: BaseScan showing the **real x402 payment** settlement (`0xddc75d72…3d76c1`), 2 seconds, just enough to register "a second real chain, a second real transaction." | *"Deplex even pays for its own threat intel — a real, on-chain micropayment, not a mock."* | [Verified onchain](README.md#verified-onchain) |
| 0:48–0:75 | **Dashboard, chain verify.** Open `dashboard/` live (or the deployed Vercel URL). Click into the CHAIN VERIFY panel. Click **RUN VERIFICATION** — show the real result: `✓ CHAIN VALID — 2532 records, genesis to head, zero breaks`, timing visible (~30ms). Then click **SIMULATE TAMPERING** — show it flip to `✗ CHAIN BROKEN at record #N: hash mismatch`, red, immediate. | *"Every one of those decisions is hash-chained — over two thousand real records, tamper-evident from block one. This isn't a mockup. It's running live, in this browser, right now, over the actual history. And if one byte changes anywhere in that chain..."* [click tamper] *"...it knows exactly where."* | Dashboard Phase 7, `src/auditchain.mjs` |
| 0:75–0:82 | Cut back to a wide shot of the dashboard — wallet status panel with the incident stepper, live feed scrolling. | *"One audit trail. Verified the same way in Node and in a browser — no separate code path to trust twice."* | Dashboard |
| 0:82–0:90 | Hard cut to black. White text, centered, holds for the full 8 seconds: **"Agents that only alert are spectators. Deplex executes."** Small `deplex` wordmark fades in under it. | *(silent, or a single low sting)* | Closing thesis |

## Notes for whoever films this

- **The attack-race segment is the load-bearing one** — don't rush it. The "one block apart"
  framing only lands if the two block numbers are actually visible on screen for at least a
  couple of seconds each.
- **Chain-verify tampering demo must be filmed live**, not cut around — a viewer needs to see the
  click and the result change in real time for it to read as proof rather than an assertion. It
  completes in well under a second, so there's no dead air to edit out.
- If a fresh take of the attack race is wanted instead of reusing existing footage/screenshots:
  `attack/run-demo.mjs` needs the watcher already running separately (`node src/watcher.mjs`) —
  see the README quickstart. **Do not** run this against real funds casually — it costs a small
  real testnet gas amount per leg and, per `FAILURE-MODES.md`'s facilitator-nonce-collision entry,
  rapid repeated real runs can produce a confusing (if harmless) rejection. One clean take is
  worth more than three rushed ones.
- Total runtime above sums to exactly 90 seconds; the two visual segments (attack race,
  chain-verify) can each flex ±3–4 seconds against the connective cuts if pacing needs it in the
  edit — the closing line should never be the thing that gets cut short.
