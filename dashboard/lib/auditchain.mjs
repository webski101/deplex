// Dependency-free hash-chain core. NO node imports -- this file is imported
// verbatim by the Phase 7 dashboard and must run in a browser as well as in
// Node. The Node-only file I/O layer (append/readAll/verify-from-file) lives
// in auditlog.mjs, which wraps these.

export const GENESIS_PREV_HASH = '0'.repeat(64);

// Canonical preimage a record's hash is computed over. Order and formatting
// are the contract: seq + ts + type + JSON(payload) + prevHash, no
// separators. Any change here breaks every previously-written chain, so it
// must never drift between the writer (auditlog.append) and any verifier.
export function recordPreimage(seq, ts, type, payload, prevHash) {
  return `${seq}${ts}${type}${JSON.stringify(payload)}${prevHash}`;
}

// digest: (string) => hex-string | Promise<hex-string>. Awaiting a
// non-promise is a no-op, so this accepts both a synchronous node:crypto
// digest and an async WebCrypto one interchangeably.
export async function computeRecordHash(digest, record) {
  return digest(recordPreimage(record.seq, record.ts, record.type, record.payload, record.prevHash));
}

// Walks the chain start to finish. Returns { valid, brokenAt, reason }:
// brokenAt is the 0-based index of the first bad record (null when valid).
// Three independent failure modes are checked per record, in order:
//   1. seq is not its position       -> record inserted/deleted/reordered
//   2. prevHash != prior record hash -> chain linkage severed
//   3. recomputed hash != stored     -> record contents tampered
export async function verifyChain(records, digest = webCryptoDigestHex) {
  let prevHash = GENESIS_PREV_HASH;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r == null || typeof r !== 'object') {
      return { valid: false, brokenAt: i, reason: 'record is not an object (unparseable or truncated line)' };
    }
    if (r.seq !== i) {
      return { valid: false, brokenAt: i, reason: `seq mismatch: expected ${i}, found ${r.seq}` };
    }
    if (r.prevHash !== prevHash) {
      return { valid: false, brokenAt: i, reason: 'prevHash does not match the previous record hash (chain linkage broken)' };
    }
    const expected = await computeRecordHash(digest, r);
    if (expected !== r.hash) {
      return { valid: false, brokenAt: i, reason: 'hash mismatch: record contents were altered after signing' };
    }
    prevHash = r.hash;
  }
  return { valid: true, brokenAt: null, reason: null };
}

// SHA-256 -> lowercase hex, via the Web Crypto API. Available as globalThis
// .crypto.subtle in both browsers and Node >=20, so the same function backs
// the dashboard's client-side verify and Node-side verification alike.
export async function webCryptoDigestHex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
