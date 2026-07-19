// Zero-dependency Ethereum primitives for the attack simulator: keccak256,
// RLP encoding, secp256k1 ECDSA signing, and legacy transaction
// construction. Exists because the drainer needs to sign a real
// transferFrom as an independent "attacker" key -- and zero npm deps means
// no ethers/viem to reach for.
//
// Risk-reduction design note: the highest-risk part of hand-rolled ECDSA is
// elliptic-curve point arithmetic (point add/double/scalar-mult). Rather
// than reimplementing that, every point multiplication here goes through
// node:crypto's ECDH('secp256k1'), which is OpenSSL-backed: setPrivateKey(k)
// + getPublicKey() computes k*G using a trusted implementation, both for
// deriving an address from a real private key and for the ephemeral point
// R=k*G during signing. Only scalar modular arithmetic (BigInt, no point
// math), keccak256, and RLP are hand-rolled here -- see
// test/attack-crypto.test.mjs, which cross-checks the signing math against
// node:crypto's own ECDSA verify (independent of this file's own r/s
// derivation) rather than trusting this file's arithmetic alone.

import { createECDH, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// keccak256 (the ORIGINAL Keccak, NOT NIST SHA3 -- different padding byte:
// 0x01 here vs SHA3's 0x06. This is exactly why node:crypto's 'sha3-256'
// cannot be used for Ethereum hashing.)
// ---------------------------------------------------------------------------

const MASK64 = (1n << 64n) - 1n;

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const KECCAK_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

function rotl64(x, n) {
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
}

function keccakF1600(st) {
  const bc = new Array(5);
  for (let round = 0; round < 24; round++) {
    // Theta
    for (let i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    for (let i = 0; i < 5; i++) {
      const t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (let j = 0; j < 25; j += 5) st[j + i] ^= t;
    }
    // Rho + Pi
    let t = st[1];
    for (let i = 0; i < 24; i++) {
      const j = KECCAK_PILN[i];
      const bc0 = st[j];
      st[j] = rotl64(t, KECCAK_ROTC[i]);
      t = bc0;
    }
    // Chi
    for (let j = 0; j < 25; j += 5) {
      for (let i = 0; i < 5; i++) bc[i] = st[j + i];
      for (let i = 0; i < 5; i++) st[j + i] ^= ~bc[(i + 1) % 5] & bc[(i + 2) % 5] & MASK64;
    }
    // Iota
    st[0] ^= KECCAK_RC[round];
  }
}

function keccakPad(msgBytes, rate) {
  const padLen = rate - (msgBytes.length % rate);
  const padded = new Uint8Array(msgBytes.length + padLen);
  padded.set(msgBytes);
  padded[msgBytes.length] = 0x01; // original-Keccak padding (NOT SHA3's 0x06)
  padded[padded.length - 1] |= 0x80;
  return padded;
}

export function keccak256(input) {
  const msgBytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const rate = 136; // 1088 bits, for 256-bit output / 512-bit capacity
  const padded = keccakPad(msgBytes, rate);

  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[offset + i * 8 + b]);
      state[i] ^= lane;
    }
    keccakF1600(state);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = state[i];
    for (let b = 0; b < 8; b++) {
      out[i * 8 + b] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

export function keccak256Hex(input) {
  return bytesToHex(keccak256(input));
}

// ---------------------------------------------------------------------------
// Byte / BigInt helpers
// ---------------------------------------------------------------------------

export function hexToBytes(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const padded = clean.length % 2 ? '0' + clean : clean;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

export function bytesToHex(bytes) {
  return '0x' + Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBigInt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bigIntTo32Bytes(v) {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

// minimal big-endian encoding, no leading zero bytes; 0 -> empty (RLP rule)
function bigIntToMinimalBytes(v) {
  if (v === 0n) return new Uint8Array(0);
  const bytes = [];
  let x = v;
  while (x > 0n) {
    bytes.unshift(Number(x & 0xffn));
    x >>= 8n;
  }
  return new Uint8Array(bytes);
}

function modPow(base, exp, mod) {
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  let result = 1n;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function modInverse(a, mod) {
  return modPow(a, mod - 2n, mod); // valid since secp256k1's p and n are both prime
}

// ---------------------------------------------------------------------------
// secp256k1: point multiplication via node:crypto ECDH (see file header)
// ---------------------------------------------------------------------------

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_N_HALF = SECP256K1_N >> 1n;

function pointMultiplyG(scalar) {
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(bigIntTo32Bytes(scalar)));
  const pub = ecdh.getPublicKey(); // uncompressed: 0x04 || X(32) || Y(32)
  return { x: bytesToBigInt(pub.subarray(1, 33)), y: bytesToBigInt(pub.subarray(33, 65)) };
}

// Test seam: lets test/attack-crypto.test.mjs check point multiplication
// against the secp256k1 generator's well-known, widely-published
// coordinates (pointMultiplyG(1n) must equal G itself) -- an absolute
// ground-truth check, not just internal self-consistency.
export function _pointMultiplyG(scalar) {
  return pointMultiplyG(scalar);
}

export function privateKeyToAddress(privateKeyHexOrBigInt) {
  const priv = typeof privateKeyHexOrBigInt === 'bigint' ? privateKeyHexOrBigInt : bytesToBigInt(hexToBytes(privateKeyHexOrBigInt));
  const { x, y } = pointMultiplyG(priv);
  const pubBytes = new Uint8Array(64);
  pubBytes.set(bigIntTo32Bytes(x), 0);
  pubBytes.set(bigIntTo32Bytes(y), 32);
  const hash = keccak256(pubBytes);
  return bytesToHex(hash.subarray(12)); // last 20 bytes
}

// Returns { r, s, recoveryParity } for a 32-byte message hash. Low-s
// normalized (EIP-2): if the raw s exceeds n/2, negate it and flip parity --
// standard practice so signatures are canonical/non-malleable.
function ecdsaSign(messageHash32, privateKey) {
  const z = bytesToBigInt(messageHash32) % SECP256K1_N;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    let k;
    do {
      k = bytesToBigInt(randomBytes(32));
    } while (k === 0n || k >= SECP256K1_N);

    const R = pointMultiplyG(k);
    const r = R.x % SECP256K1_N;
    if (r === 0n) continue;

    const kInv = modInverse(k, SECP256K1_N);
    let s = (kInv * (z + r * privateKey)) % SECP256K1_N;
    if (s === 0n) continue;

    let recoveryParity = R.y % 2n === 0n ? 0 : 1;
    if (s > SECP256K1_N_HALF) {
      s = SECP256K1_N - s;
      recoveryParity = recoveryParity === 0 ? 1 : 0;
    }
    return { r, s, recoveryParity };
  }
}

// Exposed for tests: raw (r,s) as 64 bytes, ieee-p1363-compatible, so
// node:crypto's own ECDSA verify can independently check this file's math.
export function signRawDigest(messageHash32, privateKeyHexOrBigInt) {
  const priv = typeof privateKeyHexOrBigInt === 'bigint' ? privateKeyHexOrBigInt : bytesToBigInt(hexToBytes(privateKeyHexOrBigInt));
  const { r, s, recoveryParity } = ecdsaSign(messageHash32, priv);
  return { r, s, recoveryParity, rsBytes: Buffer.concat([Buffer.from(bigIntTo32Bytes(r)), Buffer.from(bigIntTo32Bytes(s))]) };
}

// ---------------------------------------------------------------------------
// RLP
// ---------------------------------------------------------------------------

function rlpEncodeLength(len, offset) {
  if (len < 56) return Uint8Array.of(len + offset);
  const lenBytes = bigIntToMinimalBytes(BigInt(len));
  return concatBytes(Uint8Array.of(lenBytes.length + offset + 55), lenBytes);
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// input: nested array (list) or Uint8Array/number/bigint (byte string leaf)
export function rlpEncode(input) {
  if (Array.isArray(input)) {
    const encoded = concatBytes(...input.map(rlpEncode));
    return concatBytes(rlpEncodeLength(encoded.length, 0xc0), encoded);
  }
  let bytes;
  if (input instanceof Uint8Array) bytes = input;
  else if (typeof input === 'bigint') bytes = bigIntToMinimalBytes(input);
  else if (typeof input === 'number') bytes = bigIntToMinimalBytes(BigInt(input));
  else throw new Error(`rlpEncode: unsupported input type ${typeof input}`);

  if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
  return concatBytes(rlpEncodeLength(bytes.length, 0x80), bytes);
}

// ---------------------------------------------------------------------------
// Legacy (type-0) transaction: simpler RLP/v-derivation than EIP-1559, and
// fully valid on Sepolia -- chosen deliberately to minimize hand-rolled
// surface area for a demo-only signer.
// ---------------------------------------------------------------------------

function legacyTxFields(tx, v, r, s) {
  return [
    BigInt(tx.nonce),
    BigInt(tx.gasPrice),
    BigInt(tx.gasLimit),
    hexToBytes(tx.to),
    BigInt(tx.value ?? 0),
    tx.data ? hexToBytes(tx.data) : new Uint8Array(0),
    v,
    r,
    s,
  ];
}

// tx: { nonce, gasPrice, gasLimit, to, value, data }. Returns
// { raw: '0x...' (for eth_sendRawTransaction), hash: '0x...' (the resulting txHash) }.
export function signLegacyTransaction(tx, privateKeyHexOrBigInt, chainId) {
  const priv = typeof privateKeyHexOrBigInt === 'bigint' ? privateKeyHexOrBigInt : bytesToBigInt(hexToBytes(privateKeyHexOrBigInt));
  const chainIdBig = BigInt(chainId);

  // EIP-155 signing digest: same fields, v=chainId, r=s=0 placeholders
  const unsignedFields = legacyTxFields(tx, chainIdBig, 0n, 0n);
  const digest = keccak256(rlpEncode(unsignedFields));

  const { r, s, recoveryParity } = ecdsaSign(digest, priv);
  const v = chainIdBig * 2n + 35n + BigInt(recoveryParity);

  const signedFields = legacyTxFields(tx, v, r, s);
  const rawBytes = rlpEncode(signedFields);
  const txHash = keccak256(rawBytes);

  return { raw: bytesToHex(rawBytes), hash: bytesToHex(txHash) };
}
