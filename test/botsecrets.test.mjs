import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  requireMasterKey,
  encryptSecret,
  decryptSecret,
  loadStore,
  setSecret,
  getSecret,
  listSecretNames,
} from '../src/botsecrets.mjs';

let tmpDir;
let storePath;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'deplex-botsecrets-'));
  storePath = join(tmpDir, 'bot-secrets.enc.json');
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function freshKey() {
  return randomBytes(32);
}

// ---------------------------------------------------------------------------
// requireMasterKey -- fail-closed
// ---------------------------------------------------------------------------

test('requireMasterKey throws when DEPLEX_BOT_MASTER_KEY is unset', () => {
  assert.throws(() => requireMasterKey({}), /DEPLEX_BOT_MASTER_KEY is not set/);
});

test('requireMasterKey throws on a key of the wrong length', () => {
  assert.throws(
    () => requireMasterKey({ DEPLEX_BOT_MASTER_KEY: 'ab'.repeat(16) }), // 16 bytes, not 32
    /must be exactly 32 random bytes/,
  );
  assert.throws(
    () => requireMasterKey({ DEPLEX_BOT_MASTER_KEY: 'ab'.repeat(40) }), // too long
    /must be exactly 32 random bytes/,
  );
});

test('requireMasterKey throws on non-hex characters', () => {
  assert.throws(
    () => requireMasterKey({ DEPLEX_BOT_MASTER_KEY: 'z'.repeat(64) }),
    /must be exactly 32 random bytes/,
  );
});

test('requireMasterKey returns a 32-byte Buffer for a valid key', () => {
  const hex = randomBytes(32).toString('hex');
  const key = requireMasterKey({ DEPLEX_BOT_MASTER_KEY: hex });
  assert.ok(Buffer.isBuffer(key));
  assert.equal(key.length, 32);
  assert.equal(key.toString('hex'), hex);
});

// ---------------------------------------------------------------------------
// encryptSecret / decryptSecret -- round-trip + tamper detection
// ---------------------------------------------------------------------------

test('encryptSecret/decryptSecret: round-trips a plaintext value exactly', () => {
  const key = freshKey();
  const record = encryptSecret(key, 'sk-super-secret-api-key-12345');
  assert.equal(decryptSecret(key, record), 'sk-super-secret-api-key-12345');
});

test('encryptSecret: generates a fresh random IV per call, even for the same plaintext', () => {
  const key = freshKey();
  const a = encryptSecret(key, 'same-value');
  const b = encryptSecret(key, 'same-value');
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ciphertext, b.ciphertext); // GCM keystream depends on IV, so ciphertext differs too
});

test('decryptSecret: throws if a byte in the ciphertext is flipped (tamper detection)', () => {
  const key = freshKey();
  const record = encryptSecret(key, 'do-not-corrupt-me');
  const tampered = { ...record, ciphertext: flipFirstByte(record.ciphertext) };
  assert.throws(() => decryptSecret(key, tampered));
});

test('decryptSecret: throws if a byte in the authTag is flipped (tamper detection)', () => {
  const key = freshKey();
  const record = encryptSecret(key, 'do-not-corrupt-me-either');
  const tampered = { ...record, authTag: flipFirstByte(record.authTag) };
  assert.throws(() => decryptSecret(key, tampered));
});

test('decryptSecret: throws if the IV is altered (wrong IV changes the keystream/auth computation)', () => {
  const key = freshKey();
  const record = encryptSecret(key, 'iv-dependent-value');
  const tampered = { ...record, iv: flipFirstByte(record.iv) };
  assert.throws(() => decryptSecret(key, tampered));
});

test('decryptSecret: throws when decrypting with the wrong key', () => {
  const record = encryptSecret(freshKey(), 'value');
  assert.throws(() => decryptSecret(freshKey(), record));
});

function flipFirstByte(hex) {
  const byte = parseInt(hex.slice(0, 2), 16);
  const flipped = (byte ^ 0xff).toString(16).padStart(2, '0');
  return flipped + hex.slice(2);
}

// ---------------------------------------------------------------------------
// File store: setSecret / getSecret / loadStore / listSecretNames
// ---------------------------------------------------------------------------

test('setSecret/getSecret: round-trips through the on-disk store', () => {
  const key = freshKey();
  setSecret(storePath, key, 'KEEPERHUB_API_KEY', 'kh_live_abc123');
  assert.equal(getSecret(storePath, key, 'KEEPERHUB_API_KEY'), 'kh_live_abc123');
});

test('setSecret: the plaintext value never appears anywhere in the stored file', () => {
  const key = freshKey();
  setSecret(storePath, key, 'BOT_TOKEN', 'this-string-must-never-be-on-disk-in-the-clear');
  const raw = readFileSync(storePath, 'utf8');
  assert.ok(!raw.includes('this-string-must-never-be-on-disk-in-the-clear'));
});

test('setSecret: stores only {ciphertext, iv, authTag, updatedAt} per secret', () => {
  const key = freshKey();
  setSecret(storePath, key, 'SOME_KEY', 'value');
  const store = loadStore(storePath);
  const keys = Object.keys(store.SOME_KEY).sort();
  assert.deepEqual(keys, ['authTag', 'ciphertext', 'iv', 'updatedAt']);
});

test('setSecret: multiple secrets coexist and each decrypts independently', () => {
  const key = freshKey();
  setSecret(storePath, key, 'A', 'value-a');
  setSecret(storePath, key, 'B', 'value-b');
  assert.equal(getSecret(storePath, key, 'A'), 'value-a');
  assert.equal(getSecret(storePath, key, 'B'), 'value-b');
});

test('setSecret: overwriting a name replaces it (new IV, new ciphertext)', () => {
  const key = freshKey();
  setSecret(storePath, key, 'ROTATING', 'old-value');
  const first = loadStore(storePath).ROTATING;
  setSecret(storePath, key, 'ROTATING', 'new-value');
  const second = loadStore(storePath).ROTATING;
  assert.notEqual(first.iv, second.iv);
  assert.equal(getSecret(storePath, key, 'ROTATING'), 'new-value');
});

test('getSecret: returns null for a name that was never stored', () => {
  const key = freshKey();
  assert.equal(getSecret(storePath, key, 'NEVER_SET'), null);
});

test('getSecret: decrypting a stored secret under the wrong master key throws (not silent garbage)', () => {
  setSecret(storePath, freshKey(), 'CROSS_KEY_TEST', 'value');
  assert.throws(() => getSecret(storePath, freshKey(), 'CROSS_KEY_TEST'));
});

test('loadStore: returns an empty object when the file does not exist yet', () => {
  assert.deepEqual(loadStore(storePath), {});
  assert.ok(!existsSync(storePath));
});

test('listSecretNames: reflects exactly what has been set', () => {
  const key = freshKey();
  assert.deepEqual(listSecretNames(storePath), []);
  setSecret(storePath, key, 'ONE', 'x');
  setSecret(storePath, key, 'TWO', 'y');
  assert.deepEqual(listSecretNames(storePath).sort(), ['ONE', 'TWO']);
});
