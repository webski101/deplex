import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSetKeyCommand, pollBotUpdates, isHelpCommand, buildHelpText } from '../src/telegram.mjs';
import { ALLOWED_CONFIG_KEYS } from '../src/liveconfig.mjs';

const CFG = { botToken: 'fake-token', chatId: '12345' };

function fakeApi(updates) {
  const calls = [];
  const fn = async (botToken, method, payload) => {
    calls.push({ botToken, method, payload });
    if (method === 'getUpdates') return updates;
    if (method === 'deleteMessage') return { ok: true };
    if (method === 'sendMessage') return { ok: true, message_id: 1 };
    throw new Error(`fakeApi: unexpected method ${method}`);
  };
  fn.calls = calls;
  return fn;
}

function msgUpdate(update_id, { chatId = CFG.chatId, text, message_id = update_id } = {}) {
  return { update_id, message: { message_id, chat: { id: Number(chatId) }, text } };
}

// ---------------------------------------------------------------------------
// parseSetKeyCommand
// ---------------------------------------------------------------------------

test('parseSetKeyCommand: parses a well-formed command', () => {
  assert.deepEqual(parseSetKeyCommand('/setkey KEEPERHUB_API_KEY kh_live_abc123'), {
    name: 'KEEPERHUB_API_KEY',
    value: 'kh_live_abc123',
  });
});

test('parseSetKeyCommand: is case-insensitive on the command itself', () => {
  assert.deepEqual(parseSetKeyCommand('/SetKey NAME value'), { name: 'NAME', value: 'value' });
});

test('parseSetKeyCommand: tolerates the @botname suffix Telegram groups add', () => {
  assert.deepEqual(parseSetKeyCommand('/setkey@deplex_bot NAME secretvalue'), {
    name: 'NAME',
    value: 'secretvalue',
  });
});

test('parseSetKeyCommand: keeps everything after the name as the value, including spaces', () => {
  assert.deepEqual(parseSetKeyCommand('/setkey TOKEN a value with spaces in it'), {
    name: 'TOKEN',
    value: 'a value with spaces in it',
  });
});

test('parseSetKeyCommand: trims surrounding whitespace on the whole message', () => {
  assert.deepEqual(parseSetKeyCommand('  /setkey NAME value  '), { name: 'NAME', value: 'value' });
});

test('parseSetKeyCommand: returns null for a bare /setkey with no args', () => {
  assert.equal(parseSetKeyCommand('/setkey'), null);
});

test('parseSetKeyCommand: returns null for /setkey with only a name, no value', () => {
  assert.equal(parseSetKeyCommand('/setkey NAME'), null);
});

test('parseSetKeyCommand: returns null for unrelated text', () => {
  assert.equal(parseSetKeyCommand('/panic'), null);
  assert.equal(parseSetKeyCommand('hello there'), null);
  assert.equal(parseSetKeyCommand(''), null);
  assert.equal(parseSetKeyCommand(undefined), null);
});

// ---------------------------------------------------------------------------
// isHelpCommand / buildHelpText
// ---------------------------------------------------------------------------

test('isHelpCommand: matches /help, case-insensitively, with or without a @botname suffix', () => {
  assert.equal(isHelpCommand('/help'), true);
  assert.equal(isHelpCommand('/HELP'), true);
  assert.equal(isHelpCommand('/help@deplex_bot'), true);
  assert.equal(isHelpCommand('  /help  '), true);
});

test('isHelpCommand: does not match unrelated text or other commands', () => {
  assert.equal(isHelpCommand('/panic'), false);
  assert.equal(isHelpCommand('/setkey NAME value'), false);
  assert.equal(isHelpCommand('help'), false);
  assert.equal(isHelpCommand(''), false);
  assert.equal(isHelpCommand(undefined), false);
});

test('buildHelpText: lists every name in ALLOWED_CONFIG_KEYS -- fails automatically if that list ever drifts out of sync', () => {
  const helpText = buildHelpText();
  assert.ok(ALLOWED_CONFIG_KEYS.length > 0, 'sanity check: allowlist is not empty');
  for (const key of ALLOWED_CONFIG_KEYS) {
    assert.ok(helpText.includes(key), `help text is missing allowed config key "${key}"`);
  }
});

test('buildHelpText: explains /panic and /setkey, and includes the security reminder', () => {
  const helpText = buildHelpText();
  assert.ok(helpText.includes('/panic'));
  assert.ok(/EVACUATE/i.test(helpText));
  assert.ok(/SAFE_ADDRESS/.test(helpText));
  assert.ok(helpText.includes('/setkey'));
  assert.ok(/encrypted/i.test(helpText));
  assert.ok(/deleted/i.test(helpText));
  assert.ok(/restart/i.test(helpText));
  assert.ok(/allowlisted chat/i.test(helpText));
});

// ---------------------------------------------------------------------------
// pollBotUpdates dispatch
// ---------------------------------------------------------------------------

test('pollBotUpdates: /panic dispatches to onPanic, not onSetKey, and does not delete the message', async () => {
  const api = fakeApi([msgUpdate(1, { text: '/panic' })]);
  let panicked = null;
  let setKeyCalled = false;
  const nextOffset = await pollBotUpdates(
    CFG,
    { onPanic: (e) => (panicked = e), onSetKey: async () => (setKeyCalled = true) },
    { apiRequestFn: api },
  );
  assert.ok(panicked);
  assert.equal(panicked.type, 'panic');
  assert.equal(setKeyCalled, false);
  assert.equal(nextOffset, 2);
  assert.equal(api.calls.filter((c) => c.method === 'deleteMessage').length, 0);
});

test('pollBotUpdates: awaits onPanic (same pattern as onSetKey) rather than firing it and moving on', async () => {
  const api = fakeApi([msgUpdate(1, { text: '/panic' })]);
  const order = [];
  await pollBotUpdates(
    CFG,
    {
      onPanic: async () => {
        order.push('panic-start');
        await Promise.resolve();
        order.push('panic-end');
      },
    },
    { apiRequestFn: api },
  );
  order.push('poll-returned');
  assert.deepEqual(order, ['panic-start', 'panic-end', 'poll-returned']);
});

test('pollBotUpdates: an onPanic handler that throws does not crash the poll', async () => {
  const api = fakeApi([msgUpdate(1, { text: '/panic' })]);
  await assert.doesNotReject(
    pollBotUpdates(
      CFG,
      {
        onPanic: async () => {
          throw new Error('watcher exploded');
        },
      },
      { apiRequestFn: api },
    ),
  );
});

test('pollBotUpdates: /setkey dispatches to onSetKey with {name, value} and deletes the original message', async () => {
  const api = fakeApi([msgUpdate(5, { text: '/setkey BOT_TOKEN abc123', message_id: 999 })]);
  let received = null;
  await pollBotUpdates(CFG, { onSetKey: async (payload) => (received = payload) }, { apiRequestFn: api });

  assert.deepEqual(received, { name: 'BOT_TOKEN', value: 'abc123' });
  const deleteCalls = api.calls.filter((c) => c.method === 'deleteMessage');
  assert.equal(deleteCalls.length, 1);
  assert.equal(deleteCalls[0].payload.message_id, 999);
  assert.equal(deleteCalls[0].payload.chat_id, CFG.chatId);
});

test('pollBotUpdates: ignores /setkey from a chat other than the allowlisted one (no dispatch, no delete)', async () => {
  const api = fakeApi([msgUpdate(1, { chatId: '99999', text: '/setkey NAME value' })]);
  let called = false;
  await pollBotUpdates(CFG, { onSetKey: async () => (called = true) }, { apiRequestFn: api });
  assert.equal(called, false);
  assert.equal(api.calls.filter((c) => c.method === 'deleteMessage').length, 0);
});

test('pollBotUpdates: fail-closed -- with no onSetKey handler wired, nothing is dispatched but the message is still deleted', async () => {
  const api = fakeApi([msgUpdate(1, { text: '/setkey NAME value', message_id: 42 })]);
  // No onSetKey in handlers at all -- simulates DEPLEX_BOT_MASTER_KEY missing at startup.
  await pollBotUpdates(CFG, {}, { apiRequestFn: api });
  const deleteCalls = api.calls.filter((c) => c.method === 'deleteMessage');
  assert.equal(deleteCalls.length, 1);
  assert.equal(deleteCalls[0].payload.message_id, 42);
});

test('pollBotUpdates: an onSetKey handler that throws does not crash the poll, and the message is still deleted', async () => {
  const api = fakeApi([msgUpdate(1, { text: '/setkey NAME value', message_id: 7 })]);
  await assert.doesNotReject(
    pollBotUpdates(
      CFG,
      {
        onSetKey: async () => {
          throw new Error('storage backend exploded');
        },
      },
      { apiRequestFn: api },
    ),
  );
  assert.equal(api.calls.filter((c) => c.method === 'deleteMessage').length, 1);
});

test('pollBotUpdates: a plain message with no matching command is ignored entirely', async () => {
  const api = fakeApi([msgUpdate(1, { text: 'just chatting' })]);
  let panicked = false;
  let setKey = false;
  await pollBotUpdates(
    CFG,
    { onPanic: () => (panicked = true), onSetKey: async () => (setKey = true) },
    { apiRequestFn: api },
  );
  assert.equal(panicked, false);
  assert.equal(setKey, false);
  assert.equal(api.calls.filter((c) => c.method === 'deleteMessage').length, 0);
});

test('pollBotUpdates: returns an offset one past the highest update_id seen, regardless of dispatch outcome', async () => {
  const api = fakeApi([
    msgUpdate(10, { text: '/panic' }),
    msgUpdate(11, { text: 'noise' }),
    msgUpdate(12, { text: '/setkey NAME value' }),
  ]);
  const nextOffset = await pollBotUpdates(CFG, { onPanic: () => {}, onSetKey: async () => {} }, { apiRequestFn: api });
  assert.equal(nextOffset, 13);
});

test('pollBotUpdates: passes the given offset through to getUpdates', async () => {
  const api = fakeApi([]);
  await pollBotUpdates(CFG, {}, { offset: 77, apiRequestFn: api });
  const getUpdatesCall = api.calls.find((c) => c.method === 'getUpdates');
  assert.equal(getUpdatesCall.payload.offset, 77);
});

test('pollBotUpdates: /help sends the help text back to the same chat, does not touch onPanic/onSetKey, and does not delete the message', async () => {
  const api = fakeApi([msgUpdate(1, { text: '/help', message_id: 55 })]);
  let panicked = false;
  let setKeyCalled = false;
  await pollBotUpdates(
    CFG,
    { onPanic: () => (panicked = true), onSetKey: async () => (setKeyCalled = true) },
    { apiRequestFn: api },
  );

  assert.equal(panicked, false);
  assert.equal(setKeyCalled, false);
  assert.equal(api.calls.filter((c) => c.method === 'deleteMessage').length, 0);

  const sendCalls = api.calls.filter((c) => c.method === 'sendMessage');
  assert.equal(sendCalls.length, 1);
  assert.equal(sendCalls[0].payload.chat_id, CFG.chatId);
  for (const key of ALLOWED_CONFIG_KEYS) {
    assert.ok(sendCalls[0].payload.text.includes(key), `sent /help text is missing "${key}"`);
  }
});
