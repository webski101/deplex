// controlled-English policy compiler -> deterministic rules

export class PolicyParseError extends Error {}

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const DEFAULT_PRIORITY = 5;
const MAX_UINT256 = (1n << 256n) - 1n;
const UNLIMITED_THRESHOLD = 10n ** 30n;

export const INCIDENT_STATES = ['IDLE', 'ALERTED', 'REVOKING', 'EVACUATING', 'RESOLVED'];
const TIER_TO_STATE = { 0: 'ALERTED', 1: 'REVOKING', 2: 'REVOKING', 3: 'EVACUATING' };

// ---------------------------------------------------------------------------
// Tokenizer + recursive-descent parser for the condition grammar
// ---------------------------------------------------------------------------

function tokenizeCondition(text) {
  const re = /\(|\)|%|>|[A-Za-z0-9_.]+/g;
  const tokens = [];
  let match;
  let lastIndex = 0;
  while ((match = re.exec(text)) !== null) {
    const gap = text.slice(lastIndex, match.index);
    if (gap.trim() !== '') {
      throw new PolicyParseError(`unexpected character(s) "${gap.trim()}" in condition`);
    }
    tokens.push(match[0]);
    lastIndex = re.lastIndex;
  }
  const tail = text.slice(lastIndex);
  if (tail.trim() !== '') {
    throw new PolicyParseError(`unexpected character(s) "${tail.trim()}" in condition`);
  }
  return tokens;
}

class ConditionParser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek() {
    return this.tokens[this.pos];
  }

  next() {
    return this.tokens[this.pos++];
  }

  parse() {
    const node = this.parseOr();
    if (this.pos !== this.tokens.length) {
      throw new PolicyParseError(`unexpected trailing token "${this.peek()}" in condition`);
    }
    return node;
  }

  parseOr() {
    let left = this.parseAnd();
    while (this.peek() && this.peek().toUpperCase() === 'OR') {
      this.next();
      left = { op: 'OR', left, right: this.parseAnd() };
    }
    return left;
  }

  parseAnd() {
    let left = this.parseNot();
    while (this.peek() && this.peek().toUpperCase() === 'AND') {
      this.next();
      left = { op: 'AND', left, right: this.parseNot() };
    }
    return left;
  }

  parseNot() {
    if (this.peek() && this.peek().toUpperCase() === 'NOT') {
      this.next();
      return { op: 'NOT', operand: this.parseNot() };
    }
    return this.parseGroupOrAtom();
  }

  parseGroupOrAtom() {
    const tok = this.peek();
    if (tok === undefined) {
      throw new PolicyParseError('unexpected end of condition');
    }
    if (tok === '(') {
      this.next();
      const node = this.parseOr();
      if (this.peek() !== ')') {
        throw new PolicyParseError('expected ")" in condition');
      }
      this.next();
      return node;
    }
    return this.parseAtom();
  }

  parseAtom() {
    const tok = this.next();
    if (tok === undefined) throw new PolicyParseError('unexpected end of condition');
    switch (tok.toLowerCase()) {
      case 'approval.new':
        return { type: 'approval.new' };
      case 'approval.unlimited':
        return { type: 'approval.unlimited' };
      case 'panic.triggered':
        return { type: 'panic.triggered' };
      case 'approval.spender':
        return this.parseSpenderSuffix();
      case 'transfer.out.to':
        this.expectWord('NOT', '"transfer.out.to NOT ALLOWLISTED"');
        this.expectWord('ALLOWLISTED', '"transfer.out.to NOT ALLOWLISTED"');
        return { type: 'transfer.out.to.notAllowlisted' };
      case 'transfer.out.value':
        return this.parseTransferValueSuffix();
      default:
        throw new PolicyParseError(`unknown condition "${tok}"`);
    }
  }

  parseSpenderSuffix() {
    const tok = this.next();
    if (!tok) throw new PolicyParseError('expected NOT or RISK after "approval.spender"');
    const upper = tok.toUpperCase();
    if (upper === 'NOT') {
      this.expectWord('ALLOWLISTED', '"approval.spender NOT ALLOWLISTED"');
      return { type: 'approval.spender.notAllowlisted' };
    }
    if (upper === 'RISK') {
      this.expectSymbol('>');
      const num = this.expectNumber();
      if (num < 0 || num > 100) {
        throw new PolicyParseError(`RISK threshold ${num} out of range 0-100`);
      }
      return { type: 'approval.spender.riskGt', value: num };
    }
    throw new PolicyParseError(`expected NOT or RISK after "approval.spender", got "${tok}"`);
  }

  parseTransferValueSuffix() {
    this.expectSymbol('>');
    const num = this.expectNumber();
    this.expectSymbol('%');
    this.expectWord('OF', '"transfer.out.value > N% OF WALLET"');
    this.expectWord('WALLET', '"transfer.out.value > N% OF WALLET"');
    return { type: 'transfer.out.value.gtPercent', value: num };
  }

  expectWord(word, ctx) {
    const tok = this.next();
    if (!tok || tok.toUpperCase() !== word) {
      throw new PolicyParseError(`expected "${word}" in ${ctx}, got "${tok ?? 'end of condition'}"`);
    }
  }

  expectSymbol(sym) {
    const tok = this.next();
    if (tok !== sym) {
      throw new PolicyParseError(`expected "${sym}" in condition, got "${tok ?? 'end of condition'}"`);
    }
  }

  expectNumber() {
    const tok = this.next();
    if (tok === undefined || !/^\d+(\.\d+)?$/.test(tok)) {
      throw new PolicyParseError(`expected a number in condition, got "${tok ?? 'end of condition'}"`);
    }
    return Number(tok);
  }
}

// ---------------------------------------------------------------------------
// Line-level parsing
// ---------------------------------------------------------------------------

function stripComment(line) {
  const idx = line.indexOf('#');
  return idx === -1 ? line : line.slice(0, idx);
}

function parseAddress(token, context) {
  if (!ADDRESS_RE.test(token)) {
    throw new PolicyParseError(`invalid address "${token}" in ${context} (expected 0x + 40 hex chars)`);
  }
  return token;
}

function parseWatchWallet(line) {
  const m = /^WATCH\s+WALLET\s+(\S+)\s*$/i.exec(line);
  if (!m) throw new PolicyParseError('expected "WATCH WALLET <address>"');
  return parseAddress(m[1], 'WATCH WALLET');
}

function parseAllowlist(line) {
  const m = /^ALLOWLIST\s+SPENDER\s+(\S+)(?:\s+(.+))?$/i.exec(line);
  if (!m) throw new PolicyParseError('expected "ALLOWLIST SPENDER <address> [<label>]"');
  const address = parseAddress(m[1], 'ALLOWLIST SPENDER');
  const label = m[2] ? m[2].trim() : null;
  return { address, label };
}

function parseSafeAddress(line) {
  const m = /^SAFE\s+ADDRESS\s+(\S+)\s*$/i.exec(line);
  if (!m) throw new PolicyParseError('expected "SAFE ADDRESS <address>"');
  return parseAddress(m[1], 'SAFE ADDRESS');
}

function parseAction(text) {
  const words = text.split(/\s+/);
  const head = words[0].toUpperCase();
  if (head === 'ALERT' && words.length === 1) return { type: 'ALERT', tier: 0 };
  if (head === 'REVOKE' && words.length === 1) return { type: 'REVOKE', tier: 1 };
  if (head === 'REVOKE' && words.length === 2 && words[1].toUpperCase() === 'ALL') {
    return { type: 'REVOKE_ALL', tier: 2 };
  }
  if (head === 'EVACUATE' && words.length === 1) return { type: 'EVACUATE', tier: 3 };
  throw new PolicyParseError(`unknown action "${text}"`);
}

function parseRuleLine(line, lineNo) {
  const ruleMatch = /^RULE\s+(.+?):(.*)$/i.exec(line);
  if (!ruleMatch) {
    throw new PolicyParseError('expected "RULE <name>: IF <condition> THEN <action>"');
  }
  const name = ruleMatch[1].trim();
  if (!name) throw new PolicyParseError('rule name is empty');
  const rest = ruleMatch[2];

  const ifMatch = /^\s*IF\b(.*)$/i.exec(rest);
  if (!ifMatch) throw new PolicyParseError('expected "IF" after rule name');
  const afterIf = ifMatch[1];

  const thenIdx = afterIf.search(/\bTHEN\b/i);
  if (thenIdx === -1) throw new PolicyParseError('expected "THEN" in rule');
  const conditionText = afterIf.slice(0, thenIdx).trim();
  const afterThen = afterIf.slice(thenIdx + 4).trim();

  if (!conditionText) throw new PolicyParseError('condition is empty');
  const tokens = tokenizeCondition(conditionText);
  if (tokens.length === 0) throw new PolicyParseError('condition is empty');
  const condition = new ConditionParser(tokens).parse();

  let actionText = afterThen;
  let priority = DEFAULT_PRIORITY;
  const priorityIdx = afterThen.search(/\bPRIORITY\b/i);
  if (priorityIdx !== -1) {
    actionText = afterThen.slice(0, priorityIdx).trim();
    const priorityText = afterThen.slice(priorityIdx + 8).trim();
    if (!/^\d+$/.test(priorityText)) {
      throw new PolicyParseError(`invalid PRIORITY value "${priorityText}" (expected integer 1-10)`);
    }
    priority = Number(priorityText);
    if (priority < 1 || priority > 10) {
      throw new PolicyParseError(`PRIORITY ${priority} out of range 1-10`);
    }
  }
  if (!actionText.trim()) throw new PolicyParseError('action is empty');
  const action = parseAction(actionText.trim());

  return { name, condition, action, priority, line: lineNo };
}

// ---------------------------------------------------------------------------
// compile()
// ---------------------------------------------------------------------------

export function compile(text) {
  const lines = String(text).split(/\r\n|\r|\n/);
  const rules = [];
  const errors = [];
  const config = { watchWallet: null, allowlist: [], safeAddress: null };
  const seenNames = new Set();

  lines.forEach((rawLine, idx) => {
    const lineNo = idx + 1;
    const stripped = stripComment(rawLine).trim();
    if (stripped === '') return;
    try {
      if (/^WATCH\b/i.test(stripped)) {
        config.watchWallet = parseWatchWallet(stripped);
      } else if (/^ALLOWLIST\b/i.test(stripped)) {
        config.allowlist.push(parseAllowlist(stripped));
      } else if (/^SAFE\b/i.test(stripped)) {
        config.safeAddress = parseSafeAddress(stripped);
      } else if (/^RULE\b/i.test(stripped)) {
        const rule = parseRuleLine(stripped, lineNo);
        const key = rule.name.toLowerCase();
        if (seenNames.has(key)) {
          throw new PolicyParseError(`duplicate rule name "${rule.name}"`);
        }
        seenNames.add(key);
        rules.push(rule);
      } else {
        throw new PolicyParseError('unrecognized statement');
      }
    } catch (err) {
      errors.push({ line: lineNo, message: err instanceof Error ? err.message : String(err) });
    }
  });

  return { rules, errors, config };
}

// ---------------------------------------------------------------------------
// evaluate()
// ---------------------------------------------------------------------------

export function isUnlimitedAmount(amount) {
  if (amount === undefined || amount === null) return false;
  let big;
  try {
    big = typeof amount === 'bigint' ? amount : BigInt(amount);
  } catch {
    return false;
  }
  return big === MAX_UINT256 || big > UNLIMITED_THRESHOLD;
}

function isAllowlisted(address, walletState) {
  if (!address) return false;
  const list = walletState?.allowlist;
  if (!list) return false;
  const target = address.toLowerCase();
  if (list instanceof Set) return list.has(target);
  if (Array.isArray(list)) {
    return list.some((entry) => {
      const a = typeof entry === 'string' ? entry : entry?.address;
      return typeof a === 'string' && a.toLowerCase() === target;
    });
  }
  return false;
}

function getTransferPercent(event, walletState) {
  if (typeof event.percentOfWallet === 'number' && Number.isFinite(event.percentOfWallet)) {
    return event.percentOfWallet;
  }
  const value = Number(event.value);
  // A transfer of nothing can never be a large outbound transfer, regardless
  // of whether wallet balance is computable. Confirmed live: a zero-value
  // transferFrom (an attack drain attempt blocked by a zero allowance) was
  // misread as "unknown wallet share -> fail closed as Infinity%" because the
  // token wasn't in TRACKED_TOKENS, triggering an unwarranted EVACUATE for a
  // transaction that moved zero value. Checked before the fail-closed path,
  // not folded into it -- this is a real 0, not missing data.
  if (value === 0) return 0;
  const balance = Number(walletState?.balance);
  if (!Number.isFinite(value) || !Number.isFinite(balance) || balance <= 0) {
    // Can't determine wallet share from available data: fail closed as maximal outflow.
    return Infinity;
  }
  return (value / balance) * 100;
}

function evalNode(node, event, walletState) {
  switch (node.type ?? node.op) {
    case 'AND':
      return evalNode(node.left, event, walletState) && evalNode(node.right, event, walletState);
    case 'OR':
      return evalNode(node.left, event, walletState) || evalNode(node.right, event, walletState);
    case 'NOT':
      return !evalNode(node.operand, event, walletState);
    // Every field-based atom gates on its event type first. Without the
    // gate, fail-closed defaults designed for one event family leak across
    // families: an APPROVAL event evaluated transfer.out.value's
    // missing-data path (percent -> Infinity) as true and escalated straight
    // to EVACUATE -- caught live in a DRY_RUN, worst possible misfire short
    // of a real one.
    case 'approval.new':
      return event.type === 'approval';
    case 'approval.unlimited':
      return event.type === 'approval' && isUnlimitedAmount(event.amount);
    case 'approval.spender.notAllowlisted':
      return event.type === 'approval' && !isAllowlisted(event.spender, walletState);
    case 'approval.spender.riskGt': {
      if (event.type !== 'approval') return false;
      // Risk score is sourced from intel.mjs; if it's unavailable, fail closed (worst case).
      const risk = typeof event.spenderRisk === 'number' && Number.isFinite(event.spenderRisk)
        ? event.spenderRisk
        : 100;
      return risk > node.value;
    }
    case 'transfer.out.value.gtPercent':
      return event.type === 'transfer' && getTransferPercent(event, walletState) > node.value;
    case 'transfer.out.to.notAllowlisted':
      return event.type === 'transfer' && !isAllowlisted(event.to, walletState);
    case 'panic.triggered':
      return event.type === 'panic';
    default:
      return false;
  }
}

export function evaluate(rules, event, walletState = {}) {
  const incident = walletState.incident || { highestTier: -1 };
  const triggered = [];

  for (const rule of rules) {
    if (!evalNode(rule.condition, event, walletState)) continue;
    // Escalation is monotonic: a tier already superseded this incident is moot.
    if (rule.action.tier < incident.highestTier) continue;
    triggered.push({ ruleName: rule.name, action: rule.action, priority: rule.priority });
  }

  triggered.sort((a, b) => {
    if (b.priority !== a.priority) return b.priority - a.priority;
    return a.ruleName < b.ruleName ? -1 : a.ruleName > b.ruleName ? 1 : 0;
  });

  return triggered;
}

// ---------------------------------------------------------------------------
// Incident state machine: IDLE -> ALERTED -> REVOKING -> EVACUATING -> RESOLVED
// ---------------------------------------------------------------------------

export function advanceIncident(incident, triggeredActions) {
  let stateName = incident?.stateName ?? 'IDLE';
  let highestTier = incident?.highestTier ?? -1;
  // RESOLVED sits last in INCIDENT_STATES (it's a terminal marker, not a
  // progression rank), so comparing against its array index directly would
  // leave a brand-new incident's stateName stuck at RESOLVED forever. Rank
  // it like a fresh start instead.
  let stateRank = stateName === 'RESOLVED' ? INCIDENT_STATES.indexOf('IDLE') : INCIDENT_STATES.indexOf(stateName);

  for (const t of triggeredActions) {
    if (t.action.tier > highestTier) {
      highestTier = t.action.tier;
      const target = TIER_TO_STATE[t.action.tier];
      if (INCIDENT_STATES.indexOf(target) > stateRank) {
        stateName = target;
        stateRank = INCIDENT_STATES.indexOf(target);
      }
    }
  }

  return { stateName, highestTier };
}

export function resolveIncident() {
  return { stateName: 'RESOLVED', highestTier: -1 };
}

export function resetIncident() {
  return { stateName: 'IDLE', highestTier: -1 };
}
