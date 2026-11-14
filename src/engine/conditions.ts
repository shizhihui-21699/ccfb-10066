/**
 * Condition operator evaluation.
 *
 * Implements the documented AWS semantics for the commonly used operator
 * families, including negated forms, `...IfExists`, `Null`, and the
 * `ForAllValues` / `ForAnyValue` set qualifiers.
 */

import type { ConditionValue, Scalar, Tri } from './types';
import { arnMatch, wildcardMatch } from './wildcard';
import { NULL_VALUE } from './variables';

export type OperatorFamily =
  | 'string'
  | 'numeric'
  | 'date'
  | 'bool'
  | 'ip'
  | 'arn'
  | 'binary'
  | 'null';

export interface ParsedOperator {
  raw: string;
  family: OperatorFamily;
  /** Whether the base operator is a negated ("not") comparison. */
  negated: boolean;
  ignoreCase: boolean;
  setOp: 'ForAllValues' | 'ForAnyValue' | null;
  ifExists: boolean;
}

const STRING_OPERATORS: Record<string, { negated: boolean; ignoreCase: boolean; like: boolean }> = {
  StringEquals: { negated: false, ignoreCase: false, like: false },
  StringNotEquals: { negated: true, ignoreCase: false, like: false },
  StringEqualsIgnoreCase: { negated: false, ignoreCase: true, like: false },
  StringNotEqualsIgnoreCase: { negated: true, ignoreCase: true, like: false },
  StringLike: { negated: false, ignoreCase: false, like: true },
  StringNotLike: { negated: true, ignoreCase: false, like: true },
};

const NUMERIC_OPERATORS: Record<string, { negated: boolean; compare: 'eq' | 'lt' | 'lte' | 'gt' | 'gte' }> = {
  NumericEquals: { negated: false, compare: 'eq' },
  NumericNotEquals: { negated: true, compare: 'eq' },
  NumericLessThan: { negated: false, compare: 'lt' },
  NumericLessThanEquals: { negated: false, compare: 'lte' },
  NumericGreaterThan: { negated: false, compare: 'gt' },
  NumericGreaterThanEquals: { negated: false, compare: 'gte' },
};

const DATE_OPERATORS: Record<string, { negated: boolean; compare: 'eq' | 'lt' | 'lte' | 'gt' | 'gte' }> = {
  DateEquals: { negated: false, compare: 'eq' },
  DateNotEquals: { negated: true, compare: 'eq' },
  DateLessThan: { negated: false, compare: 'lt' },
  DateLessThanEquals: { negated: false, compare: 'lte' },
  DateGreaterThan: { negated: false, compare: 'gt' },
  DateGreaterThanEquals: { negated: false, compare: 'gte' },
};

const ARN_OPERATORS: Record<string, { negated: boolean }> = {
  ArnEquals: { negated: false },
  ArnLike: { negated: false },
  ArnNotEquals: { negated: true },
  ArnNotLike: { negated: true },
};

const IP_OPERATORS: Record<string, { negated: boolean }> = {
  IpAddress: { negated: false },
  NotIpAddress: { negated: true },
};

/** Parses an operator name such as `ForAnyValue:StringLikeIfExists`. */
export function parseOperator(raw: string): ParsedOperator | null {
  let rest = raw.trim();
  let setOp: ParsedOperator['setOp'] = null;
  if (rest.startsWith('ForAllValues:')) {
    setOp = 'ForAllValues';
    rest = rest.slice('ForAllValues:'.length);
  } else if (rest.startsWith('ForAnyValue:')) {
    setOp = 'ForAnyValue';
    rest = rest.slice('ForAnyValue:'.length);
  }

  let ifExists = false;
  if (rest.endsWith('IfExists')) {
    ifExists = true;
    rest = rest.slice(0, -'IfExists'.length);
  }

  if (rest === 'Null') {
    return {
      raw,
      family: 'null',
      negated: false,
      ignoreCase: false,
      setOp,
      ifExists: false,
    };
  }
  if (rest === 'Bool') {
    return { raw, family: 'bool', negated: false, ignoreCase: true, setOp, ifExists };
  }
  if (rest === 'BinaryEquals') {
    return { raw, family: 'binary', negated: false, ignoreCase: false, setOp, ifExists };
  }
  if (rest in STRING_OPERATORS) {
    return { raw, family: 'string', ...STRING_OPERATORS[rest], setOp, ifExists };
  }
  if (rest in NUMERIC_OPERATORS) {
    const { negated, compare } = NUMERIC_OPERATORS[rest];
    return { raw, family: 'numeric', negated, ignoreCase: false, setOp, ifExists, ...{ compare } };
  }
  if (rest in DATE_OPERATORS) {
    const { negated, compare } = DATE_OPERATORS[rest];
    return { raw, family: 'date', negated, ignoreCase: false, setOp, ifExists, ...{ compare } };
  }
  if (rest in ARN_OPERATORS) {
    return { raw, family: 'arn', negated: ARN_OPERATORS[rest].negated, ignoreCase: false, setOp, ifExists };
  }
  if (rest in IP_OPERATORS) {
    return { raw, family: 'ip', negated: IP_OPERATORS[rest].negated, ignoreCase: false, setOp, ifExists };
  }
  return null;
}

interface ParsedOperatorWithCompare extends ParsedOperator {
  compare?: 'eq' | 'lt' | 'lte' | 'gt' | 'gte';
  like?: boolean;
}

function toComparable(value: string | Scalar): string {
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  return value;
}

/** Parses a numeric condition value. */
function toNumber(value: string): number | null {
  if (value.trim() === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/** Parses a date value as ISO 8601 or epoch seconds. */
function toEpochMs(value: string): number | null {
  const trimmed = value.trim();
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
    const n = Number(trimmed);
    if (!Number.isFinite(n)) return null;
    return n * 1000;
  }
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? null : parsed;
}

function compareNumbers(a: number, b: number, op: 'eq' | 'lt' | 'lte' | 'gt' | 'gte'): boolean {
  switch (op) {
    case 'eq':
      return a === b;
    case 'lt':
      return a < b;
    case 'lte':
      return a <= b;
    case 'gt':
      return a > b;
    case 'gte':
      return a >= b;
    default:
      return false;
  }
}

/* ------------------------------------------------------------------ */
/* IP / CIDR support                                                   */
/* ------------------------------------------------------------------ */

function parseIPv4(text: string): { value: number; bits: number } | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(text.trim());
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  if (octets.some((o) => o > 255)) return null;
  const prefix = match[5] === undefined ? 32 : Number(match[5]);
  if (prefix > 32) return null;
  const value = octets.reduce((acc, octet) => acc * 256 + octet, 0);
  return { value, bits: prefix };
}

function parseIPv6(text: string): { value: bigint; bits: number } | null {
  const trimmed = text.trim().toLowerCase();
  const [addrPart, prefixPart] = trimmed.split('/');
  const prefix = prefixPart === undefined ? 128 : Number(prefixPart);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null;
  if (!/^[0-9a-f:.]+$/.test(addrPart)) return null;

  const doubleColonSplit = addrPart.split('::');
  if (doubleColonSplit.length > 2) return null;

  const parseGroups = (part: string): number[] | null => {
    if (part === '') return [];
    const groups = part.split(':');
    const result: number[] = [];
    for (const group of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
      result.push(parseInt(group, 16));
    }
    return result;
  };

  let groups: number[];
  if (doubleColonSplit.length === 2) {
    const left = parseGroups(doubleColonSplit[0]);
    const right = parseGroups(doubleColonSplit[1]);
    if (left === null || right === null) return null;
    const fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    groups = [...left, ...Array(fill).fill(0), ...right];
  } else {
    const single = parseGroups(addrPart);
    if (single === null || single.length !== 8) return null;
    groups = single;
  }

  const value = groups.reduce((acc, group) => (acc << 16n) | BigInt(group), 0n);
  return { value, bits: prefix };
}

function ipInCidr(ip: string, cidr: string): boolean {
  const v4 = parseIPv4(ip);
  const c4 = parseIPv4(cidr);
  if (v4 && c4) {
    if (c4.bits === 0) return true;
    const mask = c4.bits === 32 ? 0xffffffff : (0xffffffff << (32 - c4.bits)) >>> 0;
    return ((v4.value & mask) >>> 0) === ((c4.value & mask) >>> 0);
  }

  const v6 = parseIPv6(ip);
  const c6 = parseIPv6(cidr);
  if (v6 && c6) {
    if (c6.bits === 0) return true;
    const shift = BigInt(128 - c6.bits);
    return v6.value >> shift === c6.value >> shift;
  }
  return false;
}

/* ------------------------------------------------------------------ */
/* Atomic comparison                                                   */
/* ------------------------------------------------------------------ */

/**
 * Compares one policy value against one request value for a base operator.
 * Policy values carrying the NULL sentinel never positively match.
 */
function atomicMatch(op: ParsedOperatorWithCompare, policyValue: string, contextValue: string): boolean {
  if (policyValue === NULL_VALUE) return false;

  switch (op.family) {
    case 'string': {
      if (op.like) {
        return wildcardMatch(policyValue, contextValue, op.ignoreCase);
      }
      return op.ignoreCase
        ? policyValue.toLowerCase() === contextValue.toLowerCase()
        : policyValue === contextValue;
    }
    case 'numeric': {
      const a = toNumber(contextValue);
      const b = toNumber(policyValue);
      if (a === null || b === null) return false;
      return compareNumbers(a, b, op.compare ?? 'eq');
    }
    case 'date': {
      const a = toEpochMs(contextValue);
      const b = toEpochMs(policyValue);
      if (a === null || b === null) return false;
      return compareNumbers(a, b, op.compare ?? 'eq');
    }
    case 'bool': {
      const a = contextValue.toLowerCase();
      const b = policyValue.toLowerCase();
      return (a === 'true' || a === 'false') && a === b;
    }
    case 'binary':
      return policyValue === contextValue;
    case 'ip':
      return ipInCidr(contextValue, policyValue);
    case 'arn':
    case 'null':
      return arnMatch(policyValue, contextValue);
    default:
      return false;
  }
}

function normalizeConditionValues(value: ConditionValue): string[] {
  const list = Array.isArray(value) ? value : [value];
  return list.map((item) => toComparable(item));
}

export interface ConditionOperatorResult {
  outcome: Tri;
  note?: string;
  keyState: 'present' | 'absent' | 'unknown';
}

/**
 * Evaluates a single condition key/operator pair.
 *
 * @param policyRawValues Values from the policy (variables already resolved).
 * @param contextRawValues Request values, `null` when absent, `undefined` when unknown.
 */
export function evaluateOperator(
  parsed: ParsedOperator,
  policyRawValues: ConditionValue,
  contextRawValues: string[] | null | undefined,
): ConditionOperatorResult {
  const op = parsed as ParsedOperatorWithCompare;
  const policyValues = normalizeConditionValues(policyRawValues);

  if (parsed.family === 'null') {
    if (contextRawValues === undefined) {
      return { outcome: 'unknown', keyState: 'unknown', note: '条件键是否存在未知' };
    }
    const exists = contextRawValues !== null && contextRawValues.length > 0;
    // Null: "true" means the key is absent; "false" means present and non-null.
    const expectsAbsent = policyValues.some((v) => v.toLowerCase() === 'true');
    const expectsPresent = policyValues.some((v) => v.toLowerCase() === 'false');
    if (expectsAbsent && expectsPresent) return { outcome: 'match', keyState: exists ? 'present' : 'absent' };
    if (expectsAbsent) {
      return { outcome: exists ? 'no-match' : 'match', keyState: exists ? 'present' : 'absent' };
    }
    return { outcome: exists ? 'match' : 'no-match', keyState: exists ? 'present' : 'absent' };
  }

  const contextValues = contextRawValues;
  const keyState: 'present' | 'absent' | 'unknown' =
    contextValues === undefined ? 'unknown' : contextValues === null || contextValues.length === 0 ? 'absent' : 'present';

  if (keyState === 'unknown') {
    return {
      outcome: 'unknown',
      keyState,
      note: parsed.ifExists ? 'IfExists 需要知道键是否存在' : '条件键值未提供',
    };
  }

  if (keyState === 'absent') {
    if (parsed.ifExists) {
      return { outcome: 'match', keyState, note: '键不存在，IfExists 计为真' };
    }
    if (parsed.setOp === 'ForAllValues') {
      return { outcome: 'match', keyState, note: 'ForAllValues 对空集合恒为真' };
    }
    if (parsed.setOp === 'ForAnyValue') {
      return { outcome: 'no-match', keyState, note: 'ForAnyValue 对空集合为假' };
    }
    return {
      outcome: parsed.negated ? 'match' : 'no-match',
      keyState,
      note: parsed.negated ? '键不存在，否定型运算符计为真' : '键不存在，条件为假',
    };
  }

  // Null sentinel in policy values: negated operators match against null.
  if (policyValues.every((v) => v === NULL_VALUE)) {
    return {
      outcome: parsed.negated ? 'match' : 'no-match',
      keyState,
      note: '策略变量在请求上下文中无值（null）',
    };
  }

  const values = contextValues as string[];
  const positives = policyValues.filter((v) => v !== NULL_VALUE);

  const anyValueMatches = (value: string) => positives.some((p) => atomicMatch(op, p, value));
  const noneMatch = (value: string) => positives.every((p) => !atomicMatch(op, p, value));

  if (parsed.setOp === 'ForAllValues') {
    const ok = parsed.negated
      ? values.every((value) => noneMatch(value))
      : values.every((value) => anyValueMatches(value));
    return { outcome: ok ? 'match' : 'no-match', keyState };
  }

  if (parsed.setOp === 'ForAnyValue') {
    const ok = parsed.negated
      ? values.some((value) => noneMatch(value))
      : values.some((value) => anyValueMatches(value));
    return { outcome: ok ? 'match' : 'no-match', keyState };
  }

  // Plain (single-valued) operators applied to a possibly multi-valued key.
  if (parsed.negated) {
    return { outcome: values.every((value) => noneMatch(value)) ? 'match' : 'no-match', keyState };
  }
  return { outcome: values.some((value) => anyValueMatches(value)) ? 'match' : 'no-match', keyState };
}

/** Combines several tri-state results with logical AND. */
export function triAnd(values: Tri[]): Tri {
  if (values.some((v) => v === 'no-match')) return 'no-match';
  if (values.some((v) => v === 'unknown')) return 'unknown';
  return 'match';
}

/** Combines several tri-state results with logical OR. */
export function triOr(values: Tri[]): Tri {
  if (values.some((v) => v === 'match')) return 'match';
  if (values.some((v) => v === 'unknown')) return 'unknown';
  return 'no-match';
}

/** Inverts a tri-state result. */
export function triNot(value: Tri): Tri {
  if (value === 'match') return 'no-match';
  if (value === 'no-match') return 'match';
  return 'unknown';
}
