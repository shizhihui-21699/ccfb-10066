/**
 * Policy variable expansion.
 *
 * `2012-10-17` policies support `${aws:username}` style variables. A variable
 * whose key has no value resolves to a null sentinel which never matches a
 * resource/action/condition value. `${*}`, `${?}` and `${$}` produce literal
 * characters that must not act as wildcards.
 */

import type { ConditionKeyContext } from './types';
import { escapeLiteral } from './wildcard';

/** Sentinel representing an unresolved (null) policy variable. */
export const NULL_VALUE = '\u0000';

export interface VariableResolution {
  /** Resolved text, which may contain NULL_VALUE for unresolved variables. */
  text: string;
  /** Whether any variable in the input could not be resolved to a value. */
  hasNull: boolean;
  /** True when a null came from a key that is simply unknown to the analyzer. */
  hasUnknown: boolean;
  /**
   * True when the null is a definitive "no value in this request" — either the
   * key was declared absent, or it is multi-valued (invalid as a variable).
   */
  hasDefiniteNull: boolean;
  /** Human-readable descriptions of substitutions, for the reason chain. */
  substitutions: string[];
}

const VARIABLE_PATTERN = /\$\{([^}]*)\}/g;

/**
 * Aliases let users write `${username}` or `${aws:username}`. Keys with a
 * slash (`PrincipalTag/team`) map onto themselves.
 */
export const VARIABLE_ALIASES: Record<string, string> = {
  username: 'aws:username',
  'aws:username': 'aws:username',
  'aws:userid': 'aws:userid',
  PrincipalArn: 'aws:PrincipalArn',
  'aws:PrincipalArn': 'aws:PrincipalArn',
  'aws:PrincipalAccount': 'aws:PrincipalAccount',
  'aws:PrincipalTag/team': 'aws:PrincipalTag/team',
  SourceIp: 'aws:SourceIp',
  'aws:SourceIp': 'aws:SourceIp',
  CurrentTime: 'aws:CurrentTime',
  'aws:CurrentTime': 'aws:CurrentTime',
  EpochTime: 'aws:EpochTime',
  'aws:SecureTransport': 'aws:SecureTransport',
};

export function canonicalVariableKey(name: string): string {
  if (VARIABLE_ALIASES[name]) return VARIABLE_ALIASES[name];
  // AWS variable names are always prefixed with the service (`aws:username`).
  // Accept the bare form as a convenience alias.
  if (!name.includes(':')) return `aws:${name}`;
  return name;
}

/**
 * Resolves all `${...}` variables in `input`.
 *
 * @param keys Request context keys. Only single-valued keys can back a variable.
 * @param missingKeys How to treat keys absent from `keys`.
 */
export function resolveVariables(
  input: string,
  keys: ConditionKeyContext,
  missingKeys: 'unknown' | 'absent',
): VariableResolution {
  const substitutions: string[] = [];
  let hasNull = false;
  let hasUnknown = false;
  let hasDefiniteNull = false;

  const text = input.replace(VARIABLE_PATTERN, (_match, rawName: string) => {
    const name = rawName.trim();

    if (name === '*') return escapeLiteral('*');
    if (name === '?') return escapeLiteral('?');
    if (name === '$') return '$';

    const keyName = canonicalVariableKey(name);
    const values = keys[keyName];

    if (values === undefined) {
      hasNull = true;
      if (missingKeys === 'unknown') {
        hasUnknown = true;
        substitutions.push(`\${${name}} → 键 ${keyName} 未提供`);
      } else {
        hasDefiniteNull = true;
        substitutions.push(`\${${name}} → null（键不存在）`);
      }
      return NULL_VALUE;
    }

    if (values.length === 0) {
      hasNull = true;
      hasDefiniteNull = true;
      substitutions.push(`\${${name}} → null（键无值）`);
      return NULL_VALUE;
    }

    if (values.length > 1) {
      hasNull = true;
      hasDefiniteNull = true;
      substitutions.push(`\${${name}} → null（多值键不可用作变量）`);
      return NULL_VALUE;
    }

    substitutions.push(`\${${name}} → ${values[0]}`);
    return escapeLiteral(values[0]);
  });

  return { text, hasNull, hasUnknown, hasDefiniteNull, substitutions };
}

/** Lists the variable names referenced by a template (canonicalized). */
export function collectVariables(input: string): string[] {
  const names: string[] = [];
  for (const match of input.matchAll(VARIABLE_PATTERN)) {
    const name = match[1].trim();
    if (name === '*' || name === '?' || name === '$') continue;
    names.push(canonicalVariableKey(name));
  }
  return names;
}

