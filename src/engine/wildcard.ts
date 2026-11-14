/**
 * Wildcard matching primitives.
 *
 * IAM uses `*` (any sequence) and `?` (single character). Two sentinel
 * characters let substituted policy-variable text carry literal `*`/`?`
 * without widening the pattern.
 */

/** Sentinel that matches a literal `*` after policy-variable substitution. */
export const LITERAL_STAR = '\u0001';
/** Sentinel that matches a literal `?` after policy-variable substitution. */
export const LITERAL_QUESTION = '\u0002';

function escapeRegExp(char: string): string {
  return /[.*+?^${}()|[\]\\]/.test(char) ? `\\${char}` : char;
}

const patternCache = new Map<string, RegExp>();

/** Compiles an IAM wildcard pattern into an anchored RegExp. */
export function compileWildcard(pattern: string, caseInsensitive = false): RegExp {
  const cacheKey = `${caseInsensitive ? 'i' : 's'}:${pattern}`;
  const cached = patternCache.get(cacheKey);
  if (cached) return cached;

  let source = '';
  for (const char of pattern) {
    if (char === '*') source += '.*';
    else if (char === '?') source += '.';
    else if (char === LITERAL_STAR) source += '\\*';
    else if (char === LITERAL_QUESTION) source += '\\?';
    else source += escapeRegExp(char);
  }
  const regex = new RegExp(`^${source}$`, caseInsensitive ? 'is' : 's');
  // Bound the cache so imports of huge datasets don't grow unbounded.
  if (patternCache.size > 5000) patternCache.clear();
  patternCache.set(cacheKey, regex);
  return regex;
}

/** Tests `value` against an IAM wildcard `pattern`. */
export function wildcardMatch(
  pattern: string,
  value: string,
  caseInsensitive = false,
): boolean {
  return compileWildcard(pattern, caseInsensitive).test(value);
}

/**
 * Matches an ARN against a pattern.
 *
 * AWS checks the six colon-delimited ARN components separately, so a wildcard
 * in the account field does not spill across into the resource portion. When
 * either side isn't a well-formed six-part ARN we fall back to whole-string
 * matching.
 */
export function arnMatch(pattern: string, value: string): boolean {
  const pParts = pattern.split(':');
  const vParts = value.split(':');
  if (pParts.length === 6 && vParts.length === 6) {
    return pParts.every((part, idx) => wildcardMatch(part, vParts[idx]));
  }
  return wildcardMatch(pattern, value);
}

/** Escapes a literal string so it can be embedded in a pattern. */
export function escapeLiteral(text: string): string {
  return text.replace(/\*/g, LITERAL_STAR).replace(/\?/g, LITERAL_QUESTION);
}

