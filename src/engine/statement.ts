/**
 * Statement-level evaluation: action, resource, principal, and conditions.
 *
 * All four dimensions are evaluated independently to a tri-state result of
 * `match` / `no-match` / `unknown`. `unknown` only ever comes from condition
 * keys the analyzer was not told about (or from principal matching without an
 * identity), so it can be surfaced to the user as "需要补充条件键".
 */

import type {
  ConditionEvaluation,
  Effect,
  PolicyRecord,
  RequestContext,
  Statement,
  StatementEvaluation,
  Tri,
} from './types';
import { evaluateOperator, parseOperator, triAnd, triOr } from './conditions';
import { arnMatch, wildcardMatch } from './wildcard';
import { resolveVariables, NULL_VALUE, collectVariables } from './variables';
import type { PrincipalIdentity } from './identity';

export function asArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

/** Action matching is case-insensitive in AWS. */
export function actionMatches(patterns: string[], action: string): boolean {
  return patterns.some((pattern) => wildcardMatch(pattern, action, true));
}

export function resourceMatches(patterns: string[], resource: string): boolean {
  return patterns.some((pattern) => {
    if (pattern.includes(NULL_VALUE)) return false;
    return arnMatch(pattern, resource);
  });
}

/**
 * Matches a Principal element against an identity.
 *
 * Supported shapes: `"*"`, `{ "AWS": ... }`, `{ "Service": ... }`,
 * `{ "Federated": ... }`, `{ "CanonicalUser": ... }`. An account id or account
 * root ARN delegates to the whole account.
 */
export function principalMatches(principal: unknown, identity: PrincipalIdentity): Tri {
  if (principal === '*') return 'match';
  if (typeof principal === 'string') {
    return principal === '*' ? 'match' : matchesAwsPrincipal(principal, identity);
  }
  if (Array.isArray(principal)) {
    return triOr(principal.map((entry) => principalMatches(entry, identity)));
  }
  if (principal && typeof principal === 'object') {
    const spec = principal as Record<string, unknown>;
    const outcomes: Tri[] = [];
    for (const [kind, rawValue] of Object.entries(spec)) {
      const values = asArray(rawValue as string | string[]).map(String);
      if (kind === 'AWS') {
        for (const value of values) outcomes.push(matchesAwsPrincipal(value, identity));
      } else if (kind === 'Service') {
        outcomes.push(
          identity.servicePrincipal && values.some((v) => v === identity.servicePrincipal || v === '*')
            ? 'match'
            : 'no-match',
        );
      } else if (kind === 'Federated') {
        outcomes.push(
          identity.federatedProviders.some((provider) =>
            values.some((v) => wildcardMatch(v, provider)),
          )
            ? 'match'
            : 'no-match',
        );
      } else if (kind === 'CanonicalUser') {
        outcomes.push(
          identity.canonicalUserId && values.includes(identity.canonicalUserId) ? 'match' : 'no-match',
        );
      } else {
        outcomes.push('no-match');
      }
    }
    return outcomes.length ? triOr(outcomes) : 'no-match';
  }
  return 'no-match';
}

function matchesAwsPrincipal(value: string, identity: PrincipalIdentity): Tri {
  if (value === '*') return 'match';
  if (/^\d{12}$/.test(value)) return value === identity.accountId ? 'match' : 'no-match';

  const accountRoot = /^arn:aws[a-z-]*:iam::([^:]*):root$/.exec(value);
  if (accountRoot) {
    const pattern = accountRoot[1];
    if (pattern === identity.accountId) return 'match';
    if (pattern.includes('*')) return wildcardMatch(pattern, identity.accountId) ? 'match' : 'no-match';
    return 'no-match';
  }

  if (value === identity.arn) return 'match';
  if (identity.sessionArn && value === identity.sessionArn) return 'match';
  if (value.includes('*') || value.includes('?')) {
    return wildcardMatch(value, identity.arn) ? 'match' : 'no-match';
  }
  return 'no-match';
}

export interface StatementEvalOptions {
  policy: PolicyRecord;
  statement: Statement;
  statementIndex: number;
  context: RequestContext;
  identity?: PrincipalIdentity;
  /** When true, Principal/NotPrincipal elements are ignored (identity policies). */
  ignorePrincipal?: boolean;
}

interface PatternResolution {
  patterns: string[];
  unknowns: string[];
  substitutions: string[];
}

function resolvePatternList(
  raw: string | string[] | undefined,
  context: RequestContext,
): PatternResolution {
  const patterns: string[] = [];
  const unknowns: string[] = [];
  const substitutions: string[] = [];
  for (const entry of asArray(raw)) {
    const resolved = resolveVariables(entry, context.keys, context.missingKeys);
    patterns.push(resolved.text);
    if (resolved.hasUnknown) {
      unknowns.push(...collectVariables(entry).filter((key) => context.keys[key] === undefined));
    }
    substitutions.push(...resolved.substitutions);
  }
  return { patterns, unknowns: [...new Set(unknowns)], substitutions };
}

/** Evaluates a single statement. */
export function evaluateStatement(options: StatementEvalOptions): StatementEvaluation {
  const { policy, statement, statementIndex, context, identity, ignorePrincipal } = options;

  const issues: string[] = [];
  const effect: Effect = statement.Effect === 'Deny' ? 'Deny' : 'Allow';

  /* ---------------- actions ---------------- */
  let actionOutcome: Tri = 'no-match';
  let actionUnknownKeys: string[] = [];
  if (statement.Action !== undefined && statement.NotAction !== undefined) {
    issues.push('同时包含 Action 与 NotAction，语句无效');
  } else if (statement.NotAction !== undefined) {
    const resolved = resolvePatternList(statement.NotAction, context);
    actionUnknownKeys = resolved.unknowns;
    if (resolved.unknowns.length) actionOutcome = 'unknown';
    else actionOutcome = actionMatches(resolved.patterns, context.action) ? 'no-match' : 'match';
  } else if (statement.Action !== undefined) {
    const resolved = resolvePatternList(statement.Action, context);
    actionUnknownKeys = resolved.unknowns;
    if (resolved.unknowns.length) actionOutcome = 'unknown';
    else actionOutcome = actionMatches(resolved.patterns, context.action) ? 'match' : 'no-match';
  } else {
    issues.push('缺少 Action/NotAction');
  }

  /* ---------------- resources ---------------- */
  let resourceOutcome: Tri = 'no-match';
  let resourceUnknownKeys: string[] = [];
  if (statement.Resource !== undefined && statement.NotResource !== undefined) {
    issues.push('同时包含 Resource 与 NotResource，语句无效');
  } else if (statement.NotResource !== undefined) {
    const resolved = resolvePatternList(statement.NotResource, context);
    resourceUnknownKeys = resolved.unknowns;
    if (resolved.unknowns.length) resourceOutcome = 'unknown';
    else resourceOutcome = resourceMatches(resolved.patterns, context.resource) ? 'no-match' : 'match';
  } else if (statement.Resource !== undefined) {
    const resolved = resolvePatternList(statement.Resource, context);
    resourceUnknownKeys = resolved.unknowns;
    if (resolved.unknowns.length) resourceOutcome = 'unknown';
    else resourceOutcome = resourceMatches(resolved.patterns, context.resource) ? 'match' : 'no-match';
  } else if (policy.kind === 'resource' || policy.kind === 'trust') {
    // Resource/trust policies may omit Resource; it is the attached resource.
    resourceOutcome = 'match';
  } else {
    issues.push('缺少 Resource/NotResource');
  }

  /* ---------------- principal ---------------- */
  let principalOutcome: Tri = 'match';
  if (!ignorePrincipal && (policy.kind === 'resource' || policy.kind === 'trust')) {
    const hasPrincipal = statement.Principal !== undefined;
    const hasNotPrincipal = statement.NotPrincipal !== undefined;
    if (hasPrincipal && hasNotPrincipal) {
      principalOutcome = 'no-match';
      issues.push('同时包含 Principal 与 NotPrincipal');
    } else if (hasNotPrincipal) {
      if (!identity) {
        principalOutcome = 'unknown';
      } else {
        principalOutcome =
          principalMatches(statement.NotPrincipal, identity) === 'match' ? 'no-match' : 'match';
      }
    } else if (hasPrincipal) {
      principalOutcome = identity ? principalMatches(statement.Principal, identity) : 'unknown';
    } else {
      principalOutcome = 'no-match';
      issues.push('资源策略缺少 Principal');
    }
  }

  /* ---------------- conditions ---------------- */
  const conditions: ConditionEvaluation[] = [];
  const conditionUnknownKeys: string[] = [];
  if (statement.Condition) {
    for (const [rawOperator, block] of Object.entries(statement.Condition)) {
      const parsed = parseOperator(rawOperator);
      for (const [rawKey, rawValue] of Object.entries(block)) {
        const key = rawKey.trim();
        const rawValues = context.keys[key];
        // In "absent" mode an unsupplied key is treated as genuinely missing, so
        // the documented negated/IfExists semantics apply instead of "unknown".
        const contextValues = rawValues === undefined && context.missingKeys === 'absent' ? null : rawValues;

        if (!parsed) {
          conditions.push({
            operator: rawOperator,
            key,
            policyValues: asArray(rawValue as never),
            contextValues: contextValues ?? null,
            keyState:
              contextValues === undefined ? 'unknown' : contextValues && contextValues.length ? 'present' : 'absent',
            outcome: 'no-match',
            note: '不支持的条件运算符',
          });
          continue;
        }

        let policyValues = rawValue;
        const notes: string[] = [];
        const resolveValue = (value: unknown): string => {
          if (typeof value === 'string') {
            const resolved = resolveVariables(value, context.keys, context.missingKeys);
            if (resolved.substitutions.length) notes.push(...resolved.substitutions);
            for (const name of collectVariables(value)) {
              if (context.keys[name] === undefined) conditionUnknownKeys.push(name);
            }
            return resolved.text;
          }
          return String(value);
        };
        if (Array.isArray(rawValue)) policyValues = rawValue.map(resolveValue);
        else policyValues = resolveValue(rawValue);

        const result = evaluateOperator(parsed, policyValues, contextValues);
        if (result.keyState === 'unknown') conditionUnknownKeys.push(key);
        conditions.push({
          operator: rawOperator,
          key,
          policyValues: asArray(policyValues as never),
          contextValues: contextValues ?? null,
          keyState: result.keyState,
          outcome: result.outcome,
          note: [...new Set([...notes, result.note].filter(Boolean))].join('；') || undefined,
        });
      }
    }
  }

  const conditionOutcome: Tri = conditions.length ? triAnd(conditions.map((c) => c.outcome)) : 'match';

  let outcome: Tri = triAnd([actionOutcome, resourceOutcome, principalOutcome, conditionOutcome]);
  if (issues.length) outcome = 'no-match';

  const evaluation: StatementEvaluation = {
    policyId: policy.id,
    policyName: policy.name,
    policyKind: policy.kind,
    statementIndex,
    sid: statement.Sid ?? null,
    effect,
    actionOutcome,
    resourceOutcome,
    principalOutcome,
    conditions,
    conditionOutcome,
    outcome,
    issue: issues.length ? issues.join('；') : undefined,
  };
  // Keys whose absence made this statement undecidable. Only report them when
  // the statement's other dimensions also apply — otherwise the key is
  // irrelevant to the request (e.g. a policy for a different bucket).
  const otherDimensionsApply = triAnd([actionOutcome, resourceOutcome, principalOutcome]) !== 'no-match';
  (evaluation as StatementEvaluation & { unknownKeys?: string[] }).unknownKeys = otherDimensionsApply
    ? [...new Set([...actionUnknownKeys, ...resourceUnknownKeys, ...conditionUnknownKeys])]
    : [];
  return evaluation;
}

/** Keys a statement's result depends on that were unknown. */
export function unknownKeysOf(evaluation: StatementEvaluation): string[] {
  return (evaluation as StatementEvaluation & { unknownKeys?: string[] }).unknownKeys ?? [];
}

/** Evaluates every statement of a policy document. */
export function evaluatePolicy(
  policy: PolicyRecord,
  context: RequestContext,
  identity?: PrincipalIdentity,
  ignorePrincipal = true,
): StatementEvaluation[] {
  return asArray(policy.document.Statement).map((statement, index) =>
    evaluateStatement({
      policy,
      statement,
      statementIndex: index,
      context,
      identity,
      ignorePrincipal,
    }),
  );
}

