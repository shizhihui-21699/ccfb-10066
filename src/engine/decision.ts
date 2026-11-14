/**
 * Decision engine.
 *
 * Composes statement-level results into an authorization decision following the
 * AWS evaluation model:
 *
 *  - an explicit Deny in any applicable policy wins;
 *  - identity-based grants are intersected with the permissions boundary and,
 *    per level, with SCPs;
 *  - resource-based grants can stand alone within an account, but are still
 *    subject to SCPs; permissions boundaries do not implicitly limit grants to
 *    an IAM user ARN or a role-session ARN, though explicit denies still do;
 *  - an SCP level with no matching Allow blocks the request (deny-by-default).
 */

import type {
  Dataset,
  Decision,
  Evidence,
  PolicyRecord,
  PrincipalRef,
  ReasonStep,
  RequestContext,
  StatementEvaluation,
  Tri,
  Verdict,
  WhoCanResult,
} from './types';
import { evaluatePolicy, unknownKeysOf } from './statement';
import { buildContext, identityForRole, identityForUser, type PrincipalIdentity } from './identity';
import { wildcardMatch } from './wildcard';

/* ------------------------------------------------------------------ */
/* Policy collection                                                   */
/* ------------------------------------------------------------------ */

export function policyById(dataset: Dataset, id: string | null | undefined): PolicyRecord | null {
  if (!id) return null;
  return dataset.policies.find((policy) => policy.id === id) ?? null;
}

interface IdentityPolicies {
  policies: PolicyRecord[];
  /** Policy ids paired with the attachment path, for the reason chain. */
  via: Map<string, string>;
}

/** Identity-based policies attached to a principal, directly or via groups. */
export function collectIdentityPolicies(dataset: Dataset, principal: PrincipalRef): IdentityPolicies {
  const policies: PolicyRecord[] = [];
  const via = new Map<string, string>();

  const add = (id: string | null | undefined, source: string) => {
    const policy = policyById(dataset, id);
    if (!policy) return;
    if (policies.some((existing) => existing.id === policy.id)) return;
    policies.push(policy);
    via.set(policy.id, source);
  };

  if (principal.type === 'user') {
    const user = dataset.users.find((u) => u.id === principal.id);
    if (!user) return { policies, via };
    user.managedPolicyIds.forEach((id) => add(id, `用户 ${user.name} 的托管策略`));
    user.inlinePolicyIds.forEach((id) => add(id, `用户 ${user.name} 的内联策略`));
    for (const group of dataset.groups.filter((g) => user.groupIds.includes(g.id))) {
      group.managedPolicyIds.forEach((id) => add(id, `组 ${group.name} 的托管策略`));
      group.inlinePolicyIds.forEach((id) => add(id, `组 ${group.name} 的内联策略`));
    }
  } else {
    const role = dataset.roles.find((r) => r.id === principal.id);
    if (!role) return { policies, via };
    role.managedPolicyIds.forEach((id) => add(id, `角色 ${role.name} 的托管策略`));
    role.inlinePolicyIds.forEach((id) => add(id, `角色 ${role.name} 的内联策略`));
  }

  return { policies, via };
}

export function boundaryFor(dataset: Dataset, principal: PrincipalRef): PolicyRecord | null {
  if (principal.type === 'user') {
    return policyById(dataset, dataset.users.find((u) => u.id === principal.id)?.boundaryPolicyId);
  }
  return policyById(dataset, dataset.roles.find((r) => r.id === principal.id)?.boundaryPolicyId);
}

export interface ScpLevel {
  levelName: string;
  policies: PolicyRecord[];
}

/** SCP levels from the org root down to the account. */
export function scpLevelsFor(dataset: Dataset, accountId: string): ScpLevel[] {
  const account = dataset.accounts.find((a) => a.id === accountId);
  if (!account) return [];

  const units: { levelName: string; scpPolicyIds: string[] }[] = [];
  let unit = dataset.orgUnits.find((u) => u.id === account.orgUnitId);
  const seen = new Set<string>();
  while (unit && !seen.has(unit.id)) {
    seen.add(unit.id);
    units.push({ levelName: `OU ${unit.name}`, scpPolicyIds: unit.scpPolicyIds });
    const parentId: string | null = unit.parentId;
    unit = parentId ? dataset.orgUnits.find((u) => u.id === parentId) : undefined;
  }
  units.reverse();
  units.push({ levelName: `账号 ${account.name}`, scpPolicyIds: account.scpPolicyIds });

  return units.map((level) => ({
    levelName: level.levelName,
    policies: level.scpPolicyIds
      .map((id) => policyById(dataset, id))
      .filter((policy): policy is PolicyRecord => Boolean(policy)),
  }));
}

/**
 * Whether a resource-policy attachment covers the request resource.
 *
 * A policy attached to an S3 bucket ARN applies to the bucket *and* every object
 * inside it, so `arn:aws:s3:::bucket` covers `arn:aws:s3:::bucket/key`. Other
 * resource types attach to the exact ARN (wildcards allowed by the analyzer).
 */
function attachmentCovers(pattern: string, resource: string): boolean {
  if (wildcardMatch(pattern, resource)) return true;
  if (pattern.startsWith('arn:aws:s3:::') && !pattern.slice('arn:aws:s3:::'.length).includes('/')) {
    return resource.startsWith(`${pattern}/`);
  }
  return false;
}

/**
 * Role trust policies act as resource policies on the role ARN for
 * `sts:AssumeRole`. Unlike ordinary same-account resource policies, assuming a
 * role requires *both* an identity-based allow for `sts:AssumeRole` and a trust
 * policy that admits the caller.
 */
export function trustPolicyFor(dataset: Dataset, action: string, resource: string): PolicyRecord | null {
  if (!/^sts:assumerole/i.test(action)) return null;
  const role = dataset.roles.find((candidate) => candidate.arn === resource);
  return role ? policyById(dataset, role.trustPolicyId) : null;
}

/** Resource policies attached to a resource ARN. */
export function resourcePoliciesFor(dataset: Dataset, resource: string): PolicyRecord[] {
  const policies: PolicyRecord[] = [];
  for (const attachment of dataset.resourcePolicies) {
    const attached = attachment.resourceArns.some((pattern) => attachmentCovers(pattern, resource));
    if (!attached) continue;
    const policy = policyById(dataset, attachment.policyId);
    if (policy && !policies.some((existing) => existing.id === policy.id)) policies.push(policy);
  }
  return policies;
}

/**
 * Best-effort account owning a resource.
 *
 * ARNs for most services carry the account in field 4. S3 ARNs do not, so fall
 * back to the dataset's resource registry (exact ARN, then bucket prefix).
 */
export function resourceAccountFor(dataset: Dataset, resource: string): string | null {
  const parts = resource.split(':');
  if (parts.length >= 6 && parts[4]) return parts[4];

  const exact = dataset.resources?.find((entry) => entry.arn === resource);
  if (exact) return exact.accountId;

  const bucket = /^arn:aws:s3:::([^/]+)/.exec(resource);
  if (bucket) {
    const match = dataset.resources?.find((entry) => entry.type === 'bucket' && entry.arn === `arn:aws:s3:::${bucket[1]}`);
    if (match) return match.accountId;
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function statementLabel(evaluation: StatementEvaluation): string {
  return evaluation.sid ? `Sid ${evaluation.sid}` : `语句 #${evaluation.statementIndex + 1}`;
}

function triMark(tri: Tri): string {
  return tri === 'match' ? '✓' : tri === 'unknown' ? '?' : '✗';
}

function evidenceFor(evaluation: StatementEvaluation, via?: string): Evidence {
  return {
    policyId: evaluation.policyId,
    policyName: evaluation.policyName,
    policyKind: evaluation.policyKind,
    statementIndex: evaluation.statementIndex,
    sid: evaluation.sid,
    label: `${statementLabel(evaluation)} · ${evaluation.effect}`,
    detail: `Action ${triMark(evaluation.actionOutcome)} · Resource ${triMark(
      evaluation.resourceOutcome,
    )} · Condition ${triMark(evaluation.conditionOutcome)}${via ? ` · ${via}` : ''}`,
  };
}

function identityFor(principal: PrincipalRef): PrincipalIdentity {
  if (principal.type === 'user') {
    return identityForUser({
      id: principal.id,
      name: principal.name,
      arn: principal.arn,
      accountId: principal.accountId,
      groupIds: [],
      managedPolicyIds: [],
      inlinePolicyIds: [],
      boundaryPolicyId: null,
      tags: principal.tags,
    });
  }
  return identityForRole({
    id: principal.id,
    name: principal.name,
    arn: principal.arn,
    accountId: principal.accountId,
    trustPolicyId: '',
    managedPolicyIds: [],
    inlinePolicyIds: [],
    boundaryPolicyId: null,
    tags: principal.tags,
  });
}

/**
 * Whether a resource policy grant reaches the principal through an ARN that
 * boundaries do not implicitly limit.
 *
 * Per the IAM docs, resource-based grants to a same-account IAM *user* ARN or a
 * *role-session* ARN are not limited by an implicit deny in the boundary. A
 * grant that names the role ARN itself, or that delegates to the account root,
 * still is. Explicit denies apply in every case.
 */
function resourceGrantExemptFromBoundary(
  evaluations: StatementEvaluation[],
  dataset: Dataset,
  principal: PrincipalRef,
  sameAccount: boolean,
): boolean {
  if (!sameAccount) return false;
  const role = principal.type === 'role'
    ? dataset.roles.find((candidate) => candidate.id === principal.id)
    : undefined;
  const sessionPrefix = role ? `arn:aws:sts::${role.accountId}:assumed-role/` : null;
  const sessionPath = role ? `${sessionPrefix}${role.arn.split('/').slice(1).join('/')}/` : null;

  return evaluations.some((evaluation) => {
    if (evaluation.outcome !== 'match' || evaluation.effect !== 'Allow') return false;
    const policy = policyById(dataset, evaluation.policyId);
    if (!policy) return false;
    const statements = Array.isArray(policy.document.Statement)
      ? policy.document.Statement
      : [policy.document.Statement];
    const statement = statements[evaluation.statementIndex];
    if (!statement?.Principal) return false;
    const serialized = JSON.stringify(statement.Principal);

    if (principal.type === 'user') {
      // A grant naming this user's ARN directly, or the account root (delegation)
      // — for an account-root delegation AWS still requires the identity policy,
      // so only a direct user-ARN grant is boundary-exempt.
      return serialized.includes(principal.arn);
    }
    if (!sessionPrefix || !sessionPath) return false;
    return serialized.includes(sessionPrefix) || serialized.includes(sessionPath.slice(0, -1));
  });
}

function collectUnknownKeys(evaluations: StatementEvaluation[]): string[] {
  const keys = new Set<string>();
  for (const evaluation of evaluations) {
    if (evaluation.outcome !== 'unknown') continue;
    unknownKeysOf(evaluation).forEach((key) => keys.add(key));
  }
  return [...keys];
}

/* ------------------------------------------------------------------ */
/* Core decision                                                       */
/* ------------------------------------------------------------------ */

export interface DecideOptions {
  dataset: Dataset;
  principal: PrincipalRef;
  action: string;
  resource: string;
  /** Explicitly supplied condition keys. */
  keys?: Record<string, string | string[]>;
  /** Treat unsupplied keys as absent instead of unknown. */
  missingKeys?: 'unknown' | 'absent';
  resourceTags?: Record<string, string>;
  requestTags?: Record<string, string>;
}

/** Evaluates whether `principal` can perform `action` on `resource`. */
export function decide(options: DecideOptions): Decision {
  const { dataset, principal, action, resource } = options;

  const baseKeys: Record<string, string[]> = {};
  for (const [key, value] of Object.entries(options.keys ?? {})) {
    baseKeys[key] = Array.isArray(value) ? value : [value];
  }

  const context: RequestContext = buildContext(
    {
      action,
      resource,
      keys: baseKeys,
      missingKeys: options.missingKeys ?? 'unknown',
    },
    identityFor(principal),
    options.resourceTags,
    options.requestTags,
  );

  const identity = identityFor(principal);
  const identityPolicies = collectIdentityPolicies(dataset, principal);
  const boundary = boundaryFor(dataset, principal);
  const scpLevels = scpLevelsFor(dataset, principal.accountId);
  const trustPolicy = trustPolicyFor(dataset, action, resource);
  const resourcePolicies = [
    ...resourcePoliciesFor(dataset, resource),
    ...(trustPolicy ? [trustPolicy] : []),
  ];
  const resourceAccount = resourceAccountFor(dataset, resource);
  const crossAccount = resourceAccount !== null && resourceAccount !== principal.accountId;

  const steps: ReasonStep[] = [];

  /* 1. Request context */
  const keySummary = Object.entries(context.keys)
    .map(([key, values]) => `${key}=${values.length ? values.join(',') : '(null)'}`)
    .join('；');
  steps.push({
    id: 'context',
    title: '请求上下文',
    outcome: 'info',
    detail: `Action=${action}；Resource=${resource}${keySummary ? `；条件键：${keySummary}` : ''}`,
  });

  /* 2. Identity policy statements */
  const identityEvaluations = identityPolicies.policies.flatMap((policy) =>
    evaluatePolicy(policy, context, identity, true),
  );
  const identityAllows = identityEvaluations.filter((e) => e.effect === 'Allow' && e.outcome === 'match');
  const identityUnknownAllows = identityEvaluations.filter((e) => e.effect === 'Allow' && e.outcome === 'unknown');
  const identityDenies = identityEvaluations.filter((e) => e.effect === 'Deny' && e.outcome === 'match');
  const identityUnknownDenies = identityEvaluations.filter((e) => e.effect === 'Deny' && e.outcome === 'unknown');

  steps.push({
    id: 'identity',
    title: '身份策略（用户 / 组 / 角色所附）',
    outcome: identityAllows.length ? 'match' : identityUnknownAllows.length ? 'unknown' : 'no-match',
    detail: `共评估 ${identityEvaluations.length} 条语句：允许命中 ${identityAllows.length} 条，拒绝命中 ${identityDenies.length} 条${
      identityUnknownAllows.length || identityUnknownDenies.length
        ? `，结果不确定 ${identityUnknownAllows.length + identityUnknownDenies.length} 条`
        : ''
    }`,
    evidence: [...identityAllows, ...identityDenies].map((evaluation) =>
      evidenceFor(evaluation, identityPolicies.via.get(evaluation.policyId)),
    ),
  });

  /* 3. Permissions boundary */
  let boundaryOutcome: Tri = 'match';
  let boundaryAllowMatched = false;
  let boundaryUnknown = false;
  let boundaryDeny: StatementEvaluation[] = [];
  let boundaryEvaluations: StatementEvaluation[] = [];
  if (boundary) {
    boundaryEvaluations = evaluatePolicy(boundary, context, identity, true);
    boundaryAllowMatched = boundaryEvaluations.some((e) => e.effect === 'Allow' && e.outcome === 'match');
    boundaryUnknown = boundaryEvaluations.some((e) => e.outcome === 'unknown');
    boundaryDeny = boundaryEvaluations.filter((e) => e.effect === 'Deny' && e.outcome === 'match');
    boundaryOutcome = boundaryAllowMatched ? 'match' : boundaryUnknown ? 'unknown' : 'no-match';
    steps.push({
      id: 'boundary',
      title: `权限边界：${boundary.name}`,
      outcome: boundaryDeny.length ? 'no-match' : boundaryOutcome,
      detail: boundaryDeny.length
        ? '边界中存在显式拒绝'
        : boundaryAllowMatched
          ? '边界允许该操作，不与身份策略收缩'
          : boundaryUnknown
            ? '边界评估结果不确定（缺少条件键）'
            : '边界不包含允许该操作的语句 → 权限被收缩为隐式拒绝',
      evidence: boundaryEvaluations.filter((e) => e.outcome !== 'no-match').map((e) => evidenceFor(e)),
    });
  } else {
    steps.push({
      id: 'boundary',
      title: '权限边界',
      outcome: 'info',
      detail: '该身份未设置权限边界，不受边界约束',
    });
  }

  /* 4. SCP levels */
  const scpLevelResults: { levelName: string; outcome: Tri; policyIds: string[] }[] = [];
  const scpDenyEvidence: Evidence[] = [];
  const scpEvaluations: StatementEvaluation[] = [];
  let scpBlocked = false;
  let scpUnknown = false;
  let scpDenied = false;
  for (const level of scpLevels) {
    const evaluations = level.policies.flatMap((policy) => evaluatePolicy(policy, context, identity, true));
    scpEvaluations.push(...evaluations);
    const denies = evaluations.filter((e) => e.effect === 'Deny' && e.outcome === 'match');
    const allows = evaluations.filter((e) => e.effect === 'Allow' && e.outcome === 'match');
    const unknown = evaluations.some((e) => e.outcome === 'unknown');
    if (unknown) scpUnknown = true;
    let outcome: Tri;
    if (denies.length) {
      outcome = 'no-match';
      scpDenied = true;
      scpDenyEvidence.push(...denies.map((e) => evidenceFor(e)));
    } else if (!level.policies.length) {
      // Every level needs an explicit Allow. A level with no SCP attached cannot
      // supply one, so treat it as blocking (the default FullAWSAccess policy is
      // what normally prevents this).
      outcome = 'no-match';
      scpBlocked = true;
    } else if (allows.length) {
      outcome = 'match';
    } else if (unknown) {
      outcome = 'unknown';
    } else {
      outcome = 'no-match';
      scpBlocked = true;
    }
    scpLevelResults.push({
      levelName: level.levelName,
      outcome,
      policyIds: level.policies.map((policy) => policy.id),
    });
  }

  if (scpLevels.length) {
    steps.push({
      id: 'scp',
      title: '组织级策略（SCP，逐层要求显式 Allow）',
      outcome: scpDenied || scpBlocked ? 'no-match' : scpUnknown ? 'unknown' : 'match',
      detail: scpLevels
        .map((level, idx) => {
          const result = scpLevelResults[idx];
          const label =
            result.outcome === 'match' ? '允许' : result.outcome === 'no-match' ? '阻止' : '此层无策略（继承上层）';
          return `${level.levelName}：${label}`;
        })
        .join('；'),
      evidence: scpDenyEvidence,
    });
  } else {
    steps.push({
      id: 'scp',
      title: '组织级策略（SCP）',
      outcome: 'info',
      detail: '账号未加入组织或未找到 SCP 层级',
    });
  }

  /* 5. Resource policies */
  const resourceEvaluations = resourcePolicies.flatMap((policy) =>
    evaluatePolicy(policy, context, identity, false),
  );
  const resourceAllows = resourceEvaluations.filter((e) => e.effect === 'Allow' && e.outcome === 'match');
  const resourceUnknownAllows = resourceEvaluations.filter(
    (e) => e.effect === 'Allow' && e.outcome === 'unknown',
  );
  const resourceDenies = resourceEvaluations.filter((e) => e.effect === 'Deny' && e.outcome === 'match');
  const resourceUnknownDenies = resourceEvaluations.filter(
    (e) => e.effect === 'Deny' && e.outcome === 'unknown',
  );
  const resourceExempt = resourceGrantExemptFromBoundary(
    resourceEvaluations.filter((evaluation) => evaluation.policyId !== trustPolicy?.id),
    dataset,
    principal,
    !crossAccount,
  );

  if (resourcePolicies.length) {
    steps.push({
      id: 'resource',
      title: '资源策略',
      outcome: resourceAllows.length ? 'match' : resourceUnknownAllows.length ? 'unknown' : 'no-match',
      detail: resourceAllows.length
        ? `资源策略直接授权（${resourceExempt ? '同账号用户/会话 ARN 授权，不受权限边界隐式拒绝限制' : '仍受权限边界约束'}）`
        : `已检查 ${resourcePolicies.length} 个资源策略，未发现允许语句`,
      evidence: [...resourceAllows, ...resourceDenies].map((e) => evidenceFor(e)),
    });
  }

  /* 6. Deny override */
  const denyEvidence = [
    ...identityDenies.map((e) => evidenceFor(e)),
    ...boundaryDeny.map((e) => evidenceFor(e)),
    ...resourceDenies.map((e) => evidenceFor(e)),
    ...scpDenyEvidence,
  ];
  const hasUnknownDeny = identityUnknownDenies.length > 0 || resourceUnknownDenies.length > 0;

  steps.push({
    id: 'deny',
    title: '显式拒绝优先检查',
    outcome: denyEvidence.length ? 'no-match' : hasUnknownDeny ? 'unknown' : 'info',
    detail: denyEvidence.length
      ? `发现 ${denyEvidence.length} 条显式拒绝，直接拒绝`
      : hasUnknownDeny
        ? '存在因缺少条件键而无法判定的拒绝语句，结论最多为“无法确定”'
        : '未发现显式拒绝',
    evidence: denyEvidence,
  });

  /* 7. Allow composition */
  const scpBlocks = scpBlocked || scpDenied;
  const identityPathAllowed =
    identityAllows.length > 0 && boundaryOutcome === 'match' && !scpBlocks;
  // Same-account resource grants stand alone; cross-account grants additionally
  // require an identity-based allow in the caller's account (documented rule).
  const identityPathEffective = identityAllows.length > 0 && boundaryOutcome === 'match';
  // Cross-account resource grants need a same-account identity allow, and so do
  // AssumeRole grants even within one account.
  const resourceNeedsIdentity = crossAccount || trustPolicy !== null;
  const resourcePathAllowed =
    resourceAllows.length > 0 &&
    (!resourceNeedsIdentity || identityPathEffective) &&
    (resourceExempt || boundaryOutcome === 'match') &&
    !scpBlocks;
  const effectiveAllow = identityPathAllowed || resourcePathAllowed;

  const identityPathUnknown =
    identityUnknownAllows.length > 0 ||
    (identityAllows.length > 0 && boundaryOutcome === 'unknown');
  const resourcePathUnknown =
    resourceUnknownAllows.length > 0 ||
    (resourceAllows.length > 0 && !resourceExempt && boundaryOutcome === 'unknown');
  const allowUnknown = identityPathUnknown || resourcePathUnknown || scpUnknown;

  // A confirmed allow cannot stand while some applicable deny statement is
  // undecidable, or while an SCP level's allow cannot be confirmed.
  const allowConfirmed = effectiveAllow && !hasUnknownDeny && !scpUnknown;

  let verdict: Verdict;
  if (denyEvidence.length) verdict = 'Deny';
  else if (allowConfirmed) verdict = 'Allow';
  else if (effectiveAllow || allowUnknown || hasUnknownDeny) verdict = 'Maybe';
  else verdict = 'ImplicitDeny';

  const missingKeys = [
    ...new Set([
      ...collectUnknownKeys(identityEvaluations),
      ...collectUnknownKeys(boundaryEvaluations),
      ...collectUnknownKeys(resourceEvaluations),
      ...collectUnknownKeys(scpEvaluations),
    ]),
  ];

  steps.push({
    id: 'compose',
    title: '授权组合（交集 / 并集）',
    outcome: effectiveAllow ? 'match' : allowUnknown ? 'unknown' : 'no-match',
    detail: [
      `身份策略路径：${
        identityPathAllowed ? '通过' : identityAllows.length ? '被边界或 SCP 收缩' : identityUnknownAllows.length ? '不确定' : '无允许'
      }`,
      `资源策略路径：${
        resourcePathAllowed
          ? '通过'
          : resourceAllows.length
            ? resourceNeedsIdentity && !identityPathEffective
              ? trustPolicy
                ? '信任策略已匹配，但缺少身份策略的 sts:AssumeRole 允许'
                : '跨账号还需要身份策略允许'
              : '被边界或 SCP 收缩'
            : resourceUnknownAllows.length
              ? '不确定'
              : '无允许'
      }`,
      `SCP：${scpBlocks ? '阻止' : scpUnknown ? '不确定' : '允许'}`,
    ].join('；'),
  });

  const summary = buildSummary(
    verdict,
    identityPathAllowed,
    resourcePathAllowed,
    denyEvidence,
    missingKeys,
    resourceNeedsIdentity && resourceAllows.length > 0 && !identityPathEffective,
    trustPolicy !== null,
  );

  steps.push({
    id: 'verdict',
    title: '最终结论',
    outcome:
      verdict === 'Allow' ? 'match' : verdict === 'Deny' ? 'no-match' : verdict === 'Maybe' ? 'unknown' : 'no-match',
    detail: summary,
  });

  return {
    verdict,
    summary,
    allowEvidence: [
      ...(identityPathAllowed ? identityAllows.map((e) => evidenceFor(e)) : []),
      ...(resourcePathAllowed ? resourceAllows.map((e) => evidenceFor(e)) : []),
    ],
    denyEvidence,
    missingKeys,
    steps,
    statements: [
      ...identityEvaluations,
      ...boundaryEvaluations,
      ...scpEvaluations,
      ...resourceEvaluations,
    ],
    resourcePolicyIds: resourcePolicies.map((policy) => policy.id),
    scpLevels: scpLevelResults,
    boundary: boundary
      ? { policyId: boundary.id, policyName: boundary.name, outcome: boundaryOutcome }
      : null,
  };
}

function buildSummary(
  verdict: Verdict,
  identityPath: boolean,
  resourcePath: boolean,
  denyEvidence: Evidence[],
  missingKeys: string[],
  crossAccountNeedsIdentity: boolean,
  isAssumeRole: boolean,
): string {
  switch (verdict) {
    case 'Allow':
      return identityPath && resourcePath
        ? '允许：身份策略与资源策略均授予该操作'
        : identityPath
          ? '允许：身份策略授予该操作，且未被权限边界或组织级策略阻止'
          : '允许：资源策略直接授予该操作';
    case 'Deny':
      return `拒绝：命中 ${denyEvidence.length} 条显式拒绝语句（${denyEvidence
        .map((e) => `${e.policyName} / ${e.label}`)
        .slice(0, 3)
        .join('、')}${denyEvidence.length > 3 ? ' 等' : ''}）`;
    case 'Maybe':
      return missingKeys.length
        ? `无法确定：需要补充条件键 ${missingKeys.join('、')}`
        : '无法确定：存在结果取决于未提供上下文的条件或拒绝语句';
    case 'ImplicitDeny':
    default:
      if (crossAccountNeedsIdentity && isAssumeRole) {
        return '隐式拒绝：信任策略已允许，但 AssumeRole 还要求调用方身份策略允许 sts:AssumeRole';
      }
      if (crossAccountNeedsIdentity) {
        return '隐式拒绝：资源策略已允许，但跨账号访问还要求调用方账号的身份策略同样允许该操作';
      }
      return '隐式拒绝：没有任何策略明确允许该操作，或允许被权限边界 / SCP 收缩';
  }
}

/* ------------------------------------------------------------------ */
/* Reverse lookup: who can perform an action                           */
/* ------------------------------------------------------------------ */

export interface WhoCanOptions {
  dataset: Dataset;
  action: string;
  resource: string;
  keys?: Record<string, string | string[]>;
  missingKeys?: 'unknown' | 'absent';
  resourceTags?: Record<string, string>;
  requestTags?: Record<string, string>;
  verdicts?: Verdict[];
}

/** Evaluates every principal in the dataset against an action/resource pair. */
export function whoCan(options: WhoCanOptions): WhoCanResult {
  const { dataset, action, resource } = options;
  const principals: PrincipalRef[] = [
    ...dataset.users.map((user) => ({
      type: 'user' as const,
      id: user.id,
      name: user.name,
      arn: user.arn,
      accountId: user.accountId,
      tags: user.tags ?? {},
      description: user.description,
    })),
    ...dataset.roles.map((role) => ({
      type: 'role' as const,
      id: role.id,
      name: role.name,
      arn: role.arn,
      accountId: role.accountId,
      tags: role.tags ?? {},
      description: role.description,
    })),
  ];

  const missing = new Set<string>();
  const entries = principals.map((principal) => {
    const decision = decide({
      dataset,
      principal,
      action,
      resource,
      keys: options.keys,
      missingKeys: options.missingKeys,
      resourceTags: options.resourceTags,
      requestTags: options.requestTags,
    });
    decision.missingKeys.forEach((key) => missing.add(key));
    return { principal, decision };
  });

  const filtered = options.verdicts
    ? entries.filter((entry) => options.verdicts!.includes(entry.decision.verdict))
    : entries;

  const rank: Record<Verdict, number> = { Allow: 0, Maybe: 1, ImplicitDeny: 2, Deny: 3 };
  filtered.sort((a, b) => rank[a.decision.verdict] - rank[b.decision.verdict]);

  return { entries: filtered, missingKeys: [...missing] };
}
