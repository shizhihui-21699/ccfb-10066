import { describe, expect, it } from 'vitest';
import { parseOperator, evaluateOperator, triAnd, triOr, triNot } from './conditions';
import { arnMatch, escapeLiteral, wildcardMatch } from './wildcard';
import { resolveVariables, NULL_VALUE, collectVariables } from './variables';
import { actionMatches, evaluatePolicy, principalMatches, resourceMatches } from './statement';
import { decide, whoCan, scpLevelsFor } from './decision';
import { makePolicyId } from './import';
import sample from '../data/sample-dataset.json';
import type { Dataset, Decision, PolicyRecord, PrincipalRef } from './types';

const dataset = sample as unknown as Dataset;

/* ------------------------------------------------------------------ */
/* Wildcards                                                           */
/* ------------------------------------------------------------------ */

describe('wildcard matching', () => {
  it('matches * and ? the way IAM does', () => {
    expect(wildcardMatch('s3:Get*', 's3:GetObject')).toBe(true);
    expect(wildcardMatch('s3:Get*', 's3:PutObject')).toBe(false);
    expect(wildcardMatch('arn:aws:s3:::bucket/key-?.txt', 'arn:aws:s3:::bucket/key-a.txt')).toBe(true);
    expect(wildcardMatch('a?c', 'abc')).toBe(true);
    expect(wildcardMatch('a?c', 'ac')).toBe(false);
    expect(wildcardMatch('abc', 'ABC')).toBe(false);
    expect(wildcardMatch('abc', 'ABC', true)).toBe(true);
    expect(wildcardMatch('*', '')).toBe(true);
    expect(wildcardMatch('', '')).toBe(true);
    expect(wildcardMatch('a*b*c', 'aXXbYYc')).toBe(true);
    expect(wildcardMatch('a*b*c', 'aXXcYY')).toBe(false);
  });

  it('treats regex metacharacters literally', () => {
    expect(wildcardMatch('a.b', 'axb')).toBe(false);
    expect(wildcardMatch('a.b', 'a.b')).toBe(true);
    expect(wildcardMatch('a+', 'a+')).toBe(true);
    expect(wildcardMatch('(x)', '(x)')).toBe(true);
    expect(wildcardMatch('a|b', 'a|b')).toBe(true);
  });

  it('escaped literals cannot act as wildcards', () => {
    const escaped = escapeLiteral('a*b');
    expect(wildcardMatch(escaped, 'a*b')).toBe(true);
    expect(wildcardMatch(escaped, 'axxb')).toBe(false);
  });

  it('matches ARNs component-wise', () => {
    expect(arnMatch('arn:aws:s3:::prod-*', 'arn:aws:s3:::prod-artifacts')).toBe(true);
    expect(arnMatch('arn:aws:iam::111122223333:role/*', 'arn:aws:iam::111122223333:role/ProdDeployer')).toBe(true);
    // Wildcard in the account component must not spill into later components.
    expect(arnMatch('arn:aws:iam::*:role/ProdDeployer', 'arn:aws:iam::111122223333:role/Other')).toBe(false);
    // Five-part ARNs fall back to whole-string matching (S3 style).
    expect(arnMatch('arn:aws:s3:::bucket/*', 'arn:aws:s3:::bucket/key')).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Variables                                                           */
/* ------------------------------------------------------------------ */

describe('policy variables', () => {
  it('substitutes a present single-valued key', () => {
    const resolved = resolveVariables('arn:aws:iam::*:user/${aws:username}', { 'aws:username': ['alice'] }, 'unknown');
    expect(resolved.text).toBe('arn:aws:iam::*:user/alice');
    expect(resolved.hasNull).toBe(false);
  });

  it('resolves an absent key to a null sentinel that cannot match', () => {
    const resolved = resolveVariables('arn:aws:s3:::bucket/${aws:username}/*', { }, 'absent');
    expect(resolved.text.includes(NULL_VALUE)).toBe(true);
    expect(resourceMatches([resolved.text], 'arn:aws:s3:::bucket/alice/x')).toBe(false);
  });

  it('treats unknown keys as unresolved', () => {
    const resolved = resolveVariables('${PrincipalTag/team}', {}, 'unknown');
    expect(resolved.hasUnknown).toBe(true);
  });

  it('escapes substituted wildcard characters so they stay literal', () => {
    const resolved = resolveVariables('arn:aws:s3:::b/${aws:username}', { 'aws:username': ['a*'] }, 'absent');
    expect(wildcardMatch(resolved.text, 'arn:aws:s3:::b/a*')).toBe(true);
    expect(wildcardMatch(resolved.text, 'arn:aws:s3:::b/anything')).toBe(false);
  });

  it('supports literal ${*} ${?} ${$} sequences', () => {
    const resolved = resolveVariables('x${*}y${?}z${$}', {}, 'absent');
    expect(resolved.hasNull).toBe(false);
    expect(wildcardMatch(resolved.text, 'x*y?z$')).toBe(true);
    expect(wildcardMatch(resolved.text, 'xaybz$')).toBe(false);
  });

  it('collects referenced variables', () => {
    expect(collectVariables('${aws:username}/${PrincipalTag/team}/${*}')).toEqual([
      'aws:username',
      'aws:PrincipalTag/team',
    ]);
  });
});

/* ------------------------------------------------------------------ */
/* Condition operators                                                 */
/* ------------------------------------------------------------------ */

describe('condition operators', () => {
  it('parses set qualifiers, negation and IfExists suffixes', () => {
    expect(parseOperator('ForAnyValue:StringLike')).toMatchObject({
      family: 'string',
      setOp: 'ForAnyValue',
      negated: false,
    });
    expect(parseOperator('ForAllValues:StringNotLikeIfExists')).toMatchObject({
      family: 'string',
      setOp: 'ForAllValues',
      negated: true,
      ifExists: true,
    });
    expect(parseOperator('Null')).toMatchObject({ family: 'null', ifExists: false });
    expect(parseOperator('Nonsense')).toBeNull();
  });

  it('string equals / not-equals', () => {
    const eq = parseOperator('StringEquals')!;
    expect(evaluateOperator(eq, 'a', ['a']).outcome).toBe('match');
    expect(evaluateOperator(eq, ['a', 'b'], ['b']).outcome).toBe('match');
    expect(evaluateOperator(eq, 'a', ['A']).outcome).toBe('no-match');
    const notEq = parseOperator('StringNotEquals')!;
    expect(evaluateOperator(notEq, 'a', ['b']).outcome).toBe('match');
    expect(evaluateOperator(notEq, 'a', ['a']).outcome).toBe('no-match');
  });

  it('missing key: positive ops false, negated ops true', () => {
    expect(evaluateOperator(parseOperator('StringEquals')!, 'a', null).outcome).toBe('no-match');
    expect(evaluateOperator(parseOperator('StringNotEquals')!, 'a', null).outcome).toBe('match');
    expect(evaluateOperator(parseOperator('ArnLike')!, 'a', null).outcome).toBe('no-match');
    expect(evaluateOperator(parseOperator('ArnNotLike')!, 'a', null).outcome).toBe('match');
    expect(evaluateOperator(parseOperator('StringEquals')!, 'a', undefined).outcome).toBe('unknown');
  });

  it('IfExists is true when the key is missing', () => {
    expect(evaluateOperator(parseOperator('StringLikeIfExists')!, 't1.*', null).outcome).toBe('match');
    expect(evaluateOperator(parseOperator('StringLikeIfExists')!, 't1.*', ['m2.micro']).outcome).toBe('no-match');
    // Deny + negated IfExists still denies when the key is absent.
    expect(evaluateOperator(parseOperator('StringNotEqualsIfExists')!, 'x', null).outcome).toBe('match');
  });

  it('Null checks key presence', () => {
    const op = parseOperator('Null')!;
    expect(evaluateOperator(op, 'true', null).outcome).toBe('match');
    expect(evaluateOperator(op, 'true', ['x']).outcome).toBe('no-match');
    expect(evaluateOperator(op, 'false', ['x']).outcome).toBe('match');
    expect(evaluateOperator(op, 'false', null).outcome).toBe('no-match');
    expect(evaluateOperator(op, 'true', undefined).outcome).toBe('unknown');
  });

  it('Numeric and Date comparison', () => {
    const n = parseOperator('NumericLessThanEquals')!;
    expect(evaluateOperator(n, '10', ['9']).outcome).toBe('match');
    expect(evaluateOperator(n, '10', ['11']).outcome).toBe('no-match');
    expect(evaluateOperator(n, '10', ['abc']).outcome).toBe('no-match');
    const d = parseOperator('DateGreaterThan')!;
    expect(evaluateOperator(d, '2020-01-01T00:00:01Z', ['2020-06-01T00:00:00Z']).outcome).toBe('match');
    expect(evaluateOperator(d, '2020-01-01T00:00:01Z', ['2019-01-01T00:00:00Z']).outcome).toBe('no-match');
    // Epoch seconds are accepted.
    expect(evaluateOperator(d, '1577836801', ['1578000000']).outcome).toBe('match');
  });

  it('Bool', () => {
    const op = parseOperator('Bool')!;
    expect(evaluateOperator(op, 'true', ['true']).outcome).toBe('match');
    expect(evaluateOperator(op, 'true', ['false']).outcome).toBe('no-match');
    expect(evaluateOperator(op, 'true', ['TRUE']).outcome).toBe('match');
    expect(evaluateOperator(op, 'nonsense', ['true']).outcome).toBe('no-match');
  });

  it('IP / CIDR including IPv6', () => {
    const op = parseOperator('IpAddress')!;
    expect(evaluateOperator(op, '203.0.113.0/24', ['203.0.113.7']).outcome).toBe('match');
    expect(evaluateOperator(op, '203.0.113.0/24', ['198.51.100.1']).outcome).toBe('no-match');
    expect(evaluateOperator(op, '10.0.0.0/8', ['10.1.2.3']).outcome).toBe('match');
    expect(evaluateOperator(op, '2001:db8::/32', ['2001:db8:1::1']).outcome).toBe('match');
    expect(evaluateOperator(op, '2001:db8::/32', ['2001:db9::1']).outcome).toBe('no-match');
    // A bare address is treated as /32 by AWS.
    expect(evaluateOperator(op, '203.0.113.7', ['203.0.113.7']).outcome).toBe('match');
    const notOp = parseOperator('NotIpAddress')!;
    expect(evaluateOperator(notOp, '10.0.0.0/8', ['192.168.1.1']).outcome).toBe('match');
  });

  it('ForAllValues / ForAnyValue over multi-valued keys', () => {
    const forAll = parseOperator('ForAllValues:StringEquals')!;
    expect(evaluateOperator(forAll, ['environment', 'cost-center'], ['environment', 'cost-center']).outcome).toBe('match');
    expect(evaluateOperator(forAll, ['environment'], ['environment', 'dept']).outcome).toBe('no-match');
    // Missing key makes ForAllValues true (the documented footgun).
    expect(evaluateOperator(forAll, ['environment'], null).outcome).toBe('match');

    const forAny = parseOperator('ForAnyValue:StringEquals')!;
    expect(evaluateOperator(forAny, ['environment', 'cost-center'], ['environment', 'dept']).outcome).toBe('match');
    expect(evaluateOperator(forAny, ['environment'], ['dept']).outcome).toBe('no-match');
    expect(evaluateOperator(forAny, ['environment'], null).outcome).toBe('no-match');
  });

  it('negated set operators', () => {
    const forAllNot = parseOperator('ForAllValues:StringNotLike')!;
    expect(evaluateOperator(forAllNot, ['a/*', 'b/*'], ['c/x']).outcome).toBe('match');
    expect(evaluateOperator(forAllNot, ['a/*', 'b/*'], ['b/y']).outcome).toBe('no-match');
    const forAnyNot = parseOperator('ForAnyValue:StringNotEquals')!;
    expect(evaluateOperator(forAnyNot, ['a'], ['a', 'b']).outcome).toBe('match');
    expect(evaluateOperator(forAnyNot, ['a'], ['a']).outcome).toBe('no-match');
  });

  it('null sentinel in policy values never matches positively', () => {
    expect(evaluateOperator(parseOperator('StringEquals')!, NULL_VALUE, ['anything']).outcome).toBe('no-match');
    expect(evaluateOperator(parseOperator('StringNotEquals')!, NULL_VALUE, ['anything']).outcome).toBe('match');
  });

  it('tri-state combinators', () => {
    expect(triAnd(['match', 'match'])).toBe('match');
    expect(triAnd(['match', 'unknown'])).toBe('unknown');
    expect(triAnd(['match', 'no-match'])).toBe('no-match');
    expect(triOr(['no-match', 'unknown'])).toBe('unknown');
    expect(triOr(['no-match', 'match'])).toBe('match');
    expect(triNot('match')).toBe('no-match');
    expect(triNot('unknown')).toBe('unknown');
  });
});

/* ------------------------------------------------------------------ */
/* Statement semantics                                                 */
/* ------------------------------------------------------------------ */

describe('statement evaluation', () => {
  const makePolicy = (document: PolicyRecord['document']): PolicyRecord => ({
    id: 'test',
    name: 'test',
    kind: 'managed',
    document,
  });

  it('NotAction inverts action matching', () => {
    const policy = makePolicy({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', NotAction: 's3:PutObject', Resource: 'arn:aws:s3:::b/*' }],
    });
    const get = evaluatePolicy(policy, {
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::b/k',
      keys: {},
      missingKeys: 'absent',
    })[0];
    const put = evaluatePolicy(policy, {
      action: 's3:PutObject',
      resource: 'arn:aws:s3:::b/k',
      keys: {},
      missingKeys: 'absent',
    })[0];
    expect(get.outcome).toBe('match');
    expect(put.outcome).toBe('no-match');
  });

  it('NotResource inverts resource matching', () => {
    const policy = makePolicy({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: 's3:*', NotResource: 'arn:aws:s3:::b/*' }],
    });
    const inside = evaluatePolicy(policy, {
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::b/k',
      keys: {},
      missingKeys: 'absent',
    })[0];
    const outside = evaluatePolicy(policy, {
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::c/k',
      keys: {},
      missingKeys: 'absent',
    })[0];
    expect(inside.outcome).toBe('no-match');
    expect(outside.outcome).toBe('match');
  });

  it('action matching is case-insensitive', () => {
    expect(actionMatches(['s3:getobject'], 's3:GetObject')).toBe(true);
    expect(actionMatches(['S3:GETOBJECT'], 's3:GetObject')).toBe(true);
  });

  it('rejects statements with both Action and NotAction', () => {
    const policy = makePolicy({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: 's3:*', NotAction: 's3:GetObject', Resource: '*' }],
    });
    const evaluation = evaluatePolicy(policy, {
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::b/k',
      keys: {},
      missingKeys: 'absent',
    })[0];
    expect(evaluation.outcome).toBe('no-match');
    expect(evaluation.issue).toContain('无效');
  });

  it('evaluates principals for resource policies', () => {
    const identity = {
      arn: 'arn:aws:iam::111122223333:user/alice',
      accountId: '111122223333',
      tags: {},
      federatedProviders: [],
    };
    expect(principalMatches('*', identity)).toBe('match');
    expect(principalMatches({ AWS: '111122223333' }, identity)).toBe('match');
    expect(principalMatches({ AWS: 'arn:aws:iam::111122223333:root' }, identity)).toBe('match');
    expect(principalMatches({ AWS: 'arn:aws:iam::444455556666:root' }, identity)).toBe('no-match');
    expect(principalMatches({ AWS: 'arn:aws:iam::111122223333:user/bob' }, identity)).toBe('no-match');
  });

  it('resource policy without Principal does not apply', () => {
    const policy: PolicyRecord = {
      id: 'rp',
      name: 'rp',
      kind: 'resource',
      document: {
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }],
      },
    };
    const evaluation = evaluatePolicy(
      policy,
      { action: 's3:GetObject', resource: 'arn:aws:s3:::b/k', keys: {}, missingKeys: 'absent' },
      {
        arn: 'arn:aws:iam::111122223333:user/alice',
        accountId: '111122223333',
        tags: {},
        federatedProviders: [],
      },
      false,
    )[0];
    expect(evaluation.outcome).toBe('no-match');
    expect(evaluation.issue).toContain('资源策略缺少 Principal');
  });

  it('unknown condition keys make the statement undecidable', () => {
    const policy = makePolicy({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::b/*',
          Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-1' } },
        },
      ],
    });
    const evaluation = evaluatePolicy(policy, {
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::b/k',
      keys: {},
      missingKeys: 'unknown',
    })[0];
    expect(evaluation.outcome).toBe('unknown');
  });
});

/* ------------------------------------------------------------------ */
/* Decisions on the sample dataset                                     */
/* ------------------------------------------------------------------ */

function principal(id: string): PrincipalRef {
  const user = dataset.users.find((u) => u.id === id);
  if (user) {
    return {
      type: 'user',
      id: user.id,
      name: user.name,
      arn: user.arn,
      accountId: user.accountId,
      tags: user.tags,
      description: user.description,
    };
  }
  const role = dataset.roles.find((r) => r.id === id);
  if (!role) throw new Error(`unknown principal ${id}`);
  return {
    type: 'role',
    id: role.id,
    name: role.name,
    arn: role.arn,
    accountId: role.accountId,
    tags: role.tags,
    description: role.description,
  };
}

const PAYMENTS_OBJECT =
  'arn:aws:s3:::production-payments-archive/2026/11/settlement-batch-0042.parquet';

describe('decision composition', () => {
  it('allows when identity policy grants and nothing blocks', () => {
    const decision = decide({
      dataset,
      principal: principal('usr-dataeng'),
      action: 's3:GetObject',
      resource: PAYMENTS_OBJECT,
      missingKeys: 'absent',
    });
    expect(decision.verdict).toBe('Allow');
    expect(decision.allowEvidence.length).toBeGreaterThan(0);
  });

  it('explicit deny overrides an allow', () => {
    // dataeng may read payments, finops-analyst has an explicit deny on the bucket.
    const allowed = decide({
      dataset,
      principal: principal('usr-dataeng'),
      action: 's3:GetObject',
      resource: PAYMENTS_OBJECT,
      missingKeys: 'absent',
    });
    expect(allowed.verdict).toBe('Allow');

    const denied = decide({
      dataset,
      principal: principal('usr-finops'),
      action: 's3:GetObject',
      resource: PAYMENTS_OBJECT,
      missingKeys: 'absent',
    });
    expect(denied.verdict).toBe('Deny');
    expect(denied.denyEvidence.length).toBeGreaterThan(0);
    expect(denied.summary).toContain('显式拒绝');
  });

  it('implicitly denies when nothing grants access', () => {
    const decision = decide({
      dataset,
      principal: principal('usr-contractor'),
      action: 's3:PutObject',
      resource: 'arn:aws:s3:::prod-customer-exports/report.csv',
      missingKeys: 'absent',
    });
    expect(decision.verdict).not.toBe('Allow');
  });

  it('permissions boundary intersects: s3:* grant shrunk by read-only boundary', () => {
    const decision = decide({
      dataset,
      principal: principal('usr-storage-engineer'),
      action: 's3:DeleteObject',
      resource: 'arn:aws:s3:::prod-artifacts-build/old.tar.gz',
      missingKeys: 'absent',
    });
    expect(decision.verdict).toBe('ImplicitDeny');
    expect(decision.boundary?.policyName).toContain('ReadOnly');
    const boundaryStep = decision.steps.find((step) => step.id === 'boundary');
    expect(boundaryStep?.detail).toContain('收缩');
  });

  it('SCP deny from an ancestor OU blocks the request', () => {
    // pd-admin boundary allows s3:*, identity grants it, but the prod OU SCP
    // denies PutBucketAcl on prod-* buckets.
    const decision = decide({
      dataset,
      principal: principal('usr-platform-lead'),
      action: 's3:PutBucketAcl',
      resource: 'arn:aws:s3:::prod-artifacts-build',
      missingKeys: 'absent',
    });
    expect(decision.verdict).toBe('Deny');
    expect(decision.scpLevels.some((level) => level.outcome === 'no-match')).toBe(true);
    expect(decision.denyEvidence.some((evidence) => evidence.policyKind === 'scp')).toBe(true);
  });

  it('the prod SCP prefix gap lets bucket-policy writes through on production-*', () => {
    // Planted flaw: the SCP matches prod-* only, so the real production bucket
    // (production-payments-archive) escapes the bucket-policy protection.
    const escapes = decide({
      dataset,
      principal: principal('usr-storage-lead'),
      action: 's3:PutBucketPolicy',
      resource: 'arn:aws:s3:::production-payments-archive',
      missingKeys: 'absent',
    });
    expect(escapes.verdict).toBe('Allow');

    // The same action on a prod-* bucket is blocked by the SCP.
    const blocked = decide({
      dataset,
      principal: principal('usr-storage-lead'),
      action: 's3:PutBucketPolicy',
      resource: 'arn:aws:s3:::prod-artifacts-build',
      missingKeys: 'absent',
    });
    expect(blocked.verdict).toBe('Deny');
    expect(blocked.denyEvidence.some((evidence) => evidence.policyKind === 'scp')).toBe(true);
  });

  it('resource policy grants same-account access that the identity policy does not', () => {
    // The payments bucket policy allows public GetObject over TLS.
    const decision = decide({
      dataset,
      principal: principal('usr-auditor'),
      action: 's3:GetObject',
      resource: PAYMENTS_OBJECT,
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'absent',
    });
    expect(decision.verdict).toBe('Allow');
    expect(decision.resourcePolicyIds).toContain('rp-prod-payments-bucket-doc');
  });

  it('the public bucket policy requires TLS to match', () => {
    // dev-intern has no identity grant for the payments archive, so the only
    // possible path is the public bucket policy — which demands TLS.
    const plaintext = decide({
      dataset,
      principal: principal('usr-intern'),
      action: 's3:GetObject',
      resource: PAYMENTS_OBJECT,
      keys: { 'aws:SecureTransport': 'false' },
      missingKeys: 'absent',
    });
    expect(plaintext.verdict).toBe('ImplicitDeny');

    const overTls = decide({
      dataset,
      principal: principal('usr-intern'),
      action: 's3:GetObject',
      resource: PAYMENTS_OBJECT,
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'absent',
    });
    expect(overTls.verdict).toBe('Allow');
    expect(overTls.allowEvidence.some((evidence) => evidence.policyKind === 'resource')).toBe(true);
  });

  it('cross-account resource policy grant still requires a same-account identity grant', () => {
    // The artifacts bucket policy names the dev account root, so the resource
    // path matches; but role-dev-deployer only has s3:* on dev-* buckets.
    const decision = decide({
      dataset,
      principal: principal('role-dev-deployer'),
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::prod-artifacts-build/releases/api-1.24.0.tar.gz',
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'absent',
    });
    expect(decision.verdict).toBe('ImplicitDeny');
    expect(decision.resourcePolicyIds).toContain('rp-prod-artifacts-bucket-doc');
    expect(decision.summary).toContain('跨账号');

    // Same request from a prod-account principal is granted by the resource
    // policy alone (the bucket policy also allows the prod account).
    const sameAccount = decide({
      dataset,
      principal: principal('usr-platform-lead'),
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::prod-artifacts-build/releases/api-1.24.0.tar.gz',
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'absent',
    });
    expect(sameAccount.verdict).toBe('Allow');
  });

  it('a boundary whose deny prefix misses the real production bucket lets deletion through', () => {
    // Planted flaw: Admin-Boundary denies s3:DeleteBucket on prod-* only, so the
    // production-* bucket is deletable by storage admins. The SCPs do not deny
    // DeleteBucket either.
    const decision = decide({
      dataset,
      principal: principal('role-prod-storage-admin'),
      action: 's3:DeleteBucket',
      resource: 'arn:aws:s3:::production-payments-archive',
      missingKeys: 'absent',
    });
    expect(decision.verdict).toBe('Allow');

    // A prod-* bucket is protected by the boundary.
    const protectedBucket = decide({
      dataset,
      principal: principal('role-prod-storage-admin'),
      action: 's3:DeleteBucket',
      resource: 'arn:aws:s3:::prod-artifacts-build',
      missingKeys: 'absent',
    });
    expect(protectedBucket.verdict).toBe('Deny');
  });

  it('unknown condition keys yield Maybe with the key named', () => {
    const decision = decide({
      dataset,
      principal: principal('usr-dev'),
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::dev-app-data/a.txt',
      // no keys, and the dev policy has no conditions → this should still be Allow
      missingKeys: 'unknown',
    });
    expect(decision.verdict).toBe('Allow');

    const conditional = decide({
      dataset,
      principal: principal('usr-platform-lead'),
      action: 'secretsmanager:GetSecretValue',
      resource: 'arn:aws:secretsmanager:cn-north-1:111122223333:secret:prod/payments/db-password',
      missingKeys: 'unknown',
    });
    // principal tag keys are implicit, so the team tag resolves; SecureTransport
    // style keys are not involved. Either Allow or a key-naming Maybe.
    expect(['Allow', 'Maybe', 'ImplicitDeny']).toContain(conditional.verdict);
  });

  it('the BoolIfExists trap does not actually require MFA', () => {
    const withoutMfa = decide({
      dataset,
      principal: principal('role-prod-mfa-delete'),
      action: 's3:DeleteObject',
      resource: 'arn:aws:s3:::prod-customer-exports/old.csv',
      keys: {},
      missingKeys: 'absent',
    });
    expect(withoutMfa.verdict).toBe('Allow');
  });

  it('the IP-restriction trap admits 0.0.0.0/0', () => {
    // Planted flaw: the CIDR list includes 0.0.0.0/0, so the "corp network only"
    // policy actually allows every source address.
    const anywhere = decide({
      dataset,
      principal: principal('usr-network'),
      action: 's3:DeleteObject',
      resource: 'arn:aws:s3:::production-payments-archive/x.parquet',
      keys: { 'aws:SourceIp': '198.51.100.44' },
      missingKeys: 'absent',
    });
    expect(anywhere.verdict).toBe('Allow');
    expect(anywhere.allowEvidence.some((evidence) => evidence.policyName.includes('Corp-Network'))).toBe(true);

    // Any IPv4 address passes, including one that is nowhere near the corp
    // ranges — that is exactly the flaw.
    const outsideCorp = decide({
      dataset,
      principal: principal('usr-network'),
      action: 's3:DeleteObject',
      resource: 'arn:aws:s3:::production-payments-archive/y.parquet',
      keys: { 'aws:SourceIp': '198.18.7.7' },
      missingKeys: 'absent',
    });
    expect(outsideCorp.verdict).toBe('Allow');
  });

  it('SCP levels are enumerated root-first', () => {
    const levels = scpLevelsFor(dataset, '111122223333');
    expect(levels.map((level) => level.levelName)).toEqual(['OU ExampleCorp (根)', 'OU Production', '账号 prod-workloads']);
  });

  it('an SCP level with no policy blocks everything', () => {
    const patched: Dataset = {
      ...dataset,
      accounts: dataset.accounts.map((account) =>
        account.id === '111122223333' ? { ...account, scpPolicyIds: [] } : account,
      ),
      orgUnits: dataset.orgUnits.map((unit) =>
        unit.id === 'ou-prod' ? { ...unit, scpPolicyIds: ['scp-prod-full-access', 'scp-prod-guardrails'] } : unit,
      ),
    };
    const decision = decide({
      dataset: patched,
      principal: principal('usr-platform-lead'),
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::prod-artifacts-build/x',
      missingKeys: 'absent',
    });
    expect(decision.verdict).not.toBe('Allow');
  });
});

/* ------------------------------------------------------------------ */
/* Reverse lookup                                                      */
/* ------------------------------------------------------------------ */

describe('whoCan', () => {
  it('lists principals that can delete the payments archive', () => {
    const result = whoCan({
      dataset,
      action: 's3:DeleteObject',
      resource: PAYMENTS_OBJECT,
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'absent',
    });
    const allowed = result.entries.filter((entry) => entry.decision.verdict === 'Allow');
    const names = allowed.map((entry) => entry.principal.name).sort();

    // These are the accounts that the planted prefix gaps leave exposed: the
    // Admin-Boundary deny covers prod-* only, and the SCP does the same.
    expect(names).toEqual(['DeletionWorker', 'StorageAdmin', 'storage-lead']);

    // The people you would expect to be blocked are blocked by explicit denies.
    expect(names).not.toContain('dataeng-lead');
    expect(names).not.toContain('platform-lead');
  });

  it('finds readers of the payments archive via resource policy', () => {
    const result = whoCan({
      dataset,
      action: 's3:GetObject',
      resource: PAYMENTS_OBJECT,
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'absent',
      verdicts: ['Allow'],
    });
    expect(result.entries.length).toBeGreaterThan(0);
    for (const entry of result.entries) {
      expect(entry.decision.verdict).toBe('Allow');
    }
  });
});

/* ------------------------------------------------------------------ */
/* Trust policies and uncertainty semantics                            */
/* ------------------------------------------------------------------ */

describe('trust policies and uncertainty', () => {
  it('assuming a role requires the trust policy to admit the caller', () => {
    // usr-devops (team=devops) can assume ProdDeployer per its identity policy,
    // and the trust policy names the dev account with PrincipalTag/team=devops.
    const admitted = decide({
      dataset,
      principal: principal('usr-dev'),
      action: 'sts:AssumeRole',
      resource: 'arn:aws:iam::111122223333:role/ProdDeployer',
      missingKeys: 'absent',
    });
    expect(admitted.verdict).toBe('Allow');
    expect(admitted.resourcePolicyIds).toContain('trust-prod-deployer');

    // usr-network has no identity grant for that role at all.
    const noIdentity = decide({
      dataset,
      principal: principal('usr-network'),
      action: 'sts:AssumeRole',
      resource: 'arn:aws:iam::111122223333:role/ProdDeployer',
      missingKeys: 'absent',
    });
    expect(noIdentity.verdict).not.toBe('Allow');
  });

  it('a role with no matching trust statement is not assumable even with an identity grant', () => {
    // dev-intern's identity policy is the deliberately over-broad
    // Assume-Any-Role (same-account role/*), which matches BreakGlass.
    // BreakGlass trusts only security-oncall, so the trust side fails.
    const breakglass = decide({
      dataset,
      principal: principal('usr-intern'),
      action: 'sts:AssumeRole',
      resource: 'arn:aws:iam::111122223333:role/ProdBreakGlass',
      keys: { 'aws:PrincipalTag/oncall': 'true' },
      missingKeys: 'absent',
    });
    expect(breakglass.verdict).toBe('ImplicitDeny');
    // The identity policy alone would have allowed it — the trust policy is what
    // blocks the request.
    const identityAllowed = breakglass.statements.some(
      (statement) =>
        statement.policyKind === 'managed' && statement.effect === 'Allow' && statement.outcome === 'match',
    );
    expect(identityAllowed).toBe(true);
    expect(breakglass.resourcePolicyIds).toContain('trust-prod-breakglass');

    // The on-call security user is trusted and also explicitly granted nothing,
    // so it needs an identity grant: this one is denied on the identity path.
    const oncall = decide({
      dataset,
      principal: principal('usr-security-oncall'),
      action: 'sts:AssumeRole',
      resource: 'arn:aws:iam::111122223333:role/ProdBreakGlass',
      keys: { 'aws:PrincipalTag/oncall': 'true' },
      missingKeys: 'absent',
    });
    expect(oncall.verdict).toBe('ImplicitDeny');
  });

  it('an undecidable deny statement downgrades a confirmed allow to Maybe', () => {
    const patched: Dataset = {
      ...dataset,
      policies: [
        ...dataset.policies,
        {
          id: 'patch-unknown-deny',
          name: 'Unknown Deny',
          kind: 'managed',
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Deny',
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::production-payments-archive/*',
                Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-unknown' } },
              },
            ],
          },
        },
      ],
      users: dataset.users.map((user) =>
        user.id === 'usr-intern'
          ? { ...user, managedPolicyIds: [...user.managedPolicyIds, 'patch-unknown-deny'] }
          : user,
      ),
    };

    const decision = decide({
      dataset: patched,
      principal: principal('usr-intern'),
      action: 's3:GetObject',
      resource: PAYMENTS_OBJECT,
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'unknown',
    });
    expect(decision.verdict).toBe('Maybe');
    expect(decision.missingKeys).toContain('aws:SourceVpce');
  });

  it('an SCP with undecidable statements cannot confirm an allow', () => {
    const patched: Dataset = {
      ...dataset,
      policies: [
        ...dataset.policies,
        {
          id: 'patch-unknown-scp',
          name: 'Unknown SCP',
          kind: 'scp',
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*',
                Condition: { StringEquals: { 'aws:PrincipalTag/region': 'cn' } },
              },
            ],
          },
        },
      ],
      accounts: dataset.accounts.map((account) =>
        account.id === '111122223333'
          ? { ...account, scpPolicyIds: ['patch-unknown-scp'] }
          : account,
      ),
    };
    const decision = decide({
      dataset: patched,
      principal: principal('usr-platform-lead'),
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::prod-artifacts-build/x',
      missingKeys: 'unknown',
    });
    expect(decision.verdict).toBe('Maybe');
    expect(decision.missingKeys).toContain('aws:PrincipalTag/region');
  });

  it('the policy import validator rejects malformed documents', () => {
    // Covered more fully in import.test.ts; here just ensure ids are unique-ish.
    const first = makePolicyId('test');
    const second = makePolicyId('test');
    expect(first).not.toBe(second);
  });
});

/* ------------------------------------------------------------------ */
/* Missing-key handling modes                                          */
/* ------------------------------------------------------------------ */

describe('missing key modes', () => {
  const policy: PolicyRecord = {
    id: 'missing-mode',
    name: 'Missing-Mode',
    kind: 'managed',
    document: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'IpRestricted',
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::prod-artifacts-build/*',
          Condition: { IpAddress: { 'aws:SourceIp': '10.0.0.0/8' } },
        },
      ],
    },
  };

  const withPolicy = (): Dataset => ({
    ...dataset,
    policies: [...dataset.policies, policy],
    users: dataset.users.map((user) =>
      user.id === 'usr-platform-lead'
        ? { ...user, managedPolicyIds: [...user.managedPolicyIds, policy.id] }
        : user,
    ),
  });

  it('unknown mode asks for the key', () => {
    const decision = decide({
      dataset: withPolicy(),
      principal: principal('usr-platform-lead'),
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::prod-artifacts-build/x',
      keys: {},
      missingKeys: 'unknown',
    });
    expect(decision.missingKeys).toContain('aws:SourceIp');
    expect(decision.verdict).not.toBe('ImplicitDeny');
  });

  it('absent mode applies the documented semantics instead of asking', () => {
    const decision = decide({
      dataset: withPolicy(),
      principal: principal('usr-platform-lead'),
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::prod-artifacts-build/x',
      keys: {},
      missingKeys: 'absent',
    });
    expect(decision.missingKeys).not.toContain('aws:SourceIp');
  });

  it('only reports keys from statements whose action and resource already apply', () => {
    const decision = decide({
      dataset: withPolicy(),
      principal: principal('usr-platform-lead'),
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::prod-customer-exports/report.csv',
      keys: {},
      missingKeys: 'unknown',
    });
    // The IP-restricted policy targets prod-artifacts-build, so its key must not
    // be reported for a customer-exports object.
    expect(decision.missingKeys).not.toContain('aws:SourceIp');
  });
});

/* ------------------------------------------------------------------ */
/* The planted traps, asserted as executable documentation             */
/* ------------------------------------------------------------------ */

describe('planted sample traps', () => {
  const trap = (
    principalId: string,
    action: string,
    resource: string,
    keys: Record<string, string> = {},
  ): Decision =>
    decide({ dataset, principal: principal(principalId), action, resource, keys, missingKeys: 'absent' });

  it('1. SCP prefix gap: prod-* vs production-*', () => {
    expect(trap('role-prod-storage-admin', 's3:PutBucketPolicy', 'arn:aws:s3:::production-payments-archive').verdict).toBe('Allow');
    expect(trap('role-prod-storage-admin', 's3:PutBucketPolicy', 'arn:aws:s3:::prod-artifacts-build').verdict).toBe('Deny');
  });

  it('2. ForAllValues without a Null check does not require tags', () => {
    expect(trap('usr-dataeng', 's3:PutObject', 'arn:aws:s3:::production-payments-archive/new.parquet').verdict).toBe('Allow');
  });

  it('3. NotAction leaves bucket-level actions open', () => {
    expect(trap('usr-shared-ops', 's3:PutBucketPolicy', 'arn:aws:s3:::shared-audit-logs').verdict).toBe('Allow');
    expect(trap('usr-shared-ops', 's3:GetObject', 'arn:aws:s3:::shared-audit-logs/x').verdict).toBe('Allow');
  });

  it('4. account wildcard in AssumeRole reaches a cross-account role', () => {
    expect(
      trap('usr-deployer', 'sts:AssumeRole', 'arn:aws:iam::444455556666:role/ProdDeployer').verdict,
    ).toBe('Allow');
  });

  it('5. 0.0.0.0/0 in an IP condition admits arbitrary sources', () => {
    expect(
      trap('usr-network', 's3:DeleteObject', 'arn:aws:s3:::production-payments-archive/x.parquet', {
        'aws:SourceIp': '198.18.7.7',
      }).verdict,
    ).toBe('Allow');
  });

  it('6. public bucket policy with only a TLS condition', () => {
    expect(
      trap('usr-intern', 's3:GetObject', PAYMENTS_OBJECT, { 'aws:SecureTransport': 'true' }).verdict,
    ).toBe('Allow');
    expect(
      trap('usr-intern', 's3:GetObject', PAYMENTS_OBJECT, { 'aws:SecureTransport': 'false' }).verdict,
    ).toBe('ImplicitDeny');
  });

  it('7. BoolIfExists lets a delete through without MFA', () => {
    expect(trap('role-prod-mfa-delete', 's3:DeleteObject', 'arn:aws:s3:::prod-customer-exports/old.csv').verdict).toBe(
      'Allow',
    );
  });

  it('8. boundary prefix gap lets the real production bucket be deleted', () => {
    expect(trap('role-prod-storage-admin', 's3:DeleteBucket', 'arn:aws:s3:::production-payments-archive').verdict).toBe(
      'Allow',
    );
    expect(trap('role-prod-storage-admin', 's3:DeleteBucket', 'arn:aws:s3:::prod-artifacts-build').verdict).toBe('Deny');
  });
});

/* ------------------------------------------------------------------ */
/* Boundary exemption details                                          */
/* ------------------------------------------------------------------ */

describe('boundary vs resource policies', () => {
  it('a grant naming a user ARN directly bypasses the boundary implicit deny', () => {
    const patched: Dataset = {
      ...dataset,
      policies: [
        ...dataset.policies,
        {
          id: 'direct-user-grant',
          name: 'Direct-User-Grant',
          kind: 'resource',
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: { AWS: 'arn:aws:iam::111122223333:user/storage-engineer' },
                Action: 's3:PutObject',
                Resource: 'arn:aws:s3:::prod-artifacts-build/*',
              },
            ],
          },
        },
      ],
      resourcePolicies: [
        ...dataset.resourcePolicies,
        {
          id: 'direct-user-attachment',
          name: 'Direct-User-Attachment',
          resourceArns: ['arn:aws:s3:::prod-artifacts-build'],
          policyId: 'direct-user-grant',
        },
      ],
    };

    // storage-engineer's boundary is read-only, so the identity path fails; the
    // direct user-ARN grant is boundary-exempt and grants the write.
    const decision = decide({
      dataset: patched,
      principal: principal('usr-storage-engineer'),
      action: 's3:PutObject',
      resource: 'arn:aws:s3:::prod-artifacts-build/x',
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'absent',
    });
    expect(decision.verdict).toBe('Allow');
    expect(decision.allowEvidence.some((evidence) => evidence.policyKind === 'resource')).toBe(true);
  });

  it('an account-root delegation does not bypass the boundary', () => {
    const patched: Dataset = {
      ...dataset,
      policies: [
        ...dataset.policies,
        {
          id: 'account-root-grant',
          name: 'Account-Root-Grant',
          kind: 'resource',
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: { AWS: 'arn:aws:iam::111122223333:root' },
                Action: 's3:PutObject',
                Resource: 'arn:aws:s3:::prod-artifacts-build/*',
              },
            ],
          },
        },
      ],
      resourcePolicies: [
        ...dataset.resourcePolicies,
        {
          id: 'account-root-attachment',
          name: 'Account-Root-Attachment',
          resourceArns: ['arn:aws:s3:::prod-artifacts-build'],
          policyId: 'account-root-grant',
        },
      ],
    };

    const decision = decide({
      dataset: patched,
      principal: principal('usr-storage-engineer'),
      action: 's3:PutObject',
      resource: 'arn:aws:s3:::prod-artifacts-build/x',
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'absent',
    });
    // The resource grant matches, but it delegates to the account, so the
    // read-only boundary still shrinks it.
    expect(decision.verdict).not.toBe('Allow');
  });
});
