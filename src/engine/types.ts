/**
 * Core policy model types.
 *
 * The shapes intentionally mirror the IAM JSON policy grammar so that imported
 * documents can be used with minimal massaging.
 */

export type Effect = 'Allow' | 'Deny';

export type Scalar = string | number | boolean;
export type ConditionValue = Scalar | Scalar[];
export type ConditionBlock = Record<string, Record<string, ConditionValue>>;
export type PrincipalValue = string | string[];
export type PrincipalSpec = '*' | Record<string, PrincipalValue>;

export interface Statement {
  Sid?: string;
  Effect: Effect;
  Action?: string | string[];
  NotAction?: string | string[];
  Resource?: string | string[];
  NotResource?: string | string[];
  Principal?: PrincipalSpec;
  NotPrincipal?: PrincipalSpec;
  Condition?: ConditionBlock;
}

export interface PolicyDocument {
  Version: string;
  Id?: string;
  Statement: Statement | Statement[];
}

export type PolicyKind =
  | 'managed'
  | 'inline'
  | 'boundary'
  | 'scp'
  | 'resource'
  | 'trust';

export interface PolicyRecord {
  id: string;
  name: string;
  kind: PolicyKind;
  document: PolicyDocument;
  description?: string;
  /** Free-form labels used by the UI for filtering. */
  labels?: string[];
}

export interface Account {
  id: string;
  name: string;
  /** Organizational unit this account belongs to ('' for the org root). */
  orgUnitId: string;
  /** SCPs attached directly to the account. */
  scpPolicyIds: string[];
  description?: string;
}

export interface OrgUnit {
  id: string;
  name: string;
  parentId: string | null;
  scpPolicyIds: string[];
}

export interface TagMap {
  [key: string]: string;
}

export interface User {
  id: string;
  name: string;
  arn: string;
  accountId: string;
  groupIds: string[];
  managedPolicyIds: string[];
  inlinePolicyIds: string[];
  boundaryPolicyId: string | null;
  tags: TagMap;
  description?: string;
}

export interface Group {
  id: string;
  name: string;
  arn: string;
  managedPolicyIds: string[];
  inlinePolicyIds: string[];
  description?: string;
}

export interface Role {
  id: string;
  name: string;
  arn: string;
  accountId: string;
  trustPolicyId: string;
  managedPolicyIds: string[];
  inlinePolicyIds: string[];
  boundaryPolicyId: string | null;
  tags: TagMap;
  description?: string;
}

export interface ResourcePolicy {
  id: string;
  name: string;
  /** Resource ARNs (wildcards allowed) this policy is attached to. */
  resourceArns: string[];
  /** Policy id that holds the document. */
  policyId: string;
  description?: string;
}

export type ResourceType =
  | 'bucket'
  | 'object'
  | 'instance'
  | 'role'
  | 'secret'
  | 'queue'
  | 'log-group'
  | 'kms-key'
  | 'other';

export interface ResourceEntry {
  arn: string;
  name: string;
  accountId: string;
  type: ResourceType;
  tags: TagMap;
  description?: string;
}

export interface Dataset {
  meta: {
    name: string;
    generatedAt: string;
    description: string;
  };
  accounts: Account[];
  orgUnits: OrgUnit[];
  policies: PolicyRecord[];
  users: User[];
  groups: Group[];
  roles: Role[];
  resourcePolicies: ResourcePolicy[];
  resources: ResourceEntry[];
}

/** Three-valued logic result used throughout the evaluator. */
export type Tri = 'match' | 'no-match' | 'unknown';

export interface ConditionKeyContext {
  /** Present keys map to an array of values. An empty array means "present but null". */
  [key: string]: string[];
}

export interface RequestContext {
  action: string;
  resource: string;
  keys: ConditionKeyContext;
  /** How to treat condition keys that are not present in `keys`. Defaults to 'unknown'. */
  missingKeys: 'unknown' | 'absent';
  /** Optional tags on the target resource, exposed as aws:ResourceTag/<key>. */
  resourceTags?: TagMap;
  /** Optional request tags, exposed as aws:RequestTag/<key> and aws:TagKeys. */
  requestTags?: TagMap;
}

export interface ConditionEvaluation {
  operator: string;
  key: string;
  policyValues: Scalar[];
  contextValues: string[] | null;
  keyState: 'present' | 'absent' | 'unknown';
  outcome: Tri;
  note?: string;
}

export interface StatementEvaluation {
  policyId: string;
  policyName: string;
  policyKind: PolicyKind;
  statementIndex: number;
  sid: string | null;
  effect: Effect;
  actionOutcome: Tri;
  resourceOutcome: Tri;
  principalOutcome: Tri;
  conditions: ConditionEvaluation[];
  conditionOutcome: Tri;
  outcome: Tri;
  /** Set when the statement does not apply because it lacks required elements. */
  issue?: string;
}

export interface Evidence {
  policyId: string;
  policyName: string;
  policyKind: PolicyKind;
  statementIndex: number;
  sid: string | null;
  label: string;
  detail?: string;
}

export type Verdict = 'Allow' | 'Deny' | 'Maybe' | 'ImplicitDeny';

export interface ReasonStep {
  id: string;
  title: string;
  outcome: Tri | 'info';
  detail: string;
  evidence?: Evidence[];
}

export interface Decision {
  verdict: Verdict;
  summary: string;
  /** Identity or resource-policy grants that matched. */
  allowEvidence: Evidence[];
  denyEvidence: Evidence[];
  /** Condition keys the result depends on that were not supplied. */
  missingKeys: string[];
  steps: ReasonStep[];
  /** Statement-level results, used by the UI for the detailed chain. */
  statements: StatementEvaluation[];
  /** Which resource-based policies were considered. */
  resourcePolicyIds: string[];
  /** SCP levels, each with its aggregate result. */
  scpLevels: { levelName: string; outcome: Tri; policyIds: string[] }[];
  boundary?: { policyId: string; policyName: string; outcome: Tri } | null;
}

export interface PrincipalRef {
  type: 'user' | 'role';
  id: string;
  name: string;
  arn: string;
  accountId: string;
  tags: TagMap;
  description?: string;
}

export interface WhoCanEntry {
  principal: PrincipalRef;
  decision: Decision;
}

export interface WhoCanResult {
  entries: WhoCanEntry[];
  missingKeys: string[];
}
