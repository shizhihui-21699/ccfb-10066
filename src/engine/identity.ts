/**
 * Identity modelling: turns dataset users/roles into principal identities and
 * derives the implicit condition keys AWS would supply for them.
 */

import type {
  ConditionKeyContext,
  Dataset,
  PrincipalRef,
  RequestContext,
  Role,
  TagMap,
  User,
} from './types';

export interface PrincipalIdentity {
  /** ARN used for principal matching — the role ARN for roles. */
  arn: string;
  /** Assumed-role session ARN, when the principal acts through a role session. */
  sessionArn?: string;
  accountId: string;
  tags: TagMap;
  servicePrincipal?: string;
  federatedProviders: string[];
  canonicalUserId?: string;
  /** IAM user name, backing `${aws:username}`. */
  userName?: string;
  /** Unique principal id, backing `${aws:userid}`. */
  userId?: string;
}

export function roleSessionArn(roleArn: string, sessionName = 'session'): string {
  const parts = roleArn.split(':');
  // arn:aws:iam::123456789012:role/name
  const account = parts[4] ?? '';
  const name = parts[5]?.replace(/^role\//, '') ?? 'role';
  return `arn:aws:sts::${account}:assumed-role/${name}/${sessionName}`;
}

export function identityForUser(user: User): PrincipalIdentity {
  return {
    arn: user.arn,
    accountId: user.accountId,
    tags: user.tags ?? {},
    federatedProviders: [],
    userName: user.name,
    userId: user.id,
  };
}

export function identityForRole(role: Role): PrincipalIdentity {
  return {
    arn: role.arn,
    sessionArn: roleSessionArn(role.arn),
    accountId: role.accountId,
    tags: role.tags ?? {},
    federatedProviders: [],
    userName: role.name,
    userId: role.id,
  };
}

/**
 * Builds the request context, supplementing explicitly supplied keys with
 * implicit AWS keys derived from the principal, resource tags, and request tags.
 */
export function buildContext(
  base: RequestContext,
  identity: PrincipalIdentity | null,
  resourceTags?: TagMap,
  requestTags?: TagMap,
): RequestContext {
  const keys: ConditionKeyContext = { ...base.keys };

  const setIfMissing = (key: string, value: string | undefined | null) => {
    if (value === undefined || value === null) return;
    if (keys[key] === undefined) keys[key] = [value];
  };

  if (identity) {
    setIfMissing('aws:PrincipalArn', identity.sessionArn ?? identity.arn);
    setIfMissing('aws:PrincipalAccount', identity.accountId);
    if (identity.userName) setIfMissing('aws:username', identity.userName);
    if (identity.userId) setIfMissing('aws:userid', identity.userId);
    for (const [tagKey, tagValue] of Object.entries(identity.tags ?? {})) {
      setIfMissing(`aws:PrincipalTag/${tagKey}`, tagValue);
    }
    if (identity.servicePrincipal) setIfMissing('aws:PrincipalServiceName', identity.servicePrincipal);
  }

  const tags = resourceTags ?? base.resourceTags;
  if (tags) {
    for (const [tagKey, tagValue] of Object.entries(tags)) {
      setIfMissing(`aws:ResourceTag/${tagKey}`, tagValue);
    }
  }

  const reqTags = requestTags ?? base.requestTags;
  if (reqTags) {
    for (const [tagKey, tagValue] of Object.entries(reqTags)) {
      setIfMissing(`aws:RequestTag/${tagKey}`, tagValue);
    }
    if (keys['aws:TagKeys'] === undefined) {
      keys['aws:TagKeys'] = Object.keys(reqTags);
    }
  }

  return { ...base, keys };
}

/** Lists principals the UI can evaluate. */
export function allPrincipals(dataset: Dataset): PrincipalRef[] {
  const users: PrincipalRef[] = dataset.users.map((user) => ({
    type: 'user',
    id: user.id,
    name: user.name,
    arn: user.arn,
    accountId: user.accountId,
    tags: user.tags ?? {},
    description: user.description,
  }));
  const roles: PrincipalRef[] = dataset.roles.map((role) => ({
    type: 'role',
    id: role.id,
    name: role.name,
    arn: role.arn,
    accountId: role.accountId,
    tags: role.tags ?? {},
    description: role.description,
  }));
  return [...users, ...roles];
}

