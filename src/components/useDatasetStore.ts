import { useCallback, useMemo, useState } from 'react';
import type { Dataset, PolicyDocument, PolicyKind } from '../engine/types';
import { makePolicyId } from '../engine/import';

export interface CustomAttachment {
  policyId: string;
  principalId: string;
  kind: 'managed' | 'inline' | 'boundary' | 'scp' | 'resource';
  /** For resource policies: the attached resource ARNs. */
  resourceArns?: string[];
}

export interface AppState {
  dataset: Dataset;
  /** Imported documents not yet attached to anything. */
  customPolicies: { id: string; name: string; kind: PolicyKind; document: PolicyDocument }[];
}

export function useDatasetStore(initial: Dataset) {
  const [dataset, setDataset] = useState<Dataset>(initial);
  const [customPolicies, setCustomPolicies] = useState<AppState['customPolicies']>([]);
  const [activeDatasetName, setActiveDatasetName] = useState(initial.meta.name);

  const replaceDataset = useCallback((next: Dataset) => {
    setDataset(next);
    setCustomPolicies([]);
    setActiveDatasetName(next.meta.name);
  }, []);

  const resetToSample = useCallback(() => {
    replaceDataset(initial);
  }, [initial, replaceDataset]);

  /**
   * Adds a policy document and attaches it to a principal (or, for resource
   * policies, to a set of resource ARNs).
   */
  const addPolicy = useCallback(
    (input: {
      name: string;
      kind: PolicyKind;
      document: PolicyDocument;
      principalId?: string;
      resourceArns?: string[];
    }) => {
      const id = makePolicyId(input.kind);
      const policy = {
        id,
        name: input.name,
        kind: input.kind,
        document: input.document,
        labels: ['imported'],
      };

      setDataset((current) => {
        const next: Dataset = {
          ...current,
          policies: [...current.policies, policy],
          users: current.users.map((user) => ({ ...user })),
          roles: current.roles.map((role) => ({ ...role })),
          groups: current.groups.map((group) => ({ ...group })),
          resourcePolicies: [...current.resourcePolicies],
        };

        if (input.kind === 'boundary' && input.principalId) {
          if (input.principalId.startsWith('usr-')) {
            const target = next.users.find((user) => user.id === input.principalId);
            if (target) target.boundaryPolicyId = id;
          } else {
            const target = next.roles.find((role) => role.id === input.principalId);
            if (target) target.boundaryPolicyId = id;
          }
          return next;
        }

        if (input.kind === 'resource') {
          next.resourcePolicies.push({
            id: makePolicyId('attachment'),
            name: `${input.name}（挂载）`,
            resourceArns: input.resourceArns?.length ? input.resourceArns : ['*'],
            policyId: id,
            description: '导入的资源策略',
          });
          return next;
        }

        if (input.principalId && input.kind !== 'scp') {
          if (input.principalId.startsWith('usr-')) {
            const target = next.users.find((user) => user.id === input.principalId);
            if (target) {
              if (input.kind === 'inline') target.inlinePolicyIds.push(id);
              else target.managedPolicyIds.push(id);
            }
          } else {
            const target = next.roles.find((role) => role.id === input.principalId);
            if (target) {
              if (input.kind === 'inline') target.inlinePolicyIds.push(id);
              else target.managedPolicyIds.push(id);
            }
          }
        }

        if (input.kind === 'scp' && input.principalId) {
          // Attach an SCP to the account whose id matches, or to the account of
          // the selected principal.
          const accountId = input.principalId.startsWith('usr-')
            ? next.users.find((user) => user.id === input.principalId)?.accountId
            : next.roles.find((role) => role.id === input.principalId)?.accountId;
          if (accountId) {
            const account = next.accounts.find((candidate) => candidate.id === accountId);
            if (account) account.scpPolicyIds = [...account.scpPolicyIds, id];
          }
        }

        return next;
      });

      setCustomPolicies((current) => [
        ...current,
        { id, name: input.name, kind: input.kind, document: input.document },
      ]);
      return id;
    },
    [],
  );

  const stats = useMemo(() => {
    const statementCount = dataset.policies.reduce((sum, policy) => {
      const list = Array.isArray(policy.document.Statement)
        ? policy.document.Statement
        : [policy.document.Statement];
      return sum + list.length;
    }, 0);
    return {
      policies: dataset.policies.length,
      statements: statementCount,
      accounts: dataset.accounts.length,
      users: dataset.users.length,
      roles: dataset.roles.length,
      resourcePolicies: dataset.resourcePolicies.length,
    };
  }, [dataset]);

  return {
    dataset,
    activeDatasetName,
    customPolicies,
    stats,
    replaceDataset,
    resetToSample,
    addPolicy,
  };
}
