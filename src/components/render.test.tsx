import { describe, expect, it } from 'vitest';
import { renderToString } from 'react-dom/server';
import { createElement } from 'react';
import sample from '../data/sample-dataset.json';
import type { Dataset } from '../engine/types';
import { OverviewPage } from './OverviewPage';
import { CanIPage } from './CanIPage';
import { WhoCanPage } from './WhoCanPage';
import { PoliciesPage } from './PoliciesPage';

const dataset = sample as unknown as Dataset;
const stats = {
  policies: dataset.policies.length,
  statements: 367,
  accounts: dataset.accounts.length,
  users: dataset.users.length,
  roles: dataset.roles.length,
  resourcePolicies: dataset.resourcePolicies.length,
};

describe('page rendering', () => {
  it('overview lists org units and traps', () => {
    const html = renderToString(createElement(OverviewPage, { dataset, stats, onOpenTrap: () => {} }));
    expect(html).toContain('组织与 SCP 层级');
    expect(html).toContain('样例中的陷阱');
    expect(html).toContain('SCP 前缀缺口');
  });

  it('can-i shows a verdict and reason chain for a planted trap', () => {
    const html = renderToString(
      createElement(CanIPage, {
        dataset,
        initialPrincipalId: 'role-prod-storage-admin',
        initialAction: 's3:PutBucketPolicy',
        initialResource: 'arn:aws:s3:::production-payments-archive',
      }),
    );
    expect(html).toContain('理由链');
    expect(html).toContain('组织级策略');
  });

  it('can-i shows an implicit deny for a protected bucket-policy write', () => {
    const html = renderToString(
      createElement(CanIPage, {
        dataset,
        initialPrincipalId: 'usr-platform-lead',
        initialAction: 's3:PutBucketPolicy',
        initialResource: 'arn:aws:s3:::prod-artifacts-build',
      }),
    );
    expect(html).toContain('显式拒绝');
  });

  it('who-can lists principals with verdict badges', () => {
    const html = renderToString(createElement(WhoCanPage, { dataset }));
    expect(html).toContain('反查条件');
    expect(html).toContain('storage-lead');
  });

  it('policies page shows the library and import form', () => {
    const html = renderToString(
      createElement(PoliciesPage, {
        dataset,
        onImport: () => 'x',
        onReplaceDataset: () => {},
        onReset: () => {},
        datasetIsSample: true,
      }),
    );
    expect(html).toContain('策略库');
    expect(html).toContain('导入策略文档');
  });
});
