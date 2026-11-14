import { useMemo } from 'react';
import { decide } from '../engine/decision';
import type { Dataset, PrincipalRef } from '../engine/types';
import { Card, KindBadge, VerdictBadge } from './primitives';
import sample from '../data/sample-dataset.json';

/**
 * Landing overview: dataset shape, org hierarchy, and the sample dataset's
 * deliberately planted over-permissions.
 */

const TRAPS = [
  {
    title: 'SCP 前缀缺口：prod-* 放过了 production-*',
    detail:
      'Prod-Guardrails 的 ProtectProdBucketPolicies 只匹配 arn:aws:s3:::prod-*，而真正的生产桶叫 production-payments-archive，于是桶策略改写没有被任何护栏拦住。',
    query: { principal: 'role-prod-storage-admin', action: 's3:PutBucketPolicy', resource: 'arn:aws:s3:::production-payments-archive' },
  },
  {
    title: 'ForAllValues + 缺少 Null 检查',
    detail:
      'Tagged-Upload-Policy 用 ForAllValues:StringEquals 限制标签键，但空集合（请求根本没带标签）也会让 ForAllValues 为真 —— 等于不要求标签。',
    query: { principal: 'usr-dataeng', action: 's3:PutObject', resource: 'arn:aws:s3:::production-payments-archive/new.parquet' },
  },
  {
    title: 'NotAction 漏掉了桶级管理动作',
    detail:
      'Shared-ReadOnly-Objects 用 NotAction 排除 PutObject/DeleteObject，看起来"只读"，但 PutBucketPolicy、DeleteBucket 等桶级动作都不在排除列表里。',
    query: { principal: 'usr-shared-ops', action: 's3:PutBucketPolicy', resource: 'arn:aws:s3:::shared-audit-logs' },
  },
  {
    title: '账号字段通配：AssumeRole 跨账号',
    detail:
      'Deployer-Prod 的 AssumeDeployRoles 把账号写成通配 arn:aws:iam::*:role/ProdDeployer，本意是同账号两个角色，实际允许扮演任何账号下的同名角色。',
    query: { principal: 'usr-deployer', action: 'sts:AssumeRole', resource: 'arn:aws:iam::444455556666:role/ProdDeployer' },
  },
  {
    title: 'IP 条件里混入 0.0.0.0/0',
    detail:
      'Corp-Network-Prod-Access 的 aws:SourceIp 列表包含 0.0.0.0/0，"仅公司网段"实际对全互联网开放。',
    query: { principal: 'usr-network', action: 's3:DeleteObject', resource: 'arn:aws:s3:::production-payments-archive/x.parquet' },
  },
  {
    title: '资源策略：Principal * + 只要求 TLS',
    detail:
      'production-payments-archive 的桶策略允许 Principal "*" 读取对象，条件仅仅是 SecureTransport=true —— 这是公开读，而不是同账号读取。',
    query: { principal: 'usr-intern', action: 's3:GetObject', resource: 'arn:aws:s3:::production-payments-archive/2026/11/settlement-batch-0042.parquet' },
  },
  {
    title: 'BoolIfExists 让 MFA 要求失效',
    detail:
      'DeletionWorker 的 DeleteObjectsWithMfa 用 BoolIfExists 检查 MultiFactorAuthPresent：键不存在时条件为真，所以不带 MFA 也能删除。',
    query: { principal: 'role-prod-mfa-delete', action: 's3:DeleteObject', resource: 'arn:aws:s3:::prod-customer-exports/old.csv' },
  },
  {
    title: '权限边界前缀同样写错',
    detail:
      'Admin-Boundary 的 AdminNoProdDeletes 只拒绝 prod-* 的删除，StorageAdmin 角色因此可以删除 production-payments-archive 这个桶本身。',
    query: { principal: 'role-prod-storage-admin', action: 's3:DeleteBucket', resource: 'arn:aws:s3:::production-payments-archive' },
  },
];

function principalOf(dataset: Dataset, id: string): PrincipalRef | null {
  const user = dataset.users.find((entry) => entry.id === id);
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
  const role = dataset.roles.find((entry) => entry.id === id);
  if (role) {
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
  return null;
}

export function OverviewPage({
  dataset,
  stats,
  onOpenTrap,
}: {
  dataset: Dataset;
  stats: { policies: number; statements: number; accounts: number; users: number; roles: number; resourcePolicies: number };
  onOpenTrap: (principalId: string, action: string, resource: string) => void;
}) {
  const unitName = (id: string | null) =>
    id ? dataset.orgUnits.find((unit) => unit.id === id)?.name ?? id : '—';

  const trapResults = useMemo(
    () =>
      TRAPS.map((trap) => {
        const principal = principalOf(dataset, trap.query.principal);
        if (!principal) return { ...trap, verdict: 'Unknown', principalName: trap.query.principal };
        const decision = decide({
          dataset,
          principal,
          action: trap.query.action,
          resource: trap.query.resource,
          keys: { 'aws:SecureTransport': 'true', 'aws:SourceIp': '198.18.7.7' },
          missingKeys: 'absent',
        });
        return { ...trap, verdict: decision.verdict, principalName: principal.name, decision };
      }),
    [dataset],
  );

  const isSample = dataset.meta.name.includes('示例') || dataset === (sample as unknown as Dataset);

  return (
    <div className="page">
      <div className="page-header">
        <h2>概览 · {dataset.meta.name}</h2>
        <p>{dataset.meta.description}</p>
      </div>

      <Card>
        <div className="stat-grid">
          <div className="stat">
            <div className="value">{stats.policies}</div>
            <div className="label">策略文档</div>
          </div>
          <div className="stat">
            <div className="value">{stats.statements}</div>
            <div className="label">策略语句</div>
          </div>
          <div className="stat">
            <div className="value">{stats.users + stats.roles}</div>
            <div className="label">用户 + 角色</div>
          </div>
          <div className="stat">
            <div className="value">{stats.accounts}</div>
            <div className="label">账号</div>
          </div>
          <div className="stat">
            <div className="value">{stats.resourcePolicies}</div>
            <div className="label">资源策略挂载</div>
          </div>
        </div>
      </Card>

      <Card title="组织与 SCP 层级" hint="SCP 需要在根 → OU → 账号每一层都有显式 Allow">
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>层级</th>
                <th>名称</th>
                <th>SCP</th>
                <th>成员</th>
              </tr>
            </thead>
            <tbody>
              {dataset.orgUnits.map((unit) => {
                const members = dataset.accounts.filter((account) => account.orgUnitId === unit.id);
                return (
                  <tr key={unit.id}>
                    <td>
                      <span className="badge scp">OU</span>
                    </td>
                    <td>
                      <strong>{unit.name}</strong>
                      <div className="faint" style={{ fontSize: 11 }}>
                        上级：{unitName(unit.parentId)}
                      </div>
                    </td>
                    <td>
                      <div className="chip-row">
                        {unit.scpPolicyIds.map((id) => {
                          const policy = dataset.policies.find((candidate) => candidate.id === id);
                          return (
                            <span className="chip" key={id}>
                              {policy?.name ?? id}
                            </span>
                          );
                        })}
                        {unit.scpPolicyIds.length === 0 ? <span className="faint">（无）</span> : null}
                      </div>
                    </td>
                    <td className="faint" style={{ fontSize: 12 }}>
                      {members.map((account) => account.name).join('、') || '—'}
                    </td>
                  </tr>
                );
              })}
              {dataset.accounts.map((account) => (
                <tr key={account.id}>
                  <td>
                    <span className="badge">账号</span>
                  </td>
                  <td>
                    <strong>{account.name}</strong>
                    <div className="faint mono" style={{ fontSize: 11 }}>
                      {account.id}
                    </div>
                  </td>
                  <td>
                    <div className="chip-row">
                      {account.scpPolicyIds.map((id) => {
                        const policy = dataset.policies.find((candidate) => candidate.id === id);
                        return (
                          <span className="chip" key={id}>
                            {policy?.name ?? id}
                          </span>
                        );
                      })}
                      {account.scpPolicyIds.length === 0 ? <span className="faint">（无）</span> : null}
                    </div>
                  </td>
                  <td className="faint" style={{ fontSize: 12 }}>
                    {dataset.users.filter((user) => user.accountId === account.id).length} 用户 ·{' '}
                    {dataset.roles.filter((role) => role.accountId === account.id).length} 角色
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {isSample ? (
        <Card title="样例中的陷阱" hint="点击任意一行，带着参数跳到正向查询">
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>看起来安全的地方</th>
                  <th>查询</th>
                  <th>实际结论</th>
                </tr>
              </thead>
              <tbody>
                {trapResults.map((trap) => (
                  <tr
                    key={trap.title}
                    className="clickable hover-row"
                    onClick={() => onOpenTrap(trap.query.principal, trap.query.action, trap.query.resource)}
                  >
                    <td style={{ maxWidth: 460 }}>
                      <strong>{trap.title}</strong>
                      <div className="faint" style={{ fontSize: 12 }}>
                        {trap.detail}
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      <div>{trap.principalName}</div>
                      <div className="dim">{trap.query.action}</div>
                      <div className="faint" style={{ wordBreak: 'break-all' }}>
                        {trap.query.resource}
                      </div>
                    </td>
                    <td>
                      {'verdict' in trap && typeof trap.verdict === 'string' ? (
                        <VerdictBadge verdict={trap.verdict} />
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="faint" style={{ fontSize: 12, marginBottom: 0 }}>
            这些陷阱覆盖了通配前缀、NotAction、ForAllValues 空集合、账号通配、IP 条件、资源策略公开访问、IfExists 语义和边界交集。
          </p>
        </Card>
      ) : null}

      <Card title="数据分布">
        <div className="split">
          <div>
            <h3 style={{ fontSize: 13, margin: '0 0 8px' }}>按类型</h3>
            <div className="chip-row">
              {(['managed', 'inline', 'boundary', 'scp', 'resource', 'trust'] as const).map((kind) => {
                const count = dataset.policies.filter((policy) => policy.kind === kind).length;
                if (!count) return null;
                return (
                  <span className="chip on" key={kind}>
                    <KindBadge kind={kind} /> {count}
                  </span>
                );
              })}
            </div>
          </div>
          <div>
            <h3 style={{ fontSize: 13, margin: '0 0 8px' }}>资源</h3>
            <div className="chip-row">
              {Array.from(new Set(dataset.resources.map((entry) => entry.type))).map((type) => (
                <span className="chip" key={type}>
                  {type} · {dataset.resources.filter((entry) => entry.type === type).length}
                </span>
              ))}
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
}
