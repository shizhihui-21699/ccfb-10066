import { useMemo, useState } from 'react';
import { decide, collectIdentityPolicies, boundaryFor, resourcePoliciesFor, scpLevelsFor } from '../engine/decision';
import type { Dataset, Decision, PrincipalRef } from '../engine/types';
import { Card, KindBadge, Notice, VerdictBadge, Empty } from './primitives';
import { ReasonChain, StatementTable } from './ReasonChain';

const PRESET_ACTIONS = [
  's3:GetObject',
  's3:PutObject',
  's3:DeleteObject',
  's3:DeleteBucket',
  's3:PutBucketPolicy',
  's3:ListBucket',
  'kms:Decrypt',
  'kms:ScheduleKeyDeletion',
  'secretsmanager:GetSecretValue',
  'sts:AssumeRole',
  'iam:CreateAccessKey',
  'ec2:TerminateInstances',
  'logs:FilterLogEvents',
];

const PRESET_RESOURCES = [
  'arn:aws:s3:::production-payments-archive/2026/11/settlement-batch-0042.parquet',
  'arn:aws:s3:::production-payments-archive',
  'arn:aws:s3:::prod-artifacts-build/releases/api-1.24.0.tar.gz',
  'arn:aws:s3:::prod-artifacts-build',
  'arn:aws:s3:::shared-audit-logs',
  'arn:aws:secretsmanager:cn-north-1:111122223333:secret:prod/payments/db-password',
  'arn:aws:kms:cn-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
];

interface KeyRow {
  key: string;
  value: string;
}

function principalsOf(dataset: Dataset): PrincipalRef[] {
  return [
    ...dataset.users.map<PrincipalRef>((user) => ({
      type: 'user',
      id: user.id,
      name: user.name,
      arn: user.arn,
      accountId: user.accountId,
      tags: user.tags ?? {},
      description: user.description,
    })),
    ...dataset.roles.map<PrincipalRef>((role) => ({
      type: 'role',
      id: role.id,
      name: role.name,
      arn: role.arn,
      accountId: role.accountId,
      tags: role.tags ?? {},
      description: role.description,
    })),
  ];
}

function parseKeyRows(rows: KeyRow[]): Record<string, string | string[]> {
  const keys: Record<string, string | string[]> = {};
  for (const row of rows) {
    const key = row.key.trim();
    if (!key) continue;
    const values = row.value
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    if (!values.length) continue;
    keys[key] = values.length > 1 ? values : values[0];
  }
  return keys;
}

export function CanIPage({
  dataset,
  initialPrincipalId,
  initialAction,
  initialResource,
}: {
  dataset: Dataset;
  initialPrincipalId?: string;
  initialAction?: string;
  initialResource?: string;
}) {
  const principals = useMemo(() => principalsOf(dataset), [dataset]);
  const [principalId, setPrincipalId] = useState(initialPrincipalId ?? principals[0]?.id ?? '');
  const [action, setAction] = useState(initialAction ?? 's3:DeleteObject');
  const [resource, setResource] = useState(initialResource ?? PRESET_RESOURCES[0]);
  const [keyRows, setKeyRows] = useState<KeyRow[]>([
    { key: 'aws:SecureTransport', value: 'true' },
    { key: 'aws:SourceIp', value: '203.0.113.10' },
  ]);
  const [missingMode, setMissingMode] = useState<'unknown' | 'absent'>('unknown');
  const [showAllStatements, setShowAllStatements] = useState(false);
  const [showAllPolicies, setShowAllPolicies] = useState(false);

  const principal = principals.find((entry) => entry.id === principalId) ?? principals[0];

  const decision: Decision | null = useMemo(() => {
    if (!principal || !action.trim() || !resource.trim()) return null;
    return decide({
      dataset,
      principal,
      action: action.trim(),
      resource: resource.trim(),
      keys: parseKeyRows(keyRows),
      missingKeys: missingMode,
    });
  }, [dataset, principal, action, resource, keyRows, missingMode]);

  const contextSummary = useMemo(() => {
    if (!principal) return null;
    const identityPolicies = collectIdentityPolicies(dataset, principal);
    const boundary = boundaryFor(dataset, principal);
    const scps = scpLevelsFor(dataset, principal.accountId);
    const resourcePolicies = resourcePoliciesFor(dataset, resource);
    const account = dataset.accounts.find((entry) => entry.id === principal.accountId);
    return { identityPolicies, boundary, scps, resourcePolicies, account };
  }, [dataset, principal, resource]);

  const updateKeyRow = (index: number, patch: Partial<KeyRow>) => {
    setKeyRows((rows) => rows.map((row, rowIndex) => (rowIndex === index ? { ...row, ...patch } : row)));
  };

  return (
    <div className="page">
      <div className="page-header">
        <h2>谁能做什么 · 正向查询</h2>
        <p>
          选择一个身份，指定操作与资源，得到允许 / 拒绝结论以及逐层理由链：身份策略、权限边界、组织级 SCP、
          资源策略、显式拒绝优先与最终交集。
        </p>
      </div>

      <Card title="查询条件" hint="条件键可留空；留空时按“未知”处理并给出 Maybe 结论">
        <div className="field-grid">
          <div className="field">
            <label htmlFor="can-principal">身份</label>
            <select
              id="can-principal"
              value={principalId}
              onChange={(event) => setPrincipalId(event.target.value)}
            >
              {principals.map((entry) => (
                <option key={entry.id} value={entry.id}>
                  {entry.type === 'user' ? '用户' : '角色'} · {entry.name}（{entry.accountId}）
                </option>
              ))}
            </select>
            {principal ? (
              <span className="help">
                账号 {principal.accountId}
                {principal.tags.team ? ` · team=${principal.tags.team}` : ''}
                {principal.description ? ` · ${principal.description}` : ''}
              </span>
            ) : null}
          </div>

          <div className="field">
            <label htmlFor="can-action">操作 Action</label>
            <input
              id="can-action"
              type="text"
              list="action-presets"
              value={action}
              onChange={(event) => setAction(event.target.value)}
              placeholder="s3:DeleteObject"
            />
            <datalist id="action-presets">
              {PRESET_ACTIONS.map((preset) => (
                <option key={preset} value={preset} />
              ))}
            </datalist>
            <span className="help">支持通配，例如 s3:Get*</span>
          </div>

          <div className="field">
            <label htmlFor="can-resource">资源 Resource</label>
            <input
              id="can-resource"
              type="text"
              list="resource-presets"
              value={resource}
              onChange={(event) => setResource(event.target.value)}
              placeholder="arn:aws:s3:::bucket/key"
            />
            <datalist id="resource-presets">
              {Array.from(new Set([...PRESET_RESOURCES, ...dataset.resources.map((entry) => entry.arn)])).map(
                (preset) => <option key={preset} value={preset} />,
              )}
            </datalist>
          </div>

          <div className="field">
            <label htmlFor="can-missing">缺失条件键的处理</label>
            <select
              id="can-missing"
              value={missingMode}
              onChange={(event) => setMissingMode(event.target.value as 'unknown' | 'absent')}
            >
              <option value="unknown">按未知处理（推荐，可发现需要补充的键）</option>
              <option value="absent">按不存在处理（严格的 AWS 语义模拟）</option>
            </select>
            <span className="help">未知 → 结论为 Maybe 并列出键名；不存在 → 按文档语义求值</span>
          </div>
        </div>

        <div style={{ marginTop: 14 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            <h3 style={{ fontSize: 13 }}>请求条件键</h3>
            <div className="row">
              <button className="btn small ghost" onClick={() => setKeyRows((rows) => [...rows, { key: '', value: '' }])}>
                + 添加键
              </button>
              {keyRows.length ? (
                <button className="btn small ghost" onClick={() => setKeyRows([])}>
                  清空
                </button>
              ) : null}
            </div>
          </div>
          {keyRows.length === 0 ? (
            <div className="faint" style={{ fontSize: 12 }}>
              未提供任何条件键。
            </div>
          ) : (
            <div style={{ display: 'grid', gap: 8 }}>
              {keyRows.map((row, index) => (
                <div className="row" key={index}>
                  <input
                    type="text"
                    className="mono"
                    style={{ flex: '1 1 240px', background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 7, padding: '7px 10px' }}
                    placeholder="条件键，例如 aws:PrincipalTag/team"
                    value={row.key}
                    onChange={(event) => updateKeyRow(index, { key: event.target.value })}
                  />
                  <input
                    type="text"
                    className="mono"
                    style={{ flex: '1 1 240px', background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 7, padding: '7px 10px' }}
                    placeholder="值，多值用英文逗号分隔"
                    value={row.value}
                    onChange={(event) => updateKeyRow(index, { value: event.target.value })}
                  />
                  <button className="btn small ghost" onClick={() => setKeyRows((rows) => rows.filter((_, i) => i !== index))}>
                    移除
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Card>

      {contextSummary ? (
        <Card title="该身份与资源的策略覆盖面">
          <div className="stat-grid">
            <div className="stat">
              <div className="value">{contextSummary.identityPolicies.policies.length}</div>
              <div className="label">身份策略（含组继承）</div>
            </div>
            <div className="stat">
              <div className="value">{contextSummary.boundary ? '有' : '无'}</div>
              <div className="label">
                权限边界{contextSummary.boundary ? `：${contextSummary.boundary.name}` : ''}
              </div>
            </div>
            <div className="stat">
              <div className="value">{contextSummary.scps.length}</div>
              <div className="label">SCP 层级（根 → 账号）</div>
            </div>
            <div className="stat">
              <div className="value">{contextSummary.resourcePolicies.length}</div>
              <div className="label">命中的资源策略</div>
            </div>
          </div>
          <div className="chip-row" style={{ marginTop: 12 }}>
            {(showAllPolicies
              ? contextSummary.identityPolicies.policies
              : contextSummary.identityPolicies.policies.slice(0, 12)
            ).map((policy) => (
              <span className="chip" key={policy.id} title={policy.description}>
                <KindBadge kind={policy.kind} /> {policy.name}
              </span>
            ))}
            {contextSummary.resourcePolicies.map((policy) => (
              <span className="chip" key={policy.id} title={policy.description}>
                <KindBadge kind="resource" /> {policy.name}
              </span>
            ))}
            {contextSummary.identityPolicies.policies.length > 12 ? (
              <button className="btn small ghost" onClick={() => setShowAllPolicies((value) => !value)}>
                {showAllPolicies
                  ? '收起'
                  : `还有 ${contextSummary.identityPolicies.policies.length - 12} 条…`}
              </button>
            ) : null}
          </div>
        </Card>
      ) : null}

      {decision ? (
        <Card
          title="结论"
          action={
            <button className="btn small ghost" onClick={() => setShowAllStatements((value) => !value)}>
              {showAllStatements ? '只看命中的语句' : '展开所有语句'}
            </button>
          }
        >
          <div className="summary-bar" style={{ marginBottom: 16 }}>
            <VerdictBadge verdict={decision.verdict} large />
            <span className="summary-text">{decision.summary}</span>
          </div>

          {decision.missingKeys.length ? (
            <Notice level="warn">
              结论依赖以下尚未提供的条件键：<span className="mono">{decision.missingKeys.join('、')}</span>。补齐后重新查询可得到确定结论。
            </Notice>
          ) : null}

          <div className="split" style={{ marginTop: 14 }}>
            <div>
              <h3 style={{ fontSize: 13, margin: '0 0 8px' }}>理由链</h3>
              <ReasonChain decision={decision} />
            </div>
            <div>
              <h3 style={{ fontSize: 13, margin: '0 0 8px' }}>语句级明细</h3>
              <div className="scroll-y">
                <StatementTable
                  statements={decision.statements}
                  filter={
                    showAllStatements
                      ? undefined
                      : (evaluation) => evaluation.outcome !== 'no-match' || evaluation.conditions.length > 0
                  }
                />
              </div>
            </div>
          </div>
        </Card>
      ) : (
        <Empty>请选择身份并填写操作与资源。</Empty>
      )}
    </div>
  );
}
