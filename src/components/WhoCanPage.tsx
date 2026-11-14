import { useMemo, useState } from 'react';
import { whoCan } from '../engine/decision';
import type { Dataset, Verdict, WhoCanEntry } from '../engine/types';
import { Card, Empty, KindBadge, Notice, VerdictBadge } from './primitives';
import { ReasonChain } from './ReasonChain';

const PRESET_ACTIONS = [
  's3:DeleteObject',
  's3:DeleteBucket',
  's3:PutBucketPolicy',
  's3:PutObject',
  's3:GetObject',
  'kms:Decrypt',
  'secretsmanager:GetSecretValue',
  'sts:AssumeRole',
  'iam:CreateAccessKey',
];

const VERDICT_FILTERS: { value: Verdict; label: string }[] = [
  { value: 'Allow', label: '允许' },
  { value: 'Maybe', label: '无法确定' },
  { value: 'ImplicitDeny', label: '隐式拒绝' },
  { value: 'Deny', label: '显式拒绝' },
];

export function WhoCanPage({ dataset }: { dataset: Dataset }) {
  const [action, setAction] = useState('s3:DeleteObject');
  const [resource, setResource] = useState(
    'arn:aws:s3:::production-payments-archive/2026/11/settlement-batch-0042.parquet',
  );
  const [activeFilters, setActiveFilters] = useState<Verdict[]>(['Allow', 'Maybe', 'ImplicitDeny', 'Deny']);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tagFilter, setTagFilter] = useState('');

  const result = useMemo(() => {
    if (!action.trim() || !resource.trim()) return null;
    return whoCan({
      dataset,
      action: action.trim(),
      resource: resource.trim(),
      keys: { 'aws:SecureTransport': 'true' },
      missingKeys: 'absent',
      verdicts: activeFilters,
    });
  }, [dataset, action, resource, activeFilters]);

  const visibleEntries = useMemo(() => {
    if (!result) return [];
    const needle = tagFilter.trim().toLowerCase();
    if (!needle) return result.entries;
    return result.entries.filter(
      (entry) =>
        entry.principal.name.toLowerCase().includes(needle) ||
        entry.principal.id.toLowerCase().includes(needle) ||
        entry.principal.accountId.includes(needle) ||
        Object.entries(entry.principal.tags).some(
          ([key, value]) => key.toLowerCase().includes(needle) || value.toLowerCase().includes(needle),
        ),
    );
  }, [result, tagFilter]);

  const counts = useMemo(() => {
    const base: Record<Verdict, number> = { Allow: 0, Deny: 0, Maybe: 0, ImplicitDeny: 0 };
    if (!result) return base;
    for (const entry of result.entries) base[entry.decision.verdict] += 1;
    return base;
  }, [result]);

  const selected: WhoCanEntry | null =
    visibleEntries.find((entry) => entry.principal.id === selectedId) ?? visibleEntries[0] ?? null;

  const toggleFilter = (verdict: Verdict) => {
    setActiveFilters((current) =>
      current.includes(verdict) ? current.filter((value) => value !== verdict) : [...current, verdict],
    );
  };

  return (
    <div className="page">
      <div className="page-header">
        <h2>谁能做这个操作 · 反查</h2>
        <p>
          对数据集中的每个用户与角色逐一求值，回答“谁能对某资源做某操作”。结果按允许 → 无法确定 → 隐式拒绝 →
          显式拒绝排序，点击任意行查看理由链。
        </p>
      </div>

      <Card title="反查条件">
        <div className="field-grid">
          <div className="field">
            <label htmlFor="who-action">操作 Action</label>
            <input
              id="who-action"
              type="text"
              list="who-action-presets"
              value={action}
              onChange={(event) => setAction(event.target.value)}
            />
            <datalist id="who-action-presets">
              {PRESET_ACTIONS.map((preset) => (
                <option key={preset} value={preset} />
              ))}
            </datalist>
          </div>
          <div className="field">
            <label htmlFor="who-resource">资源 Resource</label>
            <input
              id="who-resource"
              type="text"
              list="who-resource-presets"
              value={resource}
              onChange={(event) => setResource(event.target.value)}
            />
            <datalist id="who-resource-presets">
              {dataset.resources.map((entry) => (
                <option key={entry.arn} value={entry.arn} />
              ))}
            </datalist>
          </div>
          <div className="field">
            <label htmlFor="who-filter">按名称 / 账号 / 标签过滤结果</label>
            <input id="who-filter" type="text" value={tagFilter} onChange={(event) => setTagFilter(event.target.value)} placeholder="例如 data-eng" />
          </div>
        </div>

        <div className="row" style={{ marginTop: 14 }}>
          <span className="faint" style={{ fontSize: 12 }}>
            结论筛选：
          </span>
          {VERDICT_FILTERS.map((filter) => (
            <button
              key={filter.value}
              className={`btn small ${activeFilters.includes(filter.value) ? 'primary' : 'ghost'}`}
              onClick={() => toggleFilter(filter.value)}
            >
              {filter.label} · {counts[filter.value]}
            </button>
          ))}
        </div>
      </Card>

      {result ? (
        <div className="split who-split" style={{ marginTop: 14 }}>
          <Card title={`结果（${visibleEntries.length} 个身份）`} hint="按结论排序">
            {visibleEntries.length === 0 ? (
              <Empty>没有符合筛选条件的身份。</Empty>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>身份（账号见 ARN）</th>
                      <th>结论</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleEntries.map((entry) => (
                      <tr
                        key={entry.principal.id}
                        className="clickable hover-row"
                        onClick={() => setSelectedId(entry.principal.id)}
                        style={{
                          background:
                            selected?.principal.id === entry.principal.id ? 'rgba(90,169,255,0.08)' : undefined,
                        }}
                      >
                        <td>
                          <div>
                            {entry.principal.type === 'user' ? '用户' : '角色'} · <strong>{entry.principal.name}</strong>
                          </div>
                          <div className="faint mono" style={{ fontSize: 11 }}>
                            {entry.principal.arn}
                          </div>
                          {Object.keys(entry.principal.tags).length ? (
                            <div className="chip-row" style={{ marginTop: 4 }}>
                              {Object.entries(entry.principal.tags).slice(0, 2).map(([key, value]) => (
                                <span className="chip" key={key}>
                                  {key}={value}
                                </span>
                              ))}
                              {Object.keys(entry.principal.tags).length > 2 ? (
                                <span className="faint" style={{ fontSize: 11 }}>
                                  +{Object.keys(entry.principal.tags).length - 2}
                                </span>
                              ) : null}
                            </div>
                          ) : null}
                        </td>
                        <td>
                          <VerdictBadge verdict={entry.decision.verdict} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card
            title={selected ? `理由链 · ${selected.principal.name}` : '理由链'}
            hint={selected ? selected.decision.summary : undefined}
          >
            {selected ? (
              <>
                {selected.decision.missingKeys.length ? (
                  <Notice level="warn">
                    依赖未提供的条件键：<span className="mono">{selected.decision.missingKeys.join('、')}</span>
                  </Notice>
                ) : null}
                <div style={{ marginTop: selected.decision.missingKeys.length ? 12 : 0 }}>
                  <ReasonChain decision={selected.decision} />
                </div>
                {selected.decision.resourcePolicyIds.length ? (
                  <div className="row" style={{ marginTop: 12 }}>
                    <span className="faint" style={{ fontSize: 12 }}>
                      涉及资源策略：
                    </span>
                    {selected.decision.resourcePolicyIds.map((id) => {
                      const policy = dataset.policies.find((candidate) => candidate.id === id);
                      if (!policy) return null;
                      return (
                        <span className="chip" key={id}>
                          <KindBadge kind="resource" /> {policy.name}
                        </span>
                      );
                    })}
                  </div>
                ) : null}
              </>
            ) : (
              <Empty>点击左侧任意身份查看理由链。</Empty>
            )}
          </Card>
        </div>
      ) : (
        <Empty>请填写操作与资源。</Empty>
      )}
    </div>
  );
}
