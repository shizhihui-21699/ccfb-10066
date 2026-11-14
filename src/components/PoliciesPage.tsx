import { useMemo, useState } from 'react';
import { parsePolicyJson, prettyDocument } from '../engine/import';
import type { Dataset, PolicyKind, PolicyRecord } from '../engine/types';
import { Card, Empty, KindBadge, Notice } from './primitives';

const KIND_OPTIONS: { value: PolicyKind; label: string }[] = [
  { value: 'managed', label: '托管策略（附加到身份）' },
  { value: 'inline', label: '内联策略（附加到身份）' },
  { value: 'boundary', label: '权限边界' },
  { value: 'scp', label: '组织级 SCP' },
  { value: 'resource', label: '资源策略' },
];

const TEMPLATE = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'ExampleAllow',
      Effect: 'Allow',
      Action: ['s3:GetObject'],
      Resource: 'arn:aws:s3:::prod-artifacts-build/*',
      Condition: { Bool: { 'aws:SecureTransport': 'true' } },
    },
  ],
};

export function PoliciesPage({
  dataset,
  onImport,
  onReplaceDataset,
  onReset,
  datasetIsSample,
}: {
  dataset: Dataset;
  onImport: (input: {
    name: string;
    kind: PolicyKind;
    document: PolicyRecord['document'];
    principalId?: string;
    resourceArns?: string[];
  }) => string;
  onReplaceDataset: (next: Dataset) => void;
  onReset: () => void;
  datasetIsSample: boolean;
}) {
  const [search, setSearch] = useState('');
  const [kindFilter, setKindFilter] = useState<PolicyKind | 'all'>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [jsonText, setJsonText] = useState(prettyDocument(TEMPLATE as PolicyRecord['document']));
  const [policyName, setPolicyName] = useState('导入的自定义策略');
  const [importKind, setImportKind] = useState<PolicyKind>('managed');
  const [targetPrincipal, setTargetPrincipal] = useState('');
  const [targetResources, setTargetResources] = useState('');

  const [datasetText, setDatasetText] = useState('');
  const [feedback, setFeedback] = useState<{ level: 'info' | 'warn' | 'error'; messages: string[] } | null>(null);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return dataset.policies.filter((policy) => {
      if (kindFilter !== 'all' && policy.kind !== kindFilter) return false;
      if (!needle) return true;
      if (policy.name.toLowerCase().includes(needle)) return true;
      if (policy.id.toLowerCase().includes(needle)) return true;
      const serialized = JSON.stringify(policy.document).toLowerCase();
      return serialized.includes(needle);
    });
  }, [dataset.policies, search, kindFilter]);

  const selected = dataset.policies.find((policy) => policy.id === selectedId) ?? filtered[0] ?? null;

  const principalOptions = [
    ...dataset.users.map((user) => ({ id: user.id, label: `用户 · ${user.name}（${user.accountId}）` })),
    ...dataset.roles.map((role) => ({ id: role.id, label: `角色 · ${role.name}（${role.accountId}）` })),
  ];

  const handleImport = () => {
    const parsed = parsePolicyJson(jsonText);
    if (!parsed.ok) {
      setFeedback({ level: 'error', messages: parsed.errors });
      return;
    }
    if (parsed.isDataset) {
      setFeedback({ level: 'error', messages: ['这是完整数据集，请使用下方的“导入整套数据集”区域'] });
      return;
    }

    const hasErrors = parsed.documents.some((document) =>
      document.issues.some((issue) => issue.level === 'error'),
    );
    if (hasErrors) {
      setFeedback({
        level: 'error',
        messages: parsed.documents.flatMap((document, index) =>
          document.issues
            .filter((issue) => issue.level === 'error')
            .map((issue) => `文档 ${index + 1}：${issue.message}`),
        ),
      });
      return;
    }

    const warnings = parsed.documents.flatMap((document, index) =>
      document.issues
        .filter((issue) => issue.level === 'warning')
        .map((issue) => `文档 ${index + 1}：${issue.message}`),
    );

    let attachedCount = 0;
    for (const document of parsed.documents) {
      onImport({
        name: parsed.documents.length > 1 ? `${policyName} #${attachedCount + 1}` : policyName,
        kind: importKind,
        document: document.document,
        principalId: targetPrincipal || undefined,
        resourceArns:
          importKind === 'resource' ? targetResources.split(/[\s,]+/).filter(Boolean) : undefined,
      });
      attachedCount += 1;
    }

    setFeedback({
      level: 'info',
      messages: [
        `已导入 ${attachedCount} 个策略文档${
          targetPrincipal ? `，附加到 ${principalOptions.find((option) => option.id === targetPrincipal)?.label}` : ''
        }。`,
        ...warnings,
      ],
    });
  };

  const handleDatasetImport = () => {
    const parsed = parsePolicyJson(datasetText);
    if (!parsed.ok) {
      setFeedback({ level: 'error', messages: parsed.errors });
      return;
    }
    if (!parsed.isDataset) {
      setFeedback({ level: 'error', messages: ['这不是完整数据集；请使用“导入策略文档”区域'] });
      return;
    }
    onReplaceDataset(parsed.dataset);
    setFeedback({
      level: 'info',
      messages: [`已加载数据集：${parsed.dataset.meta.name}`, ...parsed.issues.map((issue) => issue.message)],
    });
  };

  const download = (filename: string, text: string) => {
    const blob = new URL(URL.createObjectURL(new Blob([text], { type: 'application/json' })));
    const anchor = document.createElement('a');
    anchor.href = blob.toString();
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(blob.toString());
  };

  return (
    <div className="page">
      <div className="page-header">
        <h2>策略库与导入</h2>
        <p>
          浏览当前数据集中的全部策略；导入单个策略文档（自动附加到你选择的身份 / 资源），或导入一整套数据集。
          导入的策略会立即参与求值。
        </p>
      </div>

      {feedback ? (
        <div style={{ marginBottom: 14 }}>
          {feedback.messages.map((message, index) => (
            <div key={index} style={{ marginBottom: 6 }}>
              <Notice level={feedback.level}>{message}</Notice>
            </div>
          ))}
        </div>
      ) : null}

      <Card title="导入策略文档" hint="支持单个策略、策略数组；Version 应为 2012-10-17">
        <div className="field-grid">
          <div className="field">
            <label htmlFor="import-name">策略名称</label>
            <input
              id="import-name"
              type="text"
              value={policyName}
              onChange={(event) => setPolicyName(event.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="import-kind">策略类型</label>
            <select
              id="import-kind"
              value={importKind}
              onChange={(event) => setImportKind(event.target.value as PolicyKind)}
            >
              {KIND_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="import-principal">附加到身份</label>
            <select
              id="import-principal"
              value={targetPrincipal}
              onChange={(event) => setTargetPrincipal(event.target.value)}
            >
              <option value="">不附加（仅导入到策略库）</option>
              {principalOptions.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
            <span className="help">
              边界策略会替换该身份原有边界；SCP 会附加到该身份所属账号。
            </span>
          </div>
          {importKind === 'resource' ? (
            <div className="field">
              <label htmlFor="import-resources">资源 ARN（资源策略）</label>
              <input
                id="import-resources"
                type="text"
                value={targetResources}
                onChange={(event) => setTargetResources(event.target.value)}
                placeholder="arn:aws:s3:::bucket-name"
              />
              <span className="help">多个 ARN 用逗号分隔；支持通配。</span>
            </div>
          ) : null}
        </div>

        <div className="field" style={{ marginTop: 12 }}>
          <label htmlFor="import-json">策略 JSON</label>
          <textarea
            id="import-json"
            value={jsonText}
            onChange={(event) => setJsonText(event.target.value)}
            spellCheck={false}
            style={{ minHeight: 240 }}
          />
        </div>

        <div className="row end" style={{ marginTop: 12 }}>
          <button
            className="btn ghost"
            onClick={() => {
              setJsonText(prettyDocument(TEMPLATE as PolicyRecord['document']));
            }}
          >
            重置为模板
          </button>
          <button className="btn primary" onClick={handleImport}>
            校验并导入
          </button>
        </div>
      </Card>

      <Card title="导入整套数据集" hint={datasetIsSample ? '当前为内置样例数据集' : '当前为导入的数据集'}>
        <div className="field">
          <label htmlFor="dataset-json">数据集 JSON</label>
          <textarea
            id="dataset-json"
            value={datasetText}
            onChange={(event) => setDatasetText(event.target.value)}
            placeholder='{"meta": {...}, "accounts": [...], "policies": [...]}'
            spellCheck={false}
            style={{ minHeight: 120 }}
          />
        </div>
        <div className="row end" style={{ marginTop: 12 }}>
          <button
            className="btn ghost"
            onClick={() => download('sample-dataset.json', JSON.stringify(dataset, null, 2))}
          >
            导出当前数据集
          </button>
          {!datasetIsSample ? (
            <button className="btn ghost" onClick={onReset}>
              恢复内置样例
            </button>
          ) : null}
          <button className="btn primary" onClick={handleDatasetImport}>
            加载数据集
          </button>
        </div>
      </Card>

      <Card
        title={`策略库（${filtered.length} / ${dataset.policies.length}）`}
        action={
          <div className="row">
            <input
              aria-label="搜索策略"
              type="text"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="搜索名称、id 或策略内容"
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 7, padding: '6px 10px', minWidth: 240 }}
            />
            <select
              aria-label="按类型筛选"
              value={kindFilter}
              onChange={(event) => setKindFilter(event.target.value as PolicyKind | 'all')}
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 7, padding: '6px 10px' }}
            >
              <option value="all">全部类型</option>
              {KIND_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {filtered.length === 0 ? (
          <Empty>没有匹配的策略。</Empty>
        ) : (
          <div className="split">
            <div className="scroll-y" style={{ maxHeight: 520 }}>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>策略</th>
                      <th>类型</th>
                      <th>语句</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0, 200).map((policy) => {
                      const statementCount = Array.isArray(policy.document.Statement)
                        ? policy.document.Statement.length
                        : 1;
                      return (
                        <tr
                          key={policy.id}
                          className="clickable hover-row"
                          onClick={() => setSelectedId(policy.id)}
                          style={{
                            background: selected?.id === policy.id ? 'rgba(90,169,255,0.08)' : undefined,
                          }}
                        >
                          <td>
                            <div>
                              <strong>{policy.name}</strong>
                            </div>
                            <div className="faint mono" style={{ fontSize: 11 }}>
                              {policy.id}
                            </div>
                          </td>
                          <td>
                            <KindBadge kind={policy.kind} />
                          </td>
                          <td className="num">{statementCount}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {filtered.length > 200 ? (
                <div className="faint" style={{ fontSize: 12, marginTop: 8 }}>
                  仅显示前 200 条；请使用搜索缩小范围。
                </div>
              ) : null}
            </div>

            <div>
              {selected ? (
                <>
                  <div className="row" style={{ marginBottom: 8 }}>
                    <strong>{selected.name}</strong>
                    <KindBadge kind={selected.kind} />
                    <span className="badge mono">{selected.id}</span>
                  </div>
                  {selected.description ? <p className="dim" style={{ marginTop: 0 }}>{selected.description}</p> : null}
                  <pre className="code-block" style={{ maxHeight: 440 }}>
                    {JSON.stringify(selected.document, null, 2)}
                  </pre>
                </>
              ) : (
                <Empty>选择左侧策略查看内容。</Empty>
              )}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
