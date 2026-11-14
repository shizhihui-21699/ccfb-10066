/**
 * Import / export helpers for policy documents and whole datasets.
 *
 * The validator is deliberately forgiving about unknown elements (imported
 * documents may be newer than this tool) but strict about the pieces the
 * evaluator depends on.
 */

import type { Dataset, PolicyDocument, PolicyKind, Statement } from './types';

export interface ValidationIssue {
  level: 'error' | 'warning';
  message: string;
}

export interface ParsedDocument {
  document: PolicyDocument;
  issues: ValidationIssue[];
}

export type ParseResult =
  | { ok: true; documents: ParsedDocument[]; isDataset: false }
  | { ok: true; dataset: Dataset; isDataset: true; issues: ValidationIssue[] }
  | { ok: false; errors: string[] };

const VALID_KINDS: PolicyKind[] = ['managed', 'inline', 'boundary', 'scp', 'resource', 'trust'];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Normalizes `Statement` to an array and validates its required members. */
function normalizeDocument(raw: unknown, path: string): ParsedDocument {
  const issues: ValidationIssue[] = [];

  if (!isObject(raw)) {
    throw new Error(`${path} 不是一个 JSON 对象`);
  }

  const version = raw.Version;
  if (typeof version !== 'string') {
    issues.push({ level: 'error', message: `${path}: 缺少 Version 字段（应为 "2012-10-17"）` });
  } else if (version === '2008-10-17') {
    issues.push({
      level: 'warning',
      message: `${path}: Version "2008-10-17" 中策略变量按字面量处理，本工具会按 2012-10-17 展开变量`,
    });
  } else if (version !== '2012-10-17') {
    issues.push({ level: 'warning', message: `${path}: 未识别的 Version "${version}"，将按 2012-10-17 处理` });
  }

  const rawStatement = raw.Statement;
  if (rawStatement === undefined) {
    issues.push({ level: 'error', message: `${path}: 缺少 Statement 字段` });
    return {
      document: { Version: typeof version === 'string' ? version : '2012-10-17', Statement: [] },
      issues,
    };
  }

  const statements = Array.isArray(rawStatement) ? rawStatement : [rawStatement];
  if (!statements.length) {
    issues.push({ level: 'warning', message: `${path}: Statement 为空数组` });
  }

  const normalized: Statement[] = statements.map((entry, index) => {
    const label = `${path} Statement[${index}]`;
    if (!isObject(entry)) {
      issues.push({ level: 'error', message: `${label}: 不是对象` });
      return { Effect: 'Deny' };
    }
    const statement = entry as unknown as Statement;

    if (statement.Effect !== 'Allow' && statement.Effect !== 'Deny') {
      issues.push({ level: 'error', message: `${label}: Effect 必须是 "Allow" 或 "Deny"` });
    }
    if (statement.Action === undefined && statement.NotAction === undefined) {
      issues.push({ level: 'error', message: `${label}: 必须包含 Action 或 NotAction` });
    }
    if (statement.Action !== undefined && statement.NotAction !== undefined) {
      issues.push({ level: 'error', message: `${label}: Action 与 NotAction 不能同时出现` });
    }
    if (statement.Resource !== undefined && statement.NotResource !== undefined) {
      issues.push({ level: 'error', message: `${label}: Resource 与 NotResource 不能同时出现` });
    }
    if (statement.Principal !== undefined && statement.NotPrincipal !== undefined) {
      issues.push({ level: 'error', message: `${label}: Principal 与 NotPrincipal 不能同时出现` });
    }
    if (statement.Condition !== undefined && !isObject(statement.Condition)) {
      issues.push({ level: 'error', message: `${label}: Condition 必须是对象` });
    }
    return statement;
  });

  return {
    document: {
      Version: typeof version === 'string' ? version : '2012-10-17',
      ...(typeof raw.Id === 'string' ? { Id: raw.Id } : {}),
      Statement: normalized,
    },
    issues,
  };
}

/** Sanity-checks an imported dataset object. */
export function validateDataset(raw: unknown): { dataset: Dataset; issues: ValidationIssue[] } {
  if (!isObject(raw)) throw new Error('数据集必须是 JSON 对象');
  const issues: ValidationIssue[] = [];

  for (const key of ['accounts', 'orgUnits', 'policies', 'users', 'groups', 'roles', 'resourcePolicies'] as const) {
    if (!Array.isArray(raw[key])) {
      throw new Error(`数据集缺少数组字段 ${key}`);
    }
  }

  const dataset = raw as unknown as Dataset;
  if (!Array.isArray(dataset.resources)) {
    issues.push({ level: 'warning', message: '数据集缺少 resources 字段，资源下拉列表将不可用' });
    dataset.resources = [];
  }
  if (!isObject(dataset.meta)) {
    issues.push({ level: 'warning', message: '数据集缺少 meta 字段' });
    dataset.meta = {
      name: '导入的数据集',
      generatedAt: new Date().toISOString(),
      description: '',
    };
  }

  let invalidPolicies = 0;
  for (const policy of dataset.policies) {
    if (!isObject(policy.document) || policy.document.Statement === undefined) {
      invalidPolicies += 1;
      issues.push({ level: 'error', message: `策略 ${policy.id} 缺少有效的 document.Statement` });
    }
    if (!VALID_KINDS.includes(policy.kind)) {
      issues.push({ level: 'warning', message: `策略 ${policy.id} 的 kind "${policy.kind}" 未识别` });
    }
  }
  if (invalidPolicies === 0) {
    issues.push({ level: 'warning', message: `已加载 ${dataset.policies.length} 条策略、${dataset.users.length} 个用户、${dataset.roles.length} 个角色` });
  }

  return { dataset, issues };
}

/**
 * Parses pasted JSON. Accepts a single policy document, an array of policy
 * documents, or a whole dataset.
 */
export function parsePolicyJson(text: string): ParseResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, errors: [`JSON 解析失败：${message}`] };
  }

  // Whole dataset?
  if (isObject(raw) && Array.isArray(raw.policies) && Array.isArray(raw.accounts)) {
    try {
      const { dataset, issues } = validateDataset(raw);
      return { ok: true, dataset, isDataset: true, issues };
    } catch (error) {
      return { ok: false, errors: [error instanceof Error ? error.message : String(error)] };
    }
  }

  try {
    if (Array.isArray(raw)) {
      const documents = raw.map((entry, index) => normalizeDocument(entry, `文档[${index}]`));
      return { ok: true, documents, isDataset: false };
    }
    const single = normalizeDocument(raw, '文档');
    return { ok: true, documents: [single], isDataset: false };
  } catch (error) {
    return { ok: false, errors: [error instanceof Error ? error.message : String(error)] };
  }
}

/** Builds a unique policy id for an imported document. */
export function makePolicyId(prefix = 'custom'): string {
  const now = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 7);
  return `${prefix}-${now}-${rand}`;
}

/** Human-readable JSON for the editor. */
export function prettyDocument(document: PolicyDocument): string {
  return JSON.stringify(document, null, 2);
}
