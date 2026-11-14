import { describe, expect, it } from 'vitest';
import { parsePolicyJson, validateDataset, prettyDocument } from './import';

const VALID = {
  Version: '2012-10-17',
  Statement: [
    { Sid: 'Allow', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::bucket/*' },
  ],
};

describe('parsePolicyJson', () => {
  it('accepts a single document and normalizes Statement to an array', () => {
    const parsed = parsePolicyJson(JSON.stringify(VALID));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok || parsed.isDataset) throw new Error('unexpected shape');
    expect(parsed.documents).toHaveLength(1);
    expect(Array.isArray(parsed.documents[0].document.Statement)).toBe(true);
    expect(parsed.documents[0].issues.filter((issue) => issue.level === 'error')).toHaveLength(0);
  });

  it('accepts an array of documents', () => {
    const parsed = parsePolicyJson(JSON.stringify([VALID, VALID]));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok || parsed.isDataset) throw new Error('unexpected shape');
    expect(parsed.documents).toHaveLength(2);
  });

  it('reports invalid JSON with a readable message', () => {
    const parsed = parsePolicyJson('{ not json');
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error('expected failure');
    expect(parsed.errors[0]).toContain('JSON 解析失败');
  });

  it('flags missing Version, Effect and Action', () => {
    const parsed = parsePolicyJson(
      JSON.stringify({ Statement: [{ Resource: '*' }] }),
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok || parsed.isDataset) throw new Error('unexpected shape');
    const messages = parsed.documents[0].issues.map((issue) => issue.message).join('\n');
    expect(messages).toContain('Version');
    expect(messages).toContain('Effect');
    expect(messages).toContain('Action');
  });

  it('rejects documents with both Action and NotAction', () => {
    const parsed = parsePolicyJson(
      JSON.stringify({
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Action: 's3:*', NotAction: 's3:GetObject', Resource: '*' }],
      }),
    );
    if (!parsed.ok || parsed.isDataset) throw new Error('unexpected shape');
    expect(parsed.documents[0].issues.some((issue) => issue.message.includes('不能同时出现'))).toBe(true);
  });

  it('accepts an older Version with a warning', () => {
    const parsed = parsePolicyJson(JSON.stringify({ ...VALID, Version: '2008-10-17' }));
    if (!parsed.ok || parsed.isDataset) throw new Error('unexpected shape');
    expect(parsed.documents[0].issues.some((issue) => issue.level === 'warning')).toBe(true);
  });

  it('detects a whole dataset payload', () => {
    const parsed = parsePolicyJson(
      JSON.stringify({
        meta: { name: 'x', generatedAt: 'now', description: '' },
        accounts: [],
        orgUnits: [],
        policies: [],
        users: [],
        groups: [],
        roles: [],
        resourcePolicies: [],
      }),
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) throw new Error('unexpected failure');
    expect(parsed.isDataset).toBe(true);
  });
});

describe('validateDataset', () => {
  it('adds an empty resources array when missing', () => {
    const { dataset, issues } = validateDataset({
      meta: { name: 'x', generatedAt: 'now', description: '' },
      accounts: [],
      orgUnits: [],
      policies: [],
      users: [],
      groups: [],
      roles: [],
      resourcePolicies: [],
    });
    expect(dataset.resources).toEqual([]);
    expect(issues.some((issue) => issue.message.includes('resources'))).toBe(true);
  });

  it('throws on a non-object', () => {
    expect(() => validateDataset(42)).toThrow();
  });

  it('throws when required arrays are missing', () => {
    expect(() => validateDataset({ policies: [] })).toThrow(/accounts/);
  });
});

describe('prettyDocument', () => {
  it('produces stable two-space JSON', () => {
    const text = prettyDocument(VALID as never);
    expect(text).toContain('\n  "Version"');
    expect(JSON.parse(text)).toEqual(VALID);
  });
});
