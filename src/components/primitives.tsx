import type { ReactNode } from 'react';

const VERDICT_LABELS: Record<string, string> = {
  Allow: '允许',
  Deny: '显式拒绝',
  Maybe: '无法确定',
  ImplicitDeny: '隐式拒绝',
};

export function VerdictBadge({ verdict, large = false }: { verdict: string; large?: boolean }) {
  return (
    <span className={`verdict ${verdict}${large ? ' lg' : ''}`}>
      <span className="dot" />
      {VERDICT_LABELS[verdict] ?? verdict}
    </span>
  );
}

const KIND_LABELS: Record<string, string> = {
  managed: '托管',
  inline: '内联',
  boundary: '边界',
  scp: 'SCP',
  resource: '资源策略',
  trust: '信任策略',
};

export function KindBadge({ kind }: { kind: string }) {
  return <span className={`badge ${kind}`}>{KIND_LABELS[kind] ?? kind}</span>;
}

export function Card({
  title,
  hint,
  action,
  children,
}: {
  title?: ReactNode;
  hint?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="card">
      {title ? (
        <div className="card-title">
          <h3>{title}</h3>
          <div className="row">
            {hint ? <span className="hint">{hint}</span> : null}
            {action}
          </div>
        </div>
      ) : null}
      {children}
    </section>
  );
}

export function Notice({ level, children }: { level: 'warn' | 'error' | 'info'; children: ReactNode }) {
  return <div className={`notice ${level}`}>{children}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
