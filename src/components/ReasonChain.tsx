import type { Decision, Evidence, StatementEvaluation, Tri } from '../engine/types';
import { KindBadge, VerdictBadge } from './primitives';

const MARKERS: Record<Tri | 'info', string> = {
  match: '✓',
  'no-match': '✗',
  unknown: '?',
  info: '·',
};

const OUTCOME_LABELS: Record<Tri, string> = {
  match: '命中',
  'no-match': '未命中',
  unknown: '不确定',
};

function EvidenceRow({ evidence }: { evidence: Evidence }) {
  const side = evidence.label.includes('Deny') ? 'deny' : 'allow';
  return (
    <div className={`evidence ${side}`}>
      <span className="policy-name">{evidence.policyName}</span>
      <KindBadge kind={evidence.policyKind} />
      <span>{evidence.label}</span>
      {evidence.detail ? <span className="detail">{evidence.detail}</span> : null}
    </div>
  );
}

/** Renders the human-readable reason chain. */
export function ReasonChain({ decision }: { decision: Decision }) {
  return (
    <div className="reason-chain">
      {decision.steps.map((step) => (
        <div className="reason-step" key={step.id}>
          <div className={`step-marker ${step.outcome}`}>{MARKERS[step.outcome]}</div>
          <div className="step-body">
            <h4>
              {step.title}
              {step.outcome !== 'info' ? (
                <span className="faint"> · {OUTCOME_LABELS[step.outcome as Tri]}</span>
              ) : null}
            </h4>
            <p>{step.detail}</p>
            {step.evidence?.length ? (
              <div className="evidence-list">
                {step.evidence.map((evidence, index) => (
                  <EvidenceRow key={`${evidence.policyId}-${evidence.statementIndex}-${index}`} evidence={evidence} />
                ))}
              </div>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  );
}

function conditionClass(outcome: Tri): string {
  return outcome === 'match' ? 'ok' : outcome === 'no-match' ? 'no' : 'unk';
}

/** Detailed statement-by-statement view, useful for auditing a decision. */
export function StatementTable({
  statements,
  filter,
}: {
  statements: StatementEvaluation[];
  filter?: (evaluation: StatementEvaluation) => boolean;
}) {
  const visible = filter ? statements.filter(filter) : statements;
  if (!visible.length) {
    return <div className="faint">没有可展示的语句。</div>;
  }

  return (
    <div>
      {visible.map((evaluation) => (
        <div className="statement-card" key={`${evaluation.policyId}-${evaluation.statementIndex}`}>
          <div className="statement-head">
            <span className="step-marker" style={{ width: 18, height: 18, fontSize: 10 }}>
              {MARKERS[evaluation.outcome]}
            </span>
            <strong>{evaluation.policyName}</strong>
            <KindBadge kind={evaluation.policyKind} />
            <span className="badge">{evaluation.sid ?? `#${evaluation.statementIndex + 1}`}</span>
            <span className={evaluation.effect === 'Allow' ? 'badge managed' : 'badge resource'}>
              {evaluation.effect}
            </span>
            <span className="faint">
              Action {MARKERS[evaluation.actionOutcome]} · Resource {MARKERS[evaluation.resourceOutcome]} · Condition{' '}
              {MARKERS[evaluation.conditionOutcome]}
            </span>
          </div>
          {evaluation.issue ? <div className="faint">⚠ {evaluation.issue}</div> : null}
          {evaluation.conditions.map((condition, index) => (
            <div className="cond-row" key={`${condition.operator}-${condition.key}-${index}`}>
              <span className={conditionClass(condition.outcome)}>{MARKERS[condition.outcome]}</span>
              <span>{condition.operator}</span>
              <span className="dim">{condition.key}</span>
              <span className="dim">
                策略值 {JSON.stringify(condition.policyValues)} · 请求值{' '}
                {condition.contextValues === null ? '（缺失）' : JSON.stringify(condition.contextValues)}
              </span>
              {condition.note ? <span className="faint">— {condition.note}</span> : null}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

/** Compact one-line summary used in tables. */
export function DecisionSummary({ decision }: { decision: Decision }) {
  return (
    <div className="row">
      <VerdictBadge verdict={decision.verdict} />
      <span className="faint">{decision.summary}</span>
    </div>
  );
}
