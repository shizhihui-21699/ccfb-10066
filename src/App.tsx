import { useEffect, useRef, useState } from 'react';
import sample from './data/sample-dataset.json';
import type { Dataset } from './engine/types';
import { useDatasetStore } from './components/useDatasetStore';
import { CanIPage } from './components/CanIPage';
import { WhoCanPage } from './components/WhoCanPage';
import { PoliciesPage } from './components/PoliciesPage';
import { OverviewPage } from './components/OverviewPage';
import './styles.css';

type Tab = 'overview' | 'can-i' | 'who-can' | 'policies';

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: '概览' },
  { id: 'can-i', label: '谁能做什么' },
  { id: 'who-can', label: '反查：谁有这个权限' },
  { id: 'policies', label: '策略库与导入' },
];

const SAMPLE = sample as unknown as Dataset;

export default function App() {
  const store = useDatasetStore(SAMPLE);
  const mainRef = useRef<HTMLElement>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [pendingQuery, setPendingQuery] = useState<{
    principalId: string;
    action: string;
    resource: string;
    /** Bumped on every trap click so the query page remounts with new values. */
    nonce: number;
  } | null>(null);

  // Reset the scroll position when switching tabs so the page header is visible.
  useEffect(() => {
    mainRef.current?.scrollTo({ top: 0 });
  }, [tab]);

  const openTrap = (principalId: string, action: string, resource: string) => {
    setPendingQuery((current) => ({
      principalId,
      action,
      resource,
      nonce: (current?.nonce ?? 0) + 1,
    }));
    setTab('can-i');
  };

  const datasetIsSample = store.dataset.meta.name === SAMPLE.meta.name;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>云策略分析器</h1>
          <span>IAM Policy Analyzer</span>
        </div>
        <nav className="tabs">
          {TABS.map((entry) => (
            <button
              key={entry.id}
              className={`tab${tab === entry.id ? ' active' : ''}`}
              onClick={() => setTab(entry.id)}
            >
              {entry.label}
            </button>
          ))}
        </nav>
        <div className="topbar-spacer" />
        <span className="dataset-badge">
          {store.dataset.meta.name} · {store.stats.policies} 策略 / {store.stats.statements} 语句
        </span>
      </header>

      <main className="main" ref={mainRef}>
        {tab === 'overview' ? (
          <OverviewPage dataset={store.dataset} stats={store.stats} onOpenTrap={openTrap} />
        ) : null}
        {tab === 'can-i' ? (
          <CanIPage
            key={pendingQuery ? `query-${pendingQuery.nonce}` : 'default'}
            dataset={store.dataset}
            initialPrincipalId={pendingQuery?.principalId}
            initialAction={pendingQuery?.action}
            initialResource={pendingQuery?.resource}
          />
        ) : null}
        {tab === 'who-can' ? <WhoCanPage dataset={store.dataset} /> : null}
        {tab === 'policies' ? (
          <PoliciesPage
            dataset={store.dataset}
            onImport={store.addPolicy}
            onReplaceDataset={store.replaceDataset}
            onReset={store.resetToSample}
            datasetIsSample={datasetIsSample}
          />
        ) : null}
      </main>
    </div>
  );
}
