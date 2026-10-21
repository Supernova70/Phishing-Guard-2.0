import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Radar, RefreshCw, Search, ShieldAlert } from 'lucide-react';
import {
  getDetectionSummary,
  getFindings,
  type DetectionFinding,
  type DetectionSummary,
} from '../api/client';
import { formatDistanceToNow } from 'date-fns';

const PAGE_SIZE = 50;

function severityColor(value: number): string {
  if (value >= 80) return 'var(--danger)';
  if (value >= 60) return 'var(--warning)';
  if (value >= 30) return 'var(--primary)';
  return 'var(--text-muted)';
}

function Metric({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '12px 14px' }}>
      <p style={{ fontSize: '0.64rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{label}</p>
      <p style={{ fontSize: '1.35rem', fontWeight: 700, color: color ?? 'var(--text-primary)', marginTop: 3 }}>{value}</p>
    </div>
  );
}

function FindingRow({ finding, onOpen }: { finding: DetectionFinding; onOpen: () => void }) {
  return (
    <button
      onClick={onOpen}
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(180px, 1.4fr) minmax(140px, 1fr) 100px 90px',
        gap: 12,
        alignItems: 'center',
        width: '100%',
        textAlign: 'left',
        background: 'var(--bg-input)',
        border: '1px solid var(--border-subtle)',
        borderLeft: `3px solid ${severityColor(finding.severity)}`,
        borderRadius: 6,
        padding: '9px 11px',
        cursor: 'pointer',
        color: 'var(--text-secondary)',
      }}
    >
      <div style={{ minWidth: 0 }}>
        <p style={{ fontSize: '0.76rem', fontWeight: 700, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{finding.title}</p>
        <p className="font-mono" style={{ fontSize: '0.62rem', color: 'var(--text-muted)', marginTop: 2 }}>{finding.code}</p>
      </div>
      <div style={{ minWidth: 0 }}>
        <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{finding.subject}</p>
        <p style={{ fontSize: '0.62rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{finding.sender}</p>
      </div>
      <div>
        <span style={{ fontSize: '0.62rem', color: 'var(--text-muted)' }}>{finding.analyzer}</span>
        <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{finding.created_at ? formatDistanceToNow(new Date(finding.created_at), { addSuffix: true }) : ''}</p>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
        <span style={{ fontSize: '0.8rem', fontWeight: 700, color: severityColor(finding.severity) }}>{finding.severity.toFixed(0)}</span>
        <span style={{ fontSize: '0.62rem', color: 'var(--primary)' }}>scan #{finding.scan_id}</span>
      </div>
    </button>
  );
}

export function DetectionPage() {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<DetectionSummary | null>(null);
  const [findings, setFindings] = useState<DetectionFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [days, setDays] = useState(30);
  const [analyzer, setAnalyzer] = useState('');
  const [category, setCategory] = useState('');
  const [minSeverity, setMinSeverity] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [summaryData, findingData] = await Promise.all([
      getDetectionSummary(days),
      getFindings({
        analyzer: analyzer || undefined,
        category: category || undefined,
        min_severity: minSeverity || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    ]);
    setSummary(summaryData);
    setFindings(findingData.findings);
    setTotal(findingData.total);
  }, [analyzer, category, days, minSeverity, offset]);

  useEffect(() => {
    let active = true;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load()
      .catch(() => active && setError('Failed to load detection coverage'))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [load]);

  const filtersChanged = (setter: (value: string) => void, value: string) => {
    setOffset(0);
    setter(value);
  };

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 18, maxWidth: 1400 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Radar size={20} style={{ color: 'var(--primary)' }} />
        <div>
          <h1 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)' }}>Detection Coverage</h1>
          <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: 2 }}>
            Evidence-backed findings from every additive analyzer, across the whole mailbox. Read-only: scores and verdicts are never modified here.
          </p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 7, alignItems: 'center' }}>
          <select value={days} onChange={(e) => { setOffset(0); setDays(Number(e.target.value)); }} className="dark-input" style={{ fontSize: '0.72rem' }}>
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
            <option value={365}>Last year</option>
          </select>
          <button onClick={() => load()} className="btn-ghost" style={{ fontSize: '0.72rem' }}><RefreshCw size={12} /> Refresh</button>
        </div>
      </div>

      {error && (
        <div style={{ border: '1px solid var(--danger)', background: 'var(--danger-subtle)', color: 'var(--text-danger)', borderRadius: 6, padding: '9px 12px', fontSize: '0.76rem' }}>
          {error}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(100px, 1fr))', gap: 10 }}>
        <Metric label="Findings" value={summary?.totals.findings ?? 0} />
        <Metric label="Scans affected" value={summary?.totals.scans_with_findings ?? 0} />
        <Metric label="Critical" value={summary?.totals.critical ?? 0} color="var(--danger)" />
        <Metric label="High" value={summary?.totals.high ?? 0} color="var(--warning)" />
        <Metric label="Medium" value={summary?.totals.medium ?? 0} color="var(--primary)" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 0.7fr) minmax(520px, 1.3fr)', gap: 18 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 16 }}>
            <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 10 }}>Analyzer yield</p>
            {(summary?.analyzers ?? []).length === 0 && <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>No findings in this window.</p>}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
              {(summary?.analyzers ?? []).map((row) => (
                <div key={row.analyzer}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.72rem' }}>
                    <span style={{ color: 'var(--text-secondary)', flex: 1 }}>{row.analyzer}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{row.findings} findings · {row.scans} scans</span>
                    <span style={{ color: severityColor(row.max_severity), fontWeight: 700 }}>{row.max_severity.toFixed(0)}</span>
                  </div>
                  <div style={{ height: 4, borderRadius: 2, background: 'var(--bg-input)', marginTop: 4, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${Math.min(100, (row.findings / Math.max(1, summary?.totals.findings ?? 1)) * 100)}%`, background: severityColor(row.max_severity) }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 16 }}>
            <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 10 }}>Top codes</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {(summary?.top_codes ?? []).slice(0, 10).map((row) => (
                <div key={`${row.analyzer}-${row.code}`} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span className="font-mono" style={{ fontSize: '0.62rem', color: 'var(--warning)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.code}</span>
                  <span style={{ fontSize: '0.64rem', color: 'var(--text-muted)' }}>{row.findings}</span>
                </div>
              ))}
              {(summary?.top_codes ?? []).length === 0 && <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>No codes yet.</p>}
            </div>
          </div>
        </div>

        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 16, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
            <Search size={14} style={{ color: 'var(--text-muted)' }} />
            <select value={analyzer} onChange={(e) => filtersChanged(setAnalyzer, e.target.value)} className="dark-input" style={{ fontSize: '0.72rem' }}>
              <option value="">All analyzers</option>
              {(summary?.analyzers ?? []).map((row) => <option key={row.analyzer} value={row.analyzer}>{row.analyzer}</option>)}
            </select>
            <select value={category} onChange={(e) => filtersChanged(setCategory, e.target.value)} className="dark-input" style={{ fontSize: '0.72rem' }}>
              <option value="">All categories</option>
              {(summary?.categories ?? []).map((row) => <option key={row.category} value={row.category}>{row.category}</option>)}
            </select>
            <select value={minSeverity} onChange={(e) => { setOffset(0); setMinSeverity(Number(e.target.value)); }} className="dark-input" style={{ fontSize: '0.72rem' }}>
              <option value={0}>Any severity</option>
              <option value={30}>≥ 30</option>
              <option value={60}>≥ 60</option>
              <option value={80}>≥ 80</option>
            </select>
            <span style={{ marginLeft: 'auto', fontSize: '0.68rem', color: 'var(--text-muted)' }}>{total} matching findings</span>
          </div>

          {loading && <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Loading…</p>}
          {!loading && findings.length === 0 && (
            <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.76rem' }}>
              <ShieldAlert size={18} style={{ marginBottom: 5 }} />
              <p>No findings match these filters.</p>
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {findings.map((finding) => (
              <FindingRow key={finding.id} finding={finding} onOpen={() => navigate(`/scans/${finding.scan_id}`)} />
            ))}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
            <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0} className="btn-ghost" style={{ fontSize: '0.7rem' }}><ChevronLeft size={12} /> Prev</button>
            <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}</span>
            <button onClick={() => setOffset(offset + PAGE_SIZE)} disabled={offset + PAGE_SIZE >= total} className="btn-ghost" style={{ fontSize: '0.7rem' }}>Next <ChevronRight size={12} /></button>
          </div>
        </div>
      </div>
    </div>
  );
}
