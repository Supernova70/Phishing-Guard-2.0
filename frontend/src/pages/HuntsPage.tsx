import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { Crosshair, Play, RefreshCw, ShieldAlert, Square, X } from 'lucide-react';
import {
  cancelHunt,
  createHunt,
  getHunt,
  getHuntResults,
  listHunts,
  runHunt,
  type HuntJob,
  type HuntResult,
} from '../api/client';
import { formatDistanceToNow } from 'date-fns';

const ANALYZERS = [
  { id: 'conversation', label: 'Thread / BEC' },
  { id: 'identity', label: 'Identity phishing' },
  { id: 'kit', label: 'Kit / AiTM' },
  { id: 'clickfix', label: 'ClickFix' },
];

const STATUS_COLOR: Record<string, string> = {
  queued: 'var(--text-muted)',
  running: 'var(--primary)',
  succeeded: 'var(--safe)',
  failed: 'var(--danger)',
  cancelled: 'var(--warning)',
};

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
      {label}
      {children}
    </label>
  );
}

export function HuntsPage() {
  const navigate = useNavigate();
  const [jobs, setJobs] = useState<HuntJob[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [selected, setSelected] = useState<HuntJob | null>(null);
  const [result, setResult] = useState<HuntResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [since, setSince] = useState('');
  const [until, setUntil] = useState('');
  const [classification, setClassification] = useState('');
  const [senderDomain, setSenderDomain] = useState('');
  const [subjectContains, setSubjectContains] = useState('');
  const [maxScans, setMaxScans] = useState(500);
  const [analyzers, setAnalyzers] = useState<string[]>(ANALYZERS.map((item) => item.id));
  const [runNow, setRunNow] = useState(true);

  const refresh = useCallback(async () => {
    const listing = await listHunts();
    setJobs(listing.hunts);
    if (selectedId != null) {
      const job = await getHunt(selectedId);
      setSelected(job);
      if (job.result) {
        const payload = await getHuntResults(selectedId);
        setResult(payload.result);
      } else {
        setResult(null);
      }
    }
  }, [selectedId]);

  useEffect(() => {
    refresh()
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load hunts'))
      .finally(() => setLoading(false));
    const timer = window.setInterval(() => {
      refresh().catch(() => undefined);
    }, 4000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const create = async () => {
    if (analyzers.length === 0) {
      setError('Select at least one analyzer');
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const created = await createHunt(
        {
          since: since ? new Date(since).toISOString() : undefined,
          until: until ? new Date(until).toISOString() : undefined,
          classification: classification
            ? (classification as 'safe' | 'suspicious' | 'dangerous')
            : undefined,
          sender_domain: senderDomain || undefined,
          subject_contains: subjectContains || undefined,
          analyzers,
          max_scans: maxScans,
          run_now: runNow,
        },
        crypto.randomUUID(),
      );
      setSelectedId(created.hunt_id);
      setNotice(
        runNow
          ? `Hunt #${created.hunt_id} queued and dispatched`
          : `Hunt #${created.hunt_id} queued; trigger it when ready`,
      );
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create hunt');
    } finally {
      setBusy(false);
    }
  };

  const cancel = async (job: HuntJob) => {
    setBusy(true);
    try {
      await cancelHunt(job.id);
      setNotice(`Cancellation requested for hunt #${job.id}`);
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to cancel hunt');
    } finally {
      setBusy(false);
    }
  };

  const trigger = async (job: HuntJob) => {
    setBusy(true);
    try {
      await runHunt(job.id);
      setNotice(`Hunt #${job.id} dispatched`);
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to run hunt');
    } finally {
      setBusy(false);
    }
  };

  const topCodes = useMemo(
    () => Object.entries(result?.new_by_code ?? {}).slice(0, 12),
    [result],
  );

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 18, maxWidth: 1400 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Crosshair size={20} style={{ color: 'var(--primary)' }} />
        <div>
          <h1 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)' }}>Retroactive Hunts</h1>
          <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: 2 }}>
            Replay identity, kit, ClickFix and thread analyzers over stored scans. Findings are additive; legacy scores are never changed.
          </p>
        </div>
      </div>

      {(error || notice) && (
        <div style={{
          border: `1px solid ${error ? 'var(--danger)' : 'var(--border-default)'}`,
          background: error ? 'var(--danger-subtle)' : 'var(--bg-input)',
          color: error ? 'var(--text-danger)' : 'var(--text-secondary)',
          borderRadius: 6,
          padding: '9px 12px',
          fontSize: '0.78rem',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}>
          {error ? <ShieldAlert size={14} /> : <Crosshair size={14} />}
          <span style={{ flex: 1 }}>{error ?? notice}</span>
          <button onClick={() => { setError(null); setNotice(null); }} style={{ background: 'none', border: 0, color: 'inherit', cursor: 'pointer' }}><X size={13} /></button>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 0.8fr) minmax(420px, 1.2fr)', gap: 18 }}>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18 }}>
          <p style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>New hunt</p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <Field label="Since"><input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} className="dark-input" /></Field>
            <Field label="Until"><input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} className="dark-input" /></Field>
            <Field label="Classification">
              <select value={classification} onChange={(e) => setClassification(e.target.value)} className="dark-input">
                <option value="">Any</option>
                <option value="safe">Safe</option>
                <option value="suspicious">Suspicious</option>
                <option value="dangerous">Dangerous</option>
              </select>
            </Field>
            <Field label="Max scans"><input type="number" min={1} max={2000} value={maxScans} onChange={(e) => setMaxScans(Number(e.target.value))} className="dark-input" /></Field>
            <Field label="Sender domain"><input value={senderDomain} onChange={(e) => setSenderDomain(e.target.value)} placeholder="corp.example" className="dark-input" /></Field>
            <Field label="Subject contains"><input value={subjectContains} onChange={(e) => setSubjectContains(e.target.value)} placeholder="invoice" className="dark-input" /></Field>
          </div>

          <p style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 16, marginBottom: 8 }}>Analyzers</p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
            {ANALYZERS.map((item) => (
              <label key={item.id} style={{ display: 'flex', gap: 7, alignItems: 'center', fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                <input
                  type="checkbox"
                  checked={analyzers.includes(item.id)}
                  onChange={(e) => setAnalyzers((current) => e.target.checked ? [...current, item.id] : current.filter((value) => value !== item.id))}
                />
                {item.label}
              </label>
            ))}
          </div>

          <label style={{ display: 'flex', gap: 7, alignItems: 'center', fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: 16 }}>
            <input type="checkbox" checked={runNow} onChange={(e) => setRunNow(e.target.checked)} />
            Dispatch immediately (durable job; safe to retry)
          </label>

          <button
            onClick={create}
            disabled={busy}
            style={{ marginTop: 16, width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, background: 'var(--primary)', color: '#fff', border: 0, borderRadius: 6, padding: '9px 12px', fontSize: '0.8rem', fontWeight: 700, cursor: busy ? 'wait' : 'pointer', opacity: busy ? 0.7 : 1 }}
          >
            <Play size={14} /> Start hunt
          </button>
        </div>

        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <p style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)', flex: 1 }}>Hunt history</p>
            <button onClick={() => refresh()} style={{ background: 'none', border: '1px solid var(--border-default)', borderRadius: 4, color: 'var(--text-muted)', padding: '3px 7px', cursor: 'pointer' }}><RefreshCw size={12} /></button>
          </div>
          {loading && <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>Loading…</p>}
          {!loading && jobs.length === 0 && <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>No hunts yet.</p>}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 230, overflowY: 'auto' }}>
            {jobs.map((job) => (
              <button
                key={job.id}
                onClick={() => { setSelectedId(job.id); setSelected(job); setResult(job.result); }}
                style={{
                  textAlign: 'left',
                  background: selectedId === job.id ? 'var(--primary-glow)' : 'var(--bg-input)',
                  border: `1px solid ${selectedId === job.id ? 'var(--primary)' : 'var(--border-subtle)'}`,
                  borderRadius: 6,
                  padding: '8px 10px',
                  cursor: 'pointer',
                  color: 'var(--text-secondary)',
                }}
              >
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontSize: '0.76rem', fontWeight: 700, color: 'var(--text-primary)' }}>#{job.id}</span>
                  <span style={{ fontSize: '0.64rem', fontWeight: 700, color: STATUS_COLOR[job.status] ?? 'var(--text-muted)', textTransform: 'uppercase' }}>{job.status}</span>
                  <span style={{ fontSize: '0.66rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                    {job.created_at ? formatDistanceToNow(new Date(job.created_at), { addSuffix: true }) : ''}
                  </span>
                </div>
                <p style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 3 }}>
                  {job.progress}/{job.total || '?'} scans · {job.message ?? 'queued'}
                </p>
              </button>
            ))}
          </div>
        </div>
      </div>

      {selected && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <p style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>Hunt #{selected.id}</p>
            <span style={{ fontSize: '0.68rem', fontWeight: 700, color: STATUS_COLOR[selected.status] ?? 'var(--text-muted)', textTransform: 'uppercase' }}>{selected.status}</span>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{selected.progress}/{selected.total || '?'} scanned</span>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
              {selected.status === 'queued' && <button onClick={() => trigger(selected)} disabled={busy} className="btn-ghost" style={{ fontSize: '0.72rem' }}><Play size={12} /> Run now</button>}
              {['queued', 'running'].includes(selected.status) && <button onClick={() => cancel(selected)} disabled={busy} className="btn-ghost" style={{ fontSize: '0.72rem' }}><Square size={12} /> Cancel</button>}
            </div>
          </div>
          {selected.error && <p style={{ color: 'var(--text-danger)', fontSize: '0.76rem', marginTop: 8 }}>{selected.error}</p>}
          {selected.message && <p style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginTop: 6 }}>{selected.message}</p>}

          {result && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(100px, 1fr))', gap: 10, marginTop: 14 }}>
                {[
                  ['Matched scans', result.scans_matched],
                  ['Scanned', result.scans_scanned],
                  ['With findings', result.scans_with_findings],
                  ['New findings', result.new_finding_count],
                ].map(([label, value]) => (
                  <div key={String(label)} style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '9px 11px' }}>
                    <p style={{ fontSize: '0.63rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</p>
                    <p style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)' }}>{value}</p>
                  </div>
                ))}
              </div>

              {topCodes.length > 0 && (
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 12 }}>
                  {topCodes.map(([code, count]) => (
                    <span key={code} className="font-mono" style={{ fontSize: '0.64rem', color: 'var(--warning)', border: '1px solid var(--warning)', borderRadius: 4, padding: '2px 6px' }}>{code} × {count}</span>
                  ))}
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 14 }}>
                {result.top_findings.map((finding) => (
                  <div key={finding.id} style={{ background: 'var(--bg-input)', borderLeft: `3px solid ${finding.severity >= 65 ? 'var(--danger)' : 'var(--warning)'}`, borderRadius: '0 5px 5px 0', padding: '8px 11px' }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.76rem', fontWeight: 700, color: 'var(--text-primary)' }}>{finding.title}</span>
                      <button onClick={() => navigate(`/scans/${finding.scan_id}`)} style={{ marginLeft: 'auto', background: 'none', border: 0, color: 'var(--primary)', cursor: 'pointer', fontSize: '0.68rem' }}>Scan #{finding.scan_id} ↗</button>
                    </div>
                    <p className="font-mono" style={{ fontSize: '0.64rem', color: 'var(--text-muted)', marginTop: 3 }}>{finding.code} · {finding.analyzer} · {finding.severity.toFixed(0)}</p>
                    {finding.evidence?.[0] && <p style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', marginTop: 4, wordBreak: 'break-word' }}>{finding.evidence[0].kind}: {finding.evidence[0].value}</p>}
                  </div>
                ))}
              </div>
              {result.top_findings_truncated && <p style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 8 }}>Showing the highest-severity findings; full evidence is available from each scan.</p>}
            </>
          )}
        </div>
      )}
    </div>
  );
}
