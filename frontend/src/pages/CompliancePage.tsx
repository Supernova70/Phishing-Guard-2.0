import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  FileSearch,
  ScrollText,
  Download,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Link2,
  Clock,
} from 'lucide-react';
import { format, formatDistanceToNow } from 'date-fns';
import {
  AUDIT_ACTIONS,
  evidenceRawUrl,
  getAuditLog,
  getEvidence,
  verifyEvidence,
  type AuditEntry,
  type EvidenceEntry,
  type EvidenceVerifyResult,
} from '../api/forensics';

type Tab = 'evidence' | 'audit';

const ACTION_COLORS: Record<string, string> = {
  raw_view: 'var(--warning)',
  evidence_verify: 'var(--primary)',
  evidence_download: 'var(--primary)',
  report_export: 'var(--safe)',
  retention_purge: 'var(--danger)',
  evidence_append: 'var(--text-secondary)',
};

const cardStyle: React.CSSProperties = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border-default)',
  borderRadius: 8,
};

const labelStyle: React.CSSProperties = {
  fontSize: '0.62rem',
  fontWeight: 700,
  color: 'var(--text-muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
};

const mono: React.CSSProperties = {
  fontFamily: "'JetBrains Mono', monospace",
};

function StatCard({
  icon,
  label,
  value,
  detail,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  detail: string;
  color: string;
}) {
  return (
    <div style={{ ...cardStyle, padding: '14px 16px', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
      <div style={{
        width: 34, height: 34, borderRadius: 8, flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'var(--bg-input)', color, border: '1px solid var(--border-subtle)',
      }}>
        {icon}
      </div>
      <div>
        <p style={labelStyle}>{label}</p>
        <p style={{ ...mono, fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>{value}</p>
        <p style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 2 }}>{detail}</p>
      </div>
    </div>
  );
}

export function CompliancePage() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>('evidence');
  const [evidence, setEvidence] = useState<EvidenceEntry[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [auditAction, setAuditAction] = useState<string>('');
  const [loadingEvidence, setLoadingEvidence] = useState(true);
  const [loadingAudit, setLoadingAudit] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [verifyingId, setVerifyingId] = useState<number | null>(null);
  const [result, setResult] = useState<EvidenceVerifyResult | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadEvidence = useCallback(async () => {
    setLoadingEvidence(true);
    try {
      const rows = await getEvidence(100);
      setEvidence(rows);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load evidence chain');
    } finally {
      setLoadingEvidence(false);
    }
  }, []);

  const loadAudit = useCallback(async (action?: string) => {
    setLoadingAudit(true);
    try {
      const rows = await getAuditLog(action || undefined, 150);
      setAudit(rows);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit trail');
    } finally {
      setLoadingAudit(false);
    }
  }, []);

  useEffect(() => {
    void loadEvidence();
  }, [loadEvidence]);

  useEffect(() => {
    void loadAudit(auditAction);
  }, [loadAudit, auditAction]);

  const handleVerify = async (row: EvidenceEntry) => {
    setVerifyingId(row.id);
    setActionMessage(null);
    try {
      const verified = await verifyEvidence(row.id);
      setResult(verified);
      setActionMessage(
        verified.valid
          ? `Chain verified: row ${row.id}, link + contents + whole chain intact (${verified.chain.checked} rows).`
          : `Verification FAILED for row ${row.id}: ${verified.chain.reason ?? 'row contents or link mismatch'}.`,
      );
      void loadAudit(auditAction);
    } catch (err) {
      setActionMessage(err instanceof Error ? err.message : 'Verification request failed');
    } finally {
      setVerifyingId(null);
    }
  };

  const chainState = !result
    ? { label: 'Not checked', color: 'var(--text-muted)', detail: 'Verify a row to walk the chain' }
    : result.chain.valid
    ? { label: 'Intact', color: 'var(--safe)', detail: `${result.chain.checked} rows linked` }
    : { label: 'Broken', color: 'var(--danger)', detail: result.chain.reason ?? 'Integrity failure' };

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 1200 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <FileSearch size={20} style={{ color: 'var(--primary)' }} />
            <h2 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>Evidence &amp; Audit</h2>
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
            Append-only chain of custody for raw emails and exported reports, plus every sensitive access.
          </p>
        </div>
        <button
          className="btn-ghost"
          onClick={() => { void loadEvidence(); void loadAudit(auditAction); }}
          style={{ fontSize: '0.75rem', padding: '5px 12px' }}
        >
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 12 }}>
        <StatCard
          icon={<FileSearch size={16} />}
          label="Custody rows"
          value={String(evidence.length)}
          detail="hash-chained records"
          color="var(--primary)"
        />
        <StatCard
          icon={<ScrollText size={16} />}
          label="Audit events"
          value={String(audit.length)}
          detail="most recent 150"
          color="var(--warning)"
        />
        <StatCard
          icon={chainState.label === 'Broken' ? <ShieldAlert size={16} /> : <ShieldCheck size={16} />}
          label="Chain integrity"
          value={chainState.label}
          detail={chainState.detail}
          color={chainState.color}
        />
      </div>

      {error && (
        <div style={{ ...cardStyle, borderColor: 'var(--danger)', background: 'var(--danger-subtle)', padding: '10px 14px' }}>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-danger)' }}>{error}</p>
        </div>
      )}

      {actionMessage && (
        <div style={{
          ...cardStyle,
          borderColor: result?.valid ? 'var(--safe)' : result ? 'var(--danger)' : 'var(--border-default)',
          background: result?.valid ? 'var(--safe-subtle)' : result ? 'var(--danger-subtle)' : 'var(--bg-input)',
          padding: '10px 14px',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          {result?.valid ? (
            <CheckCircle2 size={15} style={{ color: 'var(--safe)' }} />
          ) : (
            <XCircle size={15} style={{ color: 'var(--danger)' }} />
          )}
          <p style={{ fontSize: '0.78rem', color: result?.valid ? 'var(--text-safe)' : 'var(--text-danger)' }}>{actionMessage}</p>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 6 }}>
        {([
          ['evidence', `Chain of Custody (${evidence.length})`, <FileSearch size={13} key="e" />],
          ['audit', `Audit Trail (${audit.length})`, <ScrollText size={13} key="a" />],
        ] as const).map(([key, label, icon]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: tab === key ? 'var(--primary-glow)' : 'var(--bg-card)',
              border: `1px solid ${tab === key ? 'var(--primary)' : 'var(--border-default)'}`,
              borderRadius: 6, padding: '6px 12px', cursor: 'pointer',
              fontSize: '0.75rem', fontWeight: 600,
              color: tab === key ? 'var(--primary)' : 'var(--text-secondary)',
            }}
          >
            {icon} {label}
          </button>
        ))}
      </div>

      {tab === 'evidence' && (
        <div style={{ ...cardStyle, overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-subtle)' }}>
            <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)' }}>Evidence records</p>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 2 }}>
              Each row commits the raw-message SHA-256 and links to the previous row. Verify walks the entire chain.
            </p>
          </div>

          {loadingEvidence ? (
            <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {[1, 2, 3].map((i) => <div key={i} className="skeleton" style={{ height: 32, borderRadius: 4 }} />)}
            </div>
          ) : evidence.length === 0 ? (
            <div style={{ padding: 32, textAlign: 'center' }}>
              <ShieldCheck size={26} style={{ color: 'var(--text-muted)' }} />
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 8 }}>
                No evidence rows yet — they are created when raw emails are retained at scan time.
              </p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
                <thead>
                  <tr style={{ textAlign: 'left' }}>
                    {['Row', 'Email / Scan', 'Raw SHA-256', 'Actor', 'Recorded', 'Actions'].map((h) => (
                      <th key={h} style={{ ...labelStyle, padding: '8px 14px', borderBottom: '1px solid var(--border-subtle)', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {evidence.map((row) => {
                    const verified = result && result.evidence.id === row.id ? result : null;
                    return (
                      <tr key={row.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ ...mono, padding: '8px 14px', color: 'var(--text-muted)' }}>#{row.id}</td>
                        <td style={{ padding: '8px 14px' }}>
                          <div style={{ display: 'flex', gap: 8 }}>
                            {row.email_id != null && (
                              <button
                                className="btn-link"
                                onClick={() => navigate(`/emails/${row.email_id}/trace`)}
                                style={{ background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', fontSize: '0.72rem', padding: 0 }}
                              >
                                Email #{row.email_id}
                              </button>
                            )}
                            {row.scan_id != null && (
                              <button
                                onClick={() => navigate(`/scans/${row.scan_id}`)}
                                style={{ background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', fontSize: '0.72rem', padding: 0, display: 'flex', alignItems: 'center', gap: 3 }}
                              >
                                <Link2 size={11} /> Scan #{row.scan_id}
                              </button>
                            )}
                          </div>
                        </td>
                        <td style={{ ...mono, padding: '8px 14px', color: 'var(--text-secondary)', fontSize: '0.68rem' }}>
                          <span title={row.raw_sha256 ?? undefined}>
                            {row.raw_sha256 ? `${row.raw_sha256.slice(0, 12)}…${row.raw_sha256.slice(-6)}` : '—'}
                          </span>
                          {row.report_sha256 && (
                            <span title={`report sha256: ${row.report_sha256}`} style={{ marginLeft: 6, color: 'var(--safe)' }}>+report</span>
                          )}
                        </td>
                        <td style={{ padding: '8px 14px', color: 'var(--text-secondary)' }}>{row.actor}</td>
                        <td style={{ padding: '8px 14px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }} title={row.created_at ?? ''}>
                          {row.created_at ? formatDistanceToNow(new Date(row.created_at), { addSuffix: true }) : '—'}
                        </td>
                        <td style={{ padding: '8px 14px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                            <button
                              className="btn-ghost"
                              onClick={() => void handleVerify(row)}
                              disabled={verifyingId === row.id}
                              style={{ fontSize: '0.68rem', padding: '3px 9px' }}
                            >
                              <ShieldCheck size={11} /> {verifyingId === row.id ? 'Verifying…' : 'Verify'}
                            </button>
                            {row.email_id != null && (
                              <a
                                className="btn-ghost"
                                href={evidenceRawUrl(row.email_id)}
                                download
                                title="Download the retained raw message (recorded as raw_view)"
                                style={{ fontSize: '0.68rem', padding: '3px 9px', textDecoration: 'none' }}
                              >
                                <Download size={11} /> Raw
                              </a>
                            )}
                            {verified && (
                              <span style={{
                                display: 'flex', alignItems: 'center', gap: 3,
                                fontSize: '0.65rem', fontWeight: 700,
                                color: verified.valid ? 'var(--safe)' : 'var(--danger)',
                              }}>
                                {verified.valid ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                                {verified.valid ? 'valid' : 'invalid'}
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'audit' && (
        <div style={{ ...cardStyle, overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
            <div>
              <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)' }}>Access log</p>
              <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 2 }}>
                Append-only. Viewing raw evidence, exporting reports and verification are all recorded.
              </p>
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              <Clock size={12} /> action
              <select
                value={auditAction}
                onChange={(e) => setAuditAction(e.target.value)}
                style={{ background: 'var(--bg-input)', border: '1px solid var(--border-default)', borderRadius: 4, color: 'var(--text-primary)', padding: '4px 8px', fontSize: '0.72rem' }}
              >
                <option value="">all</option>
                {AUDIT_ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
              </select>
            </label>
          </div>

          {loadingAudit ? (
            <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {[1, 2, 3].map((i) => <div key={i} className="skeleton" style={{ height: 30, borderRadius: 4 }} />)}
            </div>
          ) : audit.length === 0 ? (
            <div style={{ padding: 32, textAlign: 'center' }}>
              <ScrollText size={26} style={{ color: 'var(--text-muted)' }} />
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 8 }}>No audit entries for this filter.</p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
                <thead>
                  <tr style={{ textAlign: 'left' }}>
                    {['When', 'Action', 'Actor', 'Entity', 'Detail'].map((h) => (
                      <th key={h} style={{ ...labelStyle, padding: '8px 14px', borderBottom: '1px solid var(--border-subtle)', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {audit.map((entry) => (
                    <tr key={entry.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '8px 14px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }} title={entry.created_at ?? ''}>
                        {entry.created_at ? format(new Date(entry.created_at), 'dd MMM HH:mm:ss') : '—'}
                      </td>
                      <td style={{ padding: '8px 14px' }}>
                        <span style={{
                          ...mono, fontSize: '0.66rem', fontWeight: 600,
                          color: ACTION_COLORS[entry.action] ?? 'var(--text-secondary)',
                          background: 'var(--bg-input)', border: '1px solid var(--border-subtle)',
                          borderRadius: 4, padding: '2px 6px', whiteSpace: 'nowrap',
                        }}>
                          {entry.action}
                        </span>
                      </td>
                      <td style={{ padding: '8px 14px', color: 'var(--text-secondary)' }}>{entry.actor}</td>
                      <td style={{ padding: '8px 14px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {entry.entity_type ?? '—'}{entry.entity_id != null ? ` #${entry.entity_id}` : ''}
                      </td>
                      <td style={{ ...mono, padding: '8px 14px', color: 'var(--text-muted)', fontSize: '0.66rem', maxWidth: 340, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <span title={entry.detail ? JSON.stringify(entry.detail) : undefined}>
                          {entry.detail ? JSON.stringify(entry.detail) : '—'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
