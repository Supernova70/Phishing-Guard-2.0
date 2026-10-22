import { lazy, Suspense, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import {
  TrendingUp,
  AlertTriangle,
  AlertCircle,
  ShieldCheck,
  ShieldAlert,
  Megaphone,
  Globe,
  Brain,
  Link2,
  Paperclip,
  Download,
} from 'lucide-react';
import { getEmails, getScans, exportScansCsv } from '../api/client';
import { getAlerts, getCampaigns, getIpStats, getAttributionStats, getModelPerformance, type AttributionStats, type ModelPerformance } from '../api/forensics';
import { AttributionDonut } from '../components/charts/AttributionDonut';
import { useCountUp } from '../hooks/useCountUp';
import { ClassificationBadge, ScoreBadge } from '../components/ui/Badge';
import { StatTile } from '../components/ui/primitives';
import { Reveal } from '../components/effects/Reveal';
import { TiltCard } from '../components/effects/TiltCard';
import { ThreatTimeline } from '../components/charts/ThreatTimeline';
import { ClassificationDonut } from '../components/charts/ClassificationDonut';
import { formatDistanceToNow } from 'date-fns';
import type { Email, Scan } from '../types';

// Code-split the 3D globe (pulls in three.js) so the dashboard shell
// loads instantly and the globe chunk arrives in parallel.
const IpGlobe = lazy(() => import('../components/globe/IpGlobe'));

// ─── KPI Card ─────────────────────────────────────────────────────────────────
interface KpiCardProps {
  title: string;
  value: number;
  icon: React.ReactNode;
  tone: 'primary' | 'danger' | 'warning' | 'safe';
  subtitle?: string;
  delay?: number;
}

function KpiCard({ title, value, icon, tone, subtitle, delay = 0 }: KpiCardProps) {
  const count = useCountUp(value, 1000, delay);
  const reduceMotion = useReducedMotion();
  return (
    <motion.div
      initial={reduceMotion ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: delay / 1000, ease: [0.22, 1, 0.36, 1] }}
    >
      <StatTile
        label={title}
        value={count.toLocaleString()}
        detail={subtitle}
        icon={icon}
        tone={tone}
        tilt={6}
      />
    </motion.div>
  );
}

// ─── Intel Strip ──────────────────────────────────────────────────────────────
interface IntelStripProps {
  spoofCount: number;
  openCampaigns: number;
  topCountries: Array<{ country: string | null; count: number }>;
  attribution: AttributionStats | null;
}

function IntelStrip({ spoofCount, openCampaigns, topCountries, attribution }: IntelStripProps) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: 18,
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: 14,
        padding: '18px 20px',
        alignItems: 'center',
        boxShadow: 'var(--shadow-card)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <ShieldAlert size={16} style={{ color: 'var(--warning)' }} />
        <div>
          <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Spoof / auth-fail alerts</p>
          <p className="font-mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: spoofCount > 0 ? 'var(--warning)' : 'var(--text-primary)' }}>
            {spoofCount}
          </p>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Megaphone size={16} style={{ color: 'var(--primary)' }} />
        <div>
          <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Open campaigns</p>
          <p className="font-mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {openCampaigns}
          </p>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
        <Globe size={16} style={{ color: 'var(--safe)', flexShrink: 0 }} />
        <div style={{ minWidth: 0 }}>
          <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Top origin countries</p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 3 }}>
            {topCountries.length === 0 ? (
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>no cached geo intel yet</span>
            ) : (
              topCountries.slice(0, 4).map((c, i) => (
                <span key={i} className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', background: 'var(--bg-input)', padding: '2px 8px', borderRadius: 4 }}>
                  {c.country || 'unknown'} <span style={{ color: 'var(--text-muted)' }}>· {c.count}</span>
                </span>
              ))
            )}
          </div>
        </div>
      </div>
      {/* Attribution split donut (plan §6, FE-C5) */}
      <AttributionDonut stats={attribution} />
    </div>
  );
}

// ─── Skeleton ────────────────────────────────────────────────────────────────
function DashboardSkeleton() {
  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
        {[0,1,2,3].map(i => (
          <div key={i} className="skeleton" style={{ height: 120, borderRadius: 8 }} />
        ))}
      </div>
      <div style={{ display: 'flex', gap: 16, height: 280 }}>
        <div className="skeleton" style={{ flex: 3, borderRadius: 8 }} />
        <div className="skeleton" style={{ flex: 2, borderRadius: 8 }} />
      </div>
      <div className="skeleton" style={{ height: 320, borderRadius: 8 }} />
    </div>
  );
}

// ─── Recent Activity Table ────────────────────────────────────────────────────
function RecentActivity({ scans, emails, onViewScan }: { scans: Scan[]; emails: Email[]; onViewScan: (id: number) => void }) {
  const recent = scans.slice(0, 15);
  const emailMap = new Map(emails.map((e) => [e.id, e]));

  if (recent.length === 0) {
    return (
      <div style={{ padding: 42, textAlign: 'center' }}>
        <ShieldCheck size={40} style={{ color: 'var(--safe)', margin: '0 auto 12px' }} />
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>No scan activity yet</p>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 4 }}>Run scans on emails to see results here</p>
      </div>
    );
  }

  return (
    <table className="dark-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
      <thead>
        <tr>
          <th>Email #</th>
          <th>Sender</th>
          <th>Subject</th>
          <th>Score</th>
          <th>Classification</th>
          <th>Engines</th>
          <th>Time</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        {recent.map((scan) => {
          const email = emailMap.get(scan.email_id);
          const v = scan.verdict;
          return (
            <tr
              key={scan.id}
              onClick={() => onViewScan(scan.id)}
              style={{
                borderLeft: v
                  ? `2px solid ${v.classification === 'dangerous' ? 'var(--danger)' : v.classification === 'suspicious' ? 'var(--warning)' : 'transparent'}`
                  : undefined,
                cursor: 'pointer',
                opacity: 1,
              }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLTableRowElement).style.background = 'var(--bg-input)')}
              onMouseLeave={(e) => ((e.currentTarget as HTMLTableRowElement).style.background = '')}
            >
              <td>
                <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  #{scan.email_number ?? scan.email_id}
                </span>
              </td>
              <td style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {email?.sender ?? '—'}
              </td>
              <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                {email?.subject ?? '(no subject)'}
              </td>
              <td>
                {v ? <ScoreBadge score={v.final_score} size="sm" /> : <span style={{ color: 'var(--text-muted)' }}>—</span>}
              </td>
              <td>
                {v ? <ClassificationBadge classification={v.classification} size="sm" /> : (
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{scan.status}</span>
                )}
              </td>
              <td>
                {v ? (
                  <div style={{ display: 'flex', gap: 6 }}>
                    <Brain size={14} style={{ color: (v.ai_score ?? 0) > 0 ? 'var(--safe)' : 'var(--text-muted)' }} />
                    <Link2 size={14} style={{ color: (v.url_score ?? 0) > 0 ? 'var(--safe)' : 'var(--text-muted)' }} />
                    <Paperclip size={14} style={{ color: (v.attachment_score ?? 0) > 0 ? 'var(--safe)' : 'var(--text-muted)' }} />
                  </div>
                ) : '—'}
              </td>
              <td style={{ whiteSpace: 'nowrap' }}>
                {scan.completed_at
                  ? formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })
                  : '—'}
              </td>
              <td>
                <button
                  onClick={(e) => { e.stopPropagation(); onViewScan(scan.id); }}
                  style={{
                    background: 'var(--primary-soft)',
                    border: '1px solid var(--primary-border)',
                    borderRadius: 7,
                    color: 'var(--primary)',
                    padding: '3px 10px',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    fontWeight: 600,
                    whiteSpace: 'nowrap',
                  }}
                >
                  View Scan
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// ─── Dashboard Page ───────────────────────────────────────────────────────────

// One silent retry: these four panels are loaded with Promise.allSettled, so a
// single transient 502 would otherwise leave them empty with no UI error and
// no way to recover without a full page reload.
// ─── Model Feedback Loop ─────────────────────────────────────────────────────
function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function ModelHealthCard() {
  const navigate = useNavigate();
  const [perf, setPerf] = useState<ModelPerformance | null>(null);

  useEffect(() => {
    getModelPerformance().then(setPerf).catch(() => { /* optional widget */ });
  }, []);

  if (!perf) return null;

  const metric = (label: string, value: number, color: string) => (
    <div style={{ textAlign: 'center', minWidth: 74 }}>
      <p className="font-mono" style={{ fontSize: '1.15rem', fontWeight: 900, color }}>{pct(value)}</p>
      <p style={{ fontSize: '0.62rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</p>
    </div>
  );

  return (
    <TiltCard
      className="surface"
      intensity={3.5}
      style={{ padding: 20, borderRadius: 14 }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Brain size={17} style={{ color: 'var(--primary)' }} />
          <div>
            <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>Model Feedback Loop</p>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              Analyst labels vs model verdicts — suspicious and dangerous count as threats
            </p>
          </div>
        </div>
        <button className="btn-ghost" onClick={() => navigate('/scans')} style={{ fontSize: '0.72rem', padding: '4px 12px' }}>
          Review scans →
        </button>
      </div>

      {perf.total === 0 ? (
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 14 }}>
          No analyst feedback yet. Open a completed scan and label its verdict to start measuring
          precision and recall on your own mailbox.
        </p>
      ) : (
        <div style={{ display: 'flex', gap: 24, alignItems: 'center', marginTop: 16, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 18 }}>
            {metric('Accuracy', perf.accuracy, 'var(--primary)')}
            {metric('Precision', perf.precision, 'var(--safe)')}
            {metric('Recall', perf.recall, 'var(--warning)')}
            {metric('F1', perf.f1, 'var(--text-primary)')}
          </div>

          <div style={{ flex: 1, minWidth: 260 }}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
              {[
                { key: 'tp', label: 'TP', value: perf.confusion.tp, color: 'var(--safe)' },
                { key: 'fp', label: 'FP', value: perf.confusion.fp, color: 'var(--danger)' },
                { key: 'fn', label: 'FN', value: perf.confusion.fn, color: 'var(--warning)' },
                { key: 'tn', label: 'TN', value: perf.confusion.tn, color: 'var(--text-muted)' },
              ].map((c) => (
                <span
                  key={c.key}
                  className="font-mono"
                  style={{
                    fontSize: '0.7rem', fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                    background: 'var(--bg-input)', color: c.color,
                  }}
                >
                  {c.label} {c.value}
                </span>
              ))}
              {perf.unsure > 0 && (
                <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', padding: '2px 4px' }}>
                  {perf.unsure} unsure (excluded)
                </span>
              )}
            </div>

            {perf.recent.slice(0, 3).map((row) => (
              <button
                key={row.id}
                onClick={() => navigate(`/scans/${row.scan_id}`)}
                style={{
                  display: 'flex', width: '100%', alignItems: 'center', gap: 8,
                  padding: '4px 0', background: 'transparent', border: 'none',
                  cursor: 'pointer', textAlign: 'left',
                }}
              >
                <span style={{
                  width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                  background: row.label === 'phishing' ? 'var(--danger)'
                    : row.label === 'legitimate' ? 'var(--safe)' : 'var(--text-muted)',
                }} />
                <span style={{
                  fontSize: '0.72rem', color: 'var(--text-secondary)', flex: 1,
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {row.email_subject ?? `Scan #${row.scan_id}`}
                </span>
                <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', flexShrink: 0 }}>
                  {row.predicted_classification} → {row.label}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </TiltCard>
  );
}

const retryOnce = async <T,>(fn: () => Promise<T>): Promise<T> => {
  try {
    return await fn();
  } catch {
    await new Promise((resolve) => setTimeout(resolve, 400));
    return await fn();
  }
};

export function Dashboard() {
  const navigate = useNavigate();
  const [emails, setEmails] = useState<Email[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [spoofCount, setSpoofCount] = useState(0);
  const [openCampaigns, setOpenCampaigns] = useState(0);
  const [topCountries, setTopCountries] = useState<Array<{ country: string | null; count: number }>>([]);
  const [attribution, setAttribution] = useState<AttributionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [e, s, intel] = await Promise.all([
        getEmails(0, 200),
        getScans(0, 200),
        Promise.allSettled([
          retryOnce(() => getAlerts()),
          retryOnce(() => getCampaigns('open')),
          retryOnce(() => getIpStats()),
          retryOnce(() => getAttributionStats()),
        ]),
      ]);
      setEmails(e);
      setScans(s);
      const [alertsR, campaignsR, statsR, attrR] = intel;
      if (alertsR.status === 'fulfilled') {
        setSpoofCount(alertsR.value.alerts.filter((a) => a.reasons.includes('spoof')).length);
      }
      if (campaignsR.status === 'fulfilled') setOpenCampaigns(campaignsR.value.length);
      if (statsR.status === 'fulfilled') setTopCountries(statsR.value.countries);
      if (attrR.status === 'fulfilled') setAttribution(attrR.value);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, []);

  if (loading) return <DashboardSkeleton />;

  if (error) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ border: '1px solid var(--danger)', borderRadius: 8, background: 'var(--danger-subtle)', padding: 20, display: 'flex', gap: 12, alignItems: 'flex-start' }}>
          <AlertCircle size={20} style={{ color: 'var(--danger)', flexShrink: 0 }} />
          <div>
            <p style={{ fontWeight: 600, color: 'var(--text-danger)' }}>Failed to load dashboard</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>{error}</p>
            <button className="btn-ghost" onClick={loadData} style={{ marginTop: 12, fontSize: '0.8rem' }}>Retry</button>
          </div>
        </div>
      </div>
    );
  }

  const completedScans = scans.filter((s) => s.status === 'complete' && s.verdict);
  const threatsCount = completedScans.filter((s) => s.verdict?.classification === 'dangerous').length;
  const suspiciousCount = completedScans.filter((s) => s.verdict?.classification === 'suspicious').length;
  const safeCount = completedScans.filter((s) => s.verdict?.classification === 'safe').length;

  return (
    <div className="dashboard-page">
      {/* KPI Row */}
      <div className="dashboard-kpis">
        <KpiCard title="Total Emails" value={emails.length} icon={<TrendingUp size={16} />} tone="primary" subtitle="All fetched emails" delay={0} />
        <KpiCard title="Threats Detected" value={threatsCount} icon={<AlertTriangle size={16} />} tone="danger" subtitle="High-risk classification" delay={60} />
        <KpiCard title="Suspicious" value={suspiciousCount} icon={<AlertCircle size={16} />} tone="warning" subtitle="Requires investigation" delay={120} />
        <KpiCard title="Clean" value={safeCount} icon={<ShieldCheck size={16} />} tone="safe" subtitle="Safe classification" delay={180} />
      </div>

      {/* Forensics intel strip */}
      <Reveal delay={0.02}>
        <IntelStrip spoofCount={spoofCount} openCampaigns={openCampaigns} topCountries={topCountries} attribution={attribution} />
      </Reveal>

      {/* Human-in-the-loop model metrics */}
      <Reveal delay={0.05}>
        <ModelHealthCard />
      </Reveal>

      {/* Timeline + Donut */}
      <Reveal delay={0.08}>
      <div className="dashboard-split">
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: '17px 17px 9px', minWidth: 0, boxShadow: 'var(--shadow-card)' }}>
          <p className="section-label" style={{ marginBottom: 12 }}>
            Threat timeline · last 7 days
          </p>
          <div style={{ height: 216, minWidth: 0 }}>
            <ThreatTimeline scans={scans} />
          </div>
        </div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: 17, minWidth: 0, boxShadow: 'var(--shadow-card)' }}>
          <p className="section-label" style={{ marginBottom: 12 }}>
            Classification breakdown
          </p>
          <div style={{ height: 216, minWidth: 0 }}>
            <ClassificationDonut scans={scans} />
          </div>
        </div>
      </div>
      </Reveal>

      {/* 3D threat globe */}
      <Reveal delay={0.1}>
      <Suspense
        fallback={
          <div
            style={{
              height: 500,
              background: 'var(--bg-card)',
              border: '1px solid var(--border-default)',
              borderRadius: 14,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '0.8rem',
              color: 'var(--text-muted)',
              boxShadow: 'var(--shadow-card)',
            }}
          >
            Loading globe…
          </div>
        }
      >
        <IpGlobe />
      </Suspense>
      </Reveal>

      {/* Recent Activity */}
      <Reveal delay={0.12}>
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, overflow: 'hidden', boxShadow: 'var(--shadow-card)' }}>
        <div style={{ padding: '15px 18px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
          <p style={{ fontSize: '0.9rem', fontWeight: 680, color: 'var(--text-primary)' }}>Recent scan activity</p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn-ghost"
              onClick={async () => {
                try { await exportScansCsv(); } catch { /* silent */ }
              }}
              style={{ fontSize: '0.75rem', padding: '4px 12px', display: 'flex', alignItems: 'center', gap: 4 }}
            >
              <Download size={12} />
              Export CSV
            </button>
            <button className="btn-ghost" onClick={() => navigate('/scans')} style={{ fontSize: '0.75rem', padding: '4px 12px' }}>
              View All
            </button>
          </div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <RecentActivity scans={scans} emails={emails} onViewScan={(id) => navigate(`/scans/${id}`)} />
        </div>
      </div>
      </Reveal>
    </div>
  );
}
