import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowLeft, Brain, Link2, Paperclip, ExternalLink, AlertTriangle, ChevronDown, ChevronRight, ShieldAlert, FileText, QrCode, Flag, Check, MessageSquare } from 'lucide-react';
import { getScan, getEmail, resolveScreenshotUrl, getThreatSummary, getScanFindings, getScanThread, type ThreatSummary, type AttackTechnique, type ScanFinding, type ScanThreadResponse, type ConversationMetadata } from '../api/client';
import { getVerdictFeedback, submitVerdictFeedback, type FeedbackLabel, type VerdictFeedbackEntry } from '../api/forensics';
import { ClassificationBadge, ScoreBadge } from '../components/ui/Badge';
import { ScoreBar } from '../components/ui/ScoreBar';
import { ScoreGauge } from '../components/ui/ScoreGauge';
import { JsonViewer } from '../components/ui/JsonViewer';
import { HeaderForensics } from '../components/forensics/HeaderForensics';
import { formatDistanceToNow, format } from 'date-fns';
import type { Scan, EmailDetail, ScanBreakdown, Classification } from '../types';
import { getVtUrlLink, getVtFileLink } from '../utils/virustotal';

// ─── Verdict Feedback ────────────────────────────────────────────────────────
const FEEDBACK_OPTIONS: Array<{ label: FeedbackLabel; title: string; color: string }> = [
  { label: 'phishing', title: 'Phishing', color: 'var(--danger)' },
  { label: 'legitimate', title: 'Legitimate', color: 'var(--safe)' },
  { label: 'unsure', title: 'Not sure', color: 'var(--text-muted)' },
];

function VerdictFeedbackCard({ scanId, prediction }: { scanId: number; prediction: Classification }) {
  const [existing, setExisting] = useState<VerdictFeedbackEntry | null>(null);
  const [selected, setSelected] = useState<FeedbackLabel | null>(null);
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let active = true;
    getVerdictFeedback(scanId)
      .then((fb) => {
        if (!active) return;
        setExisting(fb);
        setSelected(fb?.label ?? null);
        setComment(fb?.comment ?? '');
      })
      .catch(() => { /* feedback is optional — never block the page */ })
      .finally(() => active && setLoaded(true));
    return () => { active = false; };
  }, [scanId]);

  const save = async (label: FeedbackLabel) => {
    setSelected(label);
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const row = await submitVerdictFeedback(scanId, label, comment);
      setExisting(row);
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save feedback');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: 20, boxShadow: 'var(--shadow-card)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <Flag size={16} style={{ color: 'var(--primary)' }} />
        <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Was this verdict right?
        </p>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          Your label is the ground truth used to measure the model.
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
        {FEEDBACK_OPTIONS.map((option) => {
          const active = selected === option.label;
          return (
            <button
              key={option.label}
              onClick={() => void save(option.label)}
              disabled={saving || !loaded}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 5,
                padding: '6px 12px',
                borderRadius: 6,
                fontSize: '0.75rem',
                fontWeight: 700,
                cursor: saving ? 'wait' : 'pointer',
                background: active ? 'var(--bg-input)' : 'transparent',
                border: `1px solid ${active ? option.color : 'var(--border-default)'}`,
                color: active ? option.color : 'var(--text-secondary)',
                opacity: saving ? 0.7 : 1,
              }}
            >
              {active && <Check size={12} />}
              {option.title}
            </button>
          );
        })}
        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          Model said <strong style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{prediction}</strong>
        </span>
      </div>

      <textarea
        value={comment}
        onChange={(e) => { setComment(e.target.value); setSaved(false); }}
        placeholder="Optional note — why is this verdict wrong or right?"
        maxLength={1000}
        rows={2}
        style={{
          width: '100%',
          marginTop: 12,
          padding: '8px 10px',
          borderRadius: 6,
          border: '1px solid var(--border-default)',
          background: 'var(--bg-input)',
          color: 'var(--text-primary)',
          fontSize: '0.78rem',
          resize: 'vertical',
          fontFamily: 'inherit',
        }}
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8, flexWrap: 'wrap' }}>
        <button
          className="btn-ghost"
          onClick={() => selected && void save(selected)}
          disabled={!selected || saving}
          style={{ fontSize: '0.72rem', padding: '4px 12px', opacity: !selected || saving ? 0.55 : 1 }}
        >
          {saving ? 'Saving…' : 'Save note'}
        </button>
        {saved && (
          <span style={{ fontSize: '0.72rem', color: 'var(--safe)' }}>
            Feedback saved — dashboard metrics updated.
          </span>
        )}
        {existing && !saved && (
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Current label: <strong style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{existing.label}</strong>
          </span>
        )}
        {error && <span style={{ fontSize: '0.72rem', color: 'var(--text-danger)' }}>{error}</span>}
      </div>
    </div>
  );
}

// ─── Verdict Hero ─────────────────────────────────────────────────────────────
function VerdictHero({ scan }: { scan: Scan }) {
  const v = scan.verdict!;
  const cls = v.classification;
  const isDangerous = cls === 'dangerous';
  const isSuspicious = cls === 'suspicious';

  const borderColor = isDangerous ? 'var(--danger)' : isSuspicious ? 'var(--warning)' : 'var(--safe)';
  const textColor = isDangerous ? 'var(--danger)' : isSuspicious ? 'var(--warning)' : 'var(--safe)';

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderLeft: `4px solid ${borderColor}`,
        borderRadius: 14,
        padding: '22px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 22,
        flexWrap: 'wrap',
        boxShadow: 'var(--shadow-card)',
      }}
    >
      <div style={{ minWidth: 0, flex: '1 1 360px' }}>
        <p className="section-label" style={{ color: textColor, marginBottom: 8 }}>
          Final verdict
        </p>
        <h2 style={{ fontSize: 'clamp(1.7rem, 3vw, 2.35rem)', fontWeight: 760, color: textColor, letterSpacing: '-0.035em', lineHeight: 1.05, textTransform: 'uppercase' }}>
          {cls}
        </h2>
        <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', marginTop: 9, lineHeight: 1.6, maxWidth: 560 }}>
          {isDangerous
            ? 'This message shows strong phishing indicators. Treat it as hostile and avoid interacting with its links or attachments.'
            : isSuspicious
              ? 'This message contains risk signals that need analyst review before it is trusted.'
              : 'No significant phishing indicators were found. Continue to apply normal sender verification.'}
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 14, flexWrap: 'wrap' }}>
          <span className="pill">
            <span className="font-mono">SCAN #{scan.id}</span>
          </span>
          <span className="pill">
            {scan.completed_at ? `Scanned ${formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })}` : 'Scan in progress'}
          </span>
          <ClassificationBadge classification={cls} size="sm" />
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 18, flexShrink: 0 }}>
        <div style={{ textAlign: 'center' }}>
          <ScoreGauge score={v.final_score} size={150} />
          <p style={{ fontSize: '0.64rem', color: 'var(--text-muted)', marginTop: -2 }}>Composite risk score</p>
        </div>
      </div>
    </motion.div>
  );
}

// ─── Engine Card ──────────────────────────────────────────────────────────────
function EngineCard({ name, score, icon, children }: { name: string; score: number; icon: React.ReactNode; children?: React.ReactNode }) {
  const label = score >= 70 ? 'HIGH RISK' : score >= 30 ? 'MEDIUM RISK' : 'CLEAN';
  const color = score >= 70 ? 'var(--danger)' : score >= 30 ? 'var(--warning)' : 'var(--safe)';

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: 20, boxShadow: 'var(--shadow-card)', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color }}>{icon}</span>
        <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{name}</p>
      </div>
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <ScoreGauge score={score} size={130} />
      </div>
      <div style={{ textAlign: 'center' }}>
        <span style={{
          fontSize: '0.7rem',
          fontWeight: 700,
          letterSpacing: '0.1em',
          color,
          background: score >= 70 ? 'var(--danger-subtle)' : score >= 30 ? 'var(--warning-subtle)' : 'var(--safe-subtle)',
          padding: '3px 10px',
          borderRadius: 4,
        }}>
          {label}
        </span>
      </div>
      {children}
    </div>
  );
}

// ─── URL Row ──────────────────────────────────────────────────────────────────
function UrlRow({ urlEntry }: { urlEntry: ScanBreakdown['url']['per_url'][0] }) {
  const [expanded, setExpanded] = useState(false);
  const { url, score, top_flags, flags, vt_malicious } = urlEntry;
  const displayFlags = top_flags ?? flags ?? [];
  const screenshotUrl = resolveScreenshotUrl(
    urlEntry.screenshot_url,
    urlEntry.playwright_screenshot_path,
  );

  return (
    <div style={{ borderBottom: '1px solid var(--border-subtle)' }}>
      <div
        onClick={() => setExpanded((e) => !e)}
        style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px', cursor: 'pointer', transition: 'background 200ms' }}
        onMouseEnter={(e) => (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-input)'}
        onMouseLeave={(e) => (e.currentTarget as HTMLDivElement).style.background = 'transparent'}
      >
        {expanded ? <ChevronDown size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} /> : <ChevronRight size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />}
        <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {url}
        </span>
        <ScoreBadge score={score} size="sm" />
        {vt_malicious > 0 && (
          <span style={{ fontSize: '0.7rem', background: 'var(--danger-subtle)', color: 'var(--text-danger)', padding: '2px 6px', borderRadius: 4 }}>
            {vt_malicious} VT hits
          </span>
        )}
      </div>
      {expanded && (
        <div style={{ padding: '12px 32px 16px', background: 'var(--bg-input)' }}>
          <p className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', wordBreak: 'break-all', marginBottom: 12 }}>{url}</p>
          {displayFlags.length > 0 && (
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
              {displayFlags.map((flag, i) => (
                <span key={i} style={{
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: 'var(--danger-subtle)',
                  color: 'var(--text-danger)',
                  border: '1px solid var(--danger-border)',
                }}>
                  {flag}
                </span>
              ))}
            </div>
          )}
          {urlEntry.vt_error && (
            <p style={{ color: 'var(--text-warning)', fontSize: '0.72rem', marginBottom: 10 }}>
              VirusTotal: {urlEntry.vt_error}
            </p>
          )}
          {urlEntry.dynamic_status && (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginBottom: 10 }}>
              Browser analysis: {urlEntry.dynamic_status}
              {urlEntry.final_url ? ` · Final URL: ${urlEntry.final_url}` : ''}
            </p>
          )}
          {screenshotUrl && (
            <a
              href={screenshotUrl}
              target="_blank"
              rel="noreferrer noopener"
              onClick={(e) => e.stopPropagation()}
              style={{ display: 'block', marginBottom: 12 }}
            >
              <img
                src={screenshotUrl}
                alt={`Browser evidence for ${url}`}
                loading="lazy"
                style={{ width: '100%', maxWidth: 720, borderRadius: 6, border: '1px solid var(--border-default)' }}
              />
            </a>
          )}
          <a
            href={getVtUrlLink(url)}
            target="_blank"
            rel="noreferrer noopener"
            onClick={(e) => e.stopPropagation()}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', color: 'var(--primary)', textDecoration: 'none' }}
          >
            <ExternalLink size={12} /> Open in VirusTotal ↗
          </a>
        </div>
      )}
    </div>
  );
}

// ─── YARA Match Card ──────────────────────────────────────────────────────────
function YaraMatchCard({ match }: { match: {
  rule: string;
  severity: string;
  tags: string[];
  description: string;
  explanation?: string;
  matched_strings?: string[];
  evidence?: Array<{ string: string; offset: number; preview: string; count: number }>;
} }) {
  return (
    <div style={{
      background: 'var(--danger-subtle)',
      border: '1px solid var(--danger-border)',
      borderRadius: 6,
      padding: '10px 14px',
      display: 'flex',
      gap: 10,
      alignItems: 'flex-start',
    }}>
      <AlertTriangle size={14} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: 2 }} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <p className="font-mono" style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-danger)' }}>{match.rule}</p>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: 2 }}>{match.description}</p>
        {match.explanation && (
          <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontStyle: 'italic', marginTop: 4 }}>
            {match.explanation}
          </p>
        )}
        {match.evidence && match.evidence.length > 0 && (
          <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 3 }}>
            <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Matched evidence
            </p>
            {match.evidence.map((ev, i) => (
              <p key={i} className="font-mono" style={{
                fontSize: '0.7rem',
                color: 'var(--text-secondary)',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 4,
                padding: '3px 8px',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}>
                {ev.string} @ 0x{ev.offset.toString(16)}{' · '}{ev.count}×{' · '}“{ev.preview}”
              </p>
            ))}
          </div>
        )}
        <div style={{ display: 'flex', gap: 4, marginTop: 6, flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.65rem', background: 'var(--danger-subtle)', color: 'var(--text-danger)', padding: '1px 6px', borderRadius: 3, fontWeight: 700 }}>
            {match.severity.toUpperCase()}
          </span>
          {match.tags.map((t, i) => (
            <span key={i} style={{ fontSize: '0.65rem', background: 'var(--bg-input)', color: 'var(--text-muted)', padding: '1px 6px', borderRadius: 3 }}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── AI Threat Summary Card ───────────────────────────────────────────────────
function ThreatSummaryCard({ scanId }: { scanId: number }) {
  const [summary, setSummary] = useState<ThreatSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getThreatSummary(scanId)
      .then(setSummary)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) {
    return (
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: 20, boxShadow: 'var(--shadow-card)' }}>
        <div className="skeleton" style={{ height: 16, width: '30%', borderRadius: 4, marginBottom: 12 }} />
        <div className="skeleton" style={{ height: 12, width: '100%', borderRadius: 4, marginBottom: 8 }} />
        <div className="skeleton" style={{ height: 12, width: '80%', borderRadius: 4 }} />
      </div>
    );
  }

  if (error || !summary) return null;

  const borderColor = summary.classification === 'dangerous'
    ? 'var(--danger)' : summary.classification === 'suspicious'
    ? 'var(--warning)' : 'var(--safe)';

  const techniques = summary.techniques ?? [];
  const byTactic = techniques.reduce<Record<string, AttackTechnique[]>>((acc, tech) => {
    (acc[tech.tactic] ||= []).push(tech);
    return acc;
  }, {});
  const tacticCount = Object.keys(byTactic).length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderTop: `3px solid ${borderColor}`,
        borderRadius: 14,
        padding: 24,
        boxShadow: 'var(--shadow-card)',
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <ShieldAlert size={20} style={{ color: borderColor }} />
        <p style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          AI Threat Analysis
        </p>
      </div>

      {/* Summary Paragraph */}
      <p style={{
        fontSize: '0.875rem',
        color: 'var(--text-secondary)',
        lineHeight: 1.7,
        background: 'var(--bg-input)',
        borderLeft: `3px solid ${borderColor}`,
        padding: '12px 16px',
        borderRadius: '0 6px 6px 0',
      }}>
        {summary.summary}
      </p>

      {/* Key Findings */}
      {summary.key_findings.length > 0 && (
        <div>
          <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
            Key Findings
          </p>
          <ul style={{ display: 'flex', flexDirection: 'column', gap: 6, paddingLeft: 0, listStyle: 'none' }}>
            {summary.key_findings.map((finding, i) => (
              <li key={i} style={{
                fontSize: '0.8rem',
                color: 'var(--text-secondary)',
                padding: '6px 10px',
                background: 'var(--bg-input)',
                borderRadius: 4,
                borderLeft: '2px solid var(--primary)',
              }}>
                {finding}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Risk Factors */}
      {summary.risk_factors.length > 0 && (
        <div>
          <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
            Risk Factors
          </p>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {summary.risk_factors.map((rf, i) => (
              <span key={i} style={{
                fontSize: '0.7rem',
                fontWeight: 600,
                padding: '3px 10px',
                borderRadius: 4,
                background: rf.severity === 'high' ? 'var(--danger-subtle)' : 'var(--warning-subtle)',
                color: rf.severity === 'high' ? 'var(--text-danger)' : 'var(--text-warning)',
                border: `1px solid ${rf.severity === 'high' ? 'var(--danger-border)' : 'var(--warning-border)'}`,
              }}>
                {rf.engine}: {rf.detail}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Coverage */}
      {techniques.length > 0 && (
        <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
            <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              MITRE ATT&amp;CK Coverage
            </p>
            <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
              {techniques.length} technique{techniques.length !== 1 ? 's' : ''} · {tacticCount} tactic{tacticCount !== 1 ? 's' : ''}
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {Object.entries(byTactic).map(([tactic, list]) => (
              <div key={tactic}>
                <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                  {tactic}
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {list.map((tech) => {
                    const confColor = tech.confidence === 'high'
                      ? 'var(--primary)'
                      : tech.confidence === 'medium'
                      ? 'var(--warning)'
                      : 'var(--text-muted)';
                    return (
                      <div key={tech.id} style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '8px 10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                          <a
                            href={tech.url}
                            target="_blank"
                            rel="noreferrer"
                            style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--primary)', textDecoration: 'none', fontWeight: 600 }}
                          >
                            {tech.id} ↗
                          </a>
                          <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>{tech.name}</span>
                          <span style={{
                            marginLeft: 'auto',
                            fontSize: '0.6rem',
                            fontWeight: 700,
                            textTransform: 'uppercase',
                            letterSpacing: '0.06em',
                            color: confColor,
                            border: `1px solid ${confColor}`,
                            borderRadius: 999,
                            padding: '1px 7px',
                          }}>
                            {tech.confidence}
                          </span>
                        </div>
                        {tech.evidence.slice(0, 3).map((line, i) => (
                          <p key={i} style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 4, paddingLeft: 2 }}>
                            • {line}
                          </p>
                        ))}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
}

// ─── Conversation / thread BEC card ──────────────────────────────────────────
function ConversationCard({ scanId }: { scanId: number }) {
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [conversation, setConversation] = useState<ConversationMetadata | null>(null);
  const [thread, setThread] = useState<ScanThreadResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.allSettled([getScanFindings(scanId), getScanThread(scanId)])
      .then(([findingsResult, threadResult]) => {
        if (!active) return;
        if (findingsResult.status === 'fulfilled') {
          const conversationFindings = findingsResult.value.findings.filter(
            (item) =>
              item.category === 'thread' ||
              item.category === 'bec' ||
              item.category === 'identity' ||
              item.category === 'kit' ||
              item.category === 'active_content',
          );
          setFindings(conversationFindings);
          setConversation(findingsResult.value.conversation);
        }
        if (threadResult.status === 'fulfilled') setThread(threadResult.value);
        if (findingsResult.status === 'rejected' && threadResult.status === 'rejected') {
          setError('Conversation evidence unavailable');
        }
      })
      .catch(() => active && setError('Conversation evidence unavailable'));
    return () => { active = false; };
  }, [scanId]);

  if (error) return null;
  if (!conversation && !thread) return null;
  if ((conversation?.prior_messages ?? 0) === 0 && findings.length === 0) return null;

  const severityColor = (severity: number) =>
    severity >= 65 ? 'var(--danger)' : severity >= 30 ? 'var(--warning)' : 'var(--primary)';

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: 20, boxShadow: 'var(--shadow-card)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <MessageSquare size={17} style={{ color: 'var(--primary)' }} />
        <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Identity &amp; Conversation
        </p>
        <span style={{
          fontSize: '0.62rem',
          fontWeight: 700,
          color: 'var(--warning)',
          border: '1px solid var(--warning)',
          borderRadius: 999,
          padding: '1px 7px',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
        }}>
          Shadow · score unchanged
        </span>
        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
          {conversation?.prior_messages ?? 0} earlier message{(conversation?.prior_messages ?? 0) === 1 ? '' : 's'} in thread
        </span>
      </div>

      {conversation?.thread_key && (
        <p className="font-mono" style={{ fontSize: '0.66rem', color: 'var(--text-muted)', marginTop: 8, wordBreak: 'break-all' }}>
          {conversation.thread_key}
        </p>
      )}

      {findings.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 14 }}>
          {findings.map((finding) => (
            <div key={finding.id} style={{
              background: 'var(--bg-input)',
              borderLeft: `3px solid ${severityColor(finding.severity)}`,
              borderRadius: '0 6px 6px 0',
              padding: '9px 12px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-primary)' }}>{finding.title}</span>
                <span className="font-mono" style={{ fontSize: '0.62rem', color: severityColor(finding.severity), marginLeft: 'auto' }}>
                  {finding.code} · {finding.severity.toFixed(0)}
                </span>
              </div>
              {finding.evidence.slice(0, 2).map((evidence, index) => (
                <p key={index} className="font-mono" style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', marginTop: 4, wordBreak: 'break-word' }}>
                  {evidence.kind}: {evidence.value}
                </p>
              ))}
            </div>
          ))}
        </div>
      )}

      {findings.length === 0 && (
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 10 }}>
          No conversation-specific risk signals were found in this thread.
        </p>
      )}

      {thread && thread.messages.length > 1 && (
        <div style={{ marginTop: 16, borderTop: '1px solid var(--border-subtle)', paddingTop: 12 }}>
          <p style={{ fontSize: '0.66rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
            Thread timeline
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {thread.messages.map((message) => (
              <div key={message.email_id} style={{ display: 'flex', gap: 8, alignItems: 'baseline', opacity: message.is_current ? 1 : 0.72 }}>
                <span style={{ fontSize: '0.62rem', color: 'var(--text-muted)', minWidth: 20 }}>#{message.email_id}</span>
                <span style={{ fontSize: '0.72rem', color: message.is_current ? 'var(--text-primary)' : 'var(--text-secondary)', fontWeight: message.is_current ? 700 : 400, flex: 1 }}>
                  {message.subject}
                </span>
                <span style={{ fontSize: '0.66rem', color: 'var(--text-muted)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {message.sender}
                </span>
                {message.has_attachments && <Paperclip size={11} style={{ color: 'var(--text-muted)' }} />}
                {message.is_current && <span style={{ fontSize: '0.6rem', color: 'var(--primary)' }}>current</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Scan Detail Page ─────────────────────────────────────────────────────────
export function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [email, setEmail] = useState<EmailDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    queueMicrotask(() => setLoading(true));
    getScan(Number(id))
      .then(async (s) => {
        setScan(s);
        try {
          const em = await getEmail(s.email_id);
          setEmail(em);
        } catch {
          /* email context is optional — scan still renders */
        }
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load scan'))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {[140, 300, 200, 240].map((h, i) => <div key={i} className="skeleton" style={{ height: h, borderRadius: 8 }} />)}
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ border: '1px solid var(--danger)', borderRadius: 8, background: 'var(--danger-subtle)', padding: 20 }}>
          <p style={{ color: 'var(--text-danger)', fontWeight: 600 }}>{error ?? 'Scan not found'}</p>
          <button className="btn-ghost" onClick={() => navigate('/scans')} style={{ marginTop: 12, fontSize: '0.8rem' }}>← Back to Scans</button>
        </div>
      </div>
    );
  }

  const v = scan.verdict;
  const bd = v?.breakdown;

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 1100 }}>
      {/* Back */}
      <button className="btn-ghost" onClick={() => navigate('/scans')} style={{ width: 'fit-content', fontSize: '0.8rem' }}>
        <ArrowLeft size={14} /> Back to Results
      </button>

      {/* Verdict Hero */}
      {v ? <VerdictHero scan={scan} /> : (
        <div style={{ padding: 32, background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, textAlign: 'center' }}>
          <p style={{ color: 'var(--text-muted)' }}>Scan status: <strong style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>{scan.status}</strong></p>
        </div>
      )}

      {/* AI Threat Summary */}
      {v && <ThreatSummaryCard scanId={scan.id} />}

      {/* Email Info */}
      {email && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: '16px 20px', boxShadow: 'var(--shadow-card)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Email Details</p>
              <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>{email.subject}</p>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>From: {email.sender} · {email.date ? format(new Date(email.date), 'PPpp') : '—'}</p>
            </div>
            <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
              <button
                className="btn-ghost"
                onClick={() => navigate(`/scans/${scan.id}/report`)}
                style={{ fontSize: '0.72rem', padding: '5px 12px', display: 'flex', alignItems: 'center', gap: 4 }}
              >
                <FileText size={12} /> Forensic Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Conversation-aware BEC (shadow) */}
      {v && <ConversationCard scanId={scan.id} />}

      {/* Analyst feedback (ground truth for model metrics) */}
      {v && <VerdictFeedbackCard scanId={scan.id} prediction={v.classification} />}

      {/* Header forensics */}
      <HeaderForensics emailId={scan.email_id} flags={bd?.header?.flags ?? []} rules={bd?.header?.rules ?? []} />

      {/* Engine Breakdown */}
      {v && (
        <>
          <div>
            <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 12 }}>Engine Analysis</p>
            <div className="engine-grid" style={{ display: 'grid', gap: 16 }}>
              <EngineCard name="ML Engine" score={v.ai_score ?? 0} icon={<Brain size={16} />}>
                {bd?.ai && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4 }}>
                    <ScoreBar score={bd.ai.score} label="Confidence" />
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Label:</span>
                      <span style={{ fontSize: '0.75rem', fontWeight: 700, color: bd.ai.is_phishing ? 'var(--text-danger)' : 'var(--text-safe)' }}>
                        {bd.ai.is_phishing ? 'Phishing' : 'Legitimate'}
                      </span>
                    </div>
                  </div>
                )}
              </EngineCard>
              <EngineCard name="URL Engine" score={v.url_score ?? 0} icon={<Link2 size={16} />}>
                {bd?.url && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Total URLs</span><span className="font-mono" style={{ color: 'var(--text-primary)' }}>{bd.url.total_urls}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>High Risk</span><span className="font-mono" style={{ color: 'var(--text-danger)' }}>{bd.url.high_risk_urls.length}</span>
                    </div>
                  </div>
                )}
              </EngineCard>
              <EngineCard name="Attachment Engine" score={v.attachment_score ?? 0} icon={<Paperclip size={16} />}>
                {bd?.attachment && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Files</span><span className="font-mono" style={{ color: 'var(--text-primary)' }}>{bd.attachment.total_files}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>High Risk</span><span className="font-mono" style={{ color: 'var(--text-danger)' }}>{bd.attachment.high_risk_files.length}</span>
                    </div>
                  </div>
                )}
              </EngineCard>
            </div>
          </div>

          {/* URL Analysis */}
          {bd?.url && bd.url.per_url.length > 0 && (
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, overflow: 'hidden', boxShadow: 'var(--shadow-card)' }}>
              <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Link2 size={16} style={{ color: 'var(--primary)' }} />
                <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>URL Analysis</p>
                <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 4 }}>{bd.url.per_url.length} URL{bd.url.per_url.length !== 1 ? 's' : ''}</span>
              </div>
              {/* Table header */}
              <div style={{ display: 'flex', gap: 12, padding: '8px 16px', background: 'var(--bg-input)', borderBottom: '1px solid var(--border-subtle)' }}>
                {['URL', 'Score', 'VT Hits'].map((h) => (
                  <span key={h} style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{h}</span>
                ))}
              </div>
              {bd.url.per_url.map((urlEntry, i) => <UrlRow key={i} urlEntry={urlEntry} />)}
            </div>
          )}

          {/* Attachment Analysis */}
          {bd?.attachment && bd.attachment.per_file.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                <Paperclip size={13} style={{ display: 'inline', marginRight: 6 }} />
                Attachment Analysis
              </p>
              {bd.attachment.per_file.map((file, i) => (
                <div key={i} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: 20, boxShadow: 'var(--shadow-card)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                    <div>
                      <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>{file.filename}</p>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>{file.file_type}</p>
                    </div>
                    <ScoreBadge score={file.risk_score} />
                  </div>
                  <ScoreBar score={file.risk_score} label="Risk Score" />

                  {/* Why this score — explainable breakdown */}
                  {(file.score_breakdown?.length ?? 0) > 0 && (
                    <div style={{ marginTop: 12, padding: '10px 12px', background: 'var(--bg-input)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                      <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
                        Why this score
                      </p>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {file.score_breakdown!.map((entry, k) => (
                          <div key={k} style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                            <span className="font-mono" style={{
                              fontSize: '0.7rem', fontWeight: 700, flexShrink: 0, minWidth: 44, textAlign: 'right',
                              color: entry.points >= 60 ? 'var(--text-danger)' : entry.points >= 25 ? 'var(--text-warning)' : 'var(--text-muted)',
                            }}>
                              +{entry.points}
                            </span>
                            <div style={{ minWidth: 0 }}>
                              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>{entry.signal}</span>
                              {entry.detail && (
                                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}> — {entry.detail}</span>
                              )}
                              {entry.evidence && entry.evidence.length > 0 && (
                                <div style={{ marginTop: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
                                  {entry.evidence.map((ev, ei) => (
                                    <p key={ei} className="font-mono" style={{
                                      fontSize: '0.68rem', color: 'var(--text-secondary)',
                                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                    }}>{ev}</p>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Embedded URLs (metadata vs payload) */}
                  {(file.embedded_urls?.length ?? 0) > 0 && (
                    <div style={{ marginTop: 12 }}>
                      <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>
                        Embedded URLs ({file.embedded_urls!.length})
                      </p>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                        {file.embedded_urls!.map((u, ui) => (
                          <p key={ui} className="font-mono" style={{
                            fontSize: '0.68rem', color: 'var(--text-secondary)',
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                          }}>{u}</p>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* VT Hash Results */}
                  {(file.vt_total ?? 0) > 0 && (
                    <div style={{ marginTop: 12, padding: '8px 12px', background: 'var(--bg-input)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>VT Hash Check: </span>
                      <span style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.72rem',
                        color: (file.vt_malicious ?? 0) > 0 ? 'var(--text-danger)' : 'var(--text-safe)',
                        fontWeight: 700,
                      }}>
                        {(file.vt_malicious ?? 0) > 0
                          ? `${file.vt_malicious} malicious · ${file.vt_suspicious ?? 0} suspicious`
                          : `Clean (${file.vt_total} engines checked)`
                        }
                      </span>
                    </div>
                  )}

                  {/* VT Error */}
                  {file.vt_error && (
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-warning)', marginTop: 8, display: 'flex', alignItems: 'center', gap: 4 }}>
                      ⚠ VT: {file.vt_error}
                    </div>
                  )}

                  {/* Open in VirusTotal (file hash link) */}
                  {file.sha256 && (
                    <div style={{ marginTop: 10 }}>
                      <a
                        href={getVtFileLink(file.sha256)}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          color: 'var(--primary)',
                          fontSize: '0.75rem',
                          textDecoration: 'none',
                          fontWeight: 600,
                        }}
                      >
                        <ExternalLink size={12} />
                        Open in VirusTotal ↗
                      </a>
                    </div>
                  )}

                  {file.yara_matches.length > 0 && (
                    <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                        YARA Matches ({file.yara_matches.length})
                      </p>
                      {file.yara_matches.map((m, j) => <YaraMatchCard key={j} match={m} />)}
                    </div>
                  )}

                  {file.findings.length > 0 && (
                    <div style={{ marginTop: 14 }}>
                      <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Findings</p>
                      <ul style={{ paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {file.findings.map((f, j) => (
                          <li key={j} style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{f}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Quishing (QR codes hidden in attachments) */}
          {bd?.qr?.present && (
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: 20, boxShadow: 'var(--shadow-card)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <QrCode size={16} style={{ color: 'var(--primary)' }} />
                <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Quishing — QR / barcode payloads
                </p>
                <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: 4 }}>
                  {bd.qr.code_count} symbol{bd.qr.code_count === 1 ? '' : 's'} ·{' '}
                  {bd.qr.url_count} URL{bd.qr.url_count === 1 ? '' : 's'}
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {bd.qr.codes.map((code, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '10px 12px',
                      borderRadius: 6,
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                      <span style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        {code.format} · {code.container}
                        {code.page ? ` · page ${code.page}` : ''}
                      </span>
                      <span style={{ fontSize: '0.65rem', color: code.is_url ? 'var(--warning)' : 'var(--text-muted)' }}>
                        {code.is_url ? 'URL payload' : 'non-URL payload'}
                      </span>
                    </div>
                    <p className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                      {code.value}
                    </p>
                  </div>
                ))}
              </div>

              <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 10 }}>
                Decoded URLs are scored by the URL engine and included in the URL score
                {bd.qr.score > 0 ? ` (max ${Math.round(bd.qr.score)})` : ''}.
              </p>
            </div>
          )}

          {/* Raw Breakdown */}
          {v.breakdown && <JsonViewer data={v.breakdown} title="Raw Breakdown JSON" />}
        </>
      )}
    </div>
  );
}
