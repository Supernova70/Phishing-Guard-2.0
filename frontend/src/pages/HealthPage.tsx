import { useCallback, useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Activity, Database, Server, RefreshCw, CheckCircle, AlertTriangle, AlertCircle, Globe2, Shield } from 'lucide-react';
import { LineChart, Line, ResponsiveContainer } from 'recharts';
import { useSystemHealth } from '../hooks/useSystemHealth';

interface HealthSnapshot {
  time: number;
  latency: number;
  status: boolean;
}

interface ServiceCardProps {
  name: string;
  icon: React.ReactNode;
  status: string;
  detail?: string;
  variant?: 'healthy' | 'error' | 'warning' | 'unknown';
}

function ServiceCard({ name, icon, status, detail, variant = 'unknown' }: ServiceCardProps) {
  const colors = {
    healthy: { text: 'var(--text-safe)', bg: 'var(--safe-subtle)', border: 'var(--safe-border)' },
    error:   { text: 'var(--text-danger)', bg: 'rgba(239,68,68,0.1)',   border: 'var(--danger-border)' },
    warning: { text: 'var(--text-warning)', bg: 'var(--warning-subtle)',  border: 'var(--warning-border)' },
    unknown: { text: 'var(--text-muted)', bg: 'var(--bg-subtle)', border: 'var(--border-default)' },
  };
  const c = colors[variant];

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      style={{
        background: 'var(--bg-card)',
        border: `1px solid var(--border-default)`,
        borderRadius: 14,
        padding: '18px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        boxShadow: 'var(--shadow-card)',
        minWidth: 0,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ color: 'var(--text-muted)' }}>{icon}</div>
          <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>{name}</span>
        </div>
        <span style={{
          fontSize: '0.7rem',
          fontWeight: 700,
          textTransform: 'uppercase' as const,
          letterSpacing: '0.06em',
          color: c.text,
          background: c.bg,
          border: `1px solid ${c.border}`,
          padding: '3px 10px',
          borderRadius: 4,
        }}>
          {status}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {variant === 'healthy'
          ? <CheckCircle size={14} style={{ color: 'var(--safe)' }} />
          : variant === 'error'
          ? <AlertCircle size={14} style={{ color: 'var(--danger)' }} />
          : <AlertCircle size={14} style={{ color: 'var(--text-muted)' }} />
        }
        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.5, overflowWrap: 'anywhere' }}>
          {detail ?? 'No detail available'}
        </span>
      </div>
    </motion.div>
  );
}

export function HealthPage() {
  const { health, loading: hookLoading, refresh } = useSystemHealth();
  const [history, setHistory] = useState<HealthSnapshot[]>([]);
  const [latency, setLatency] = useState(0);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [manualLoading, setManualLoading] = useState(false);

  const fetchAndTrack = useCallback(async () => {
    const t0 = performance.now();
    await refresh();
    const ms = Math.round(performance.now() - t0);
    setLatency(ms);
    setHistory((prev) => [...prev.slice(-19), { time: Date.now(), latency: ms, status: true }]);
    setLastUpdated(new Date());
  }, [refresh]);

  useEffect(() => {
    if (!health) return;
    queueMicrotask(() => {
      setLatency(health.response_time_ms);
      setLastUpdated(new Date());
      setHistory((prev) => [...prev.slice(-19), {
        time: Date.now(), latency: health.response_time_ms, status: true,
      }]);
    });
  }, [health]);

  const handleRefresh = async () => {
    setManualLoading(true);
    await fetchAndTrack();
    setManualLoading(false);
  };

  const allOk = health?.status === 'ok';
  const dbStatus = health?.components?.database?.status;
  const mlStatus = health?.components?.ml_model?.status;
  const dynamicStatus = health?.components?.dynamic_url?.status;
  const vtComponent = health?.components?.virustotal;
  const vtRot = vtComponent?.rotation;

  // Determine failing components for degraded banner
  const failingComponents: string[] = [];
  if (health?.status === 'degraded') {
    if (dbStatus === 'error') failingComponents.push('Database');
    if (mlStatus === 'not_loaded') failingComponents.push('ML Model');
  }

  return (
    <div className="health-page" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Main Status Banner */}
      <motion.div
        className="health-banner"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          background: allOk ? 'var(--safe-subtle)' : health ? 'var(--warning-subtle)' : 'rgba(239,68,68,0.08)',
          border: `1px solid ${allOk ? 'var(--safe)' : health ? 'var(--warning)' : 'var(--danger)'}`,
          borderRadius: 14,
          padding: '24px 26px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 16,
          flexWrap: 'wrap',
          boxShadow: 'var(--shadow-card)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          {allOk
            ? <CheckCircle size={36} style={{ color: 'var(--safe)' }} />
            : <AlertTriangle size={36} style={{ color: health ? 'var(--warning)' : 'var(--danger)' }} />
          }
          <div>
            <p style={{
              fontSize: '1.5rem',
              fontWeight: 900,
              color: allOk ? 'var(--safe)' : health ? 'var(--warning)' : 'var(--danger)',
              textTransform: 'uppercase' as const,
              letterSpacing: '-0.01em',
            }}>
              {hookLoading ? 'Checking...' : allOk ? 'All Systems Operational' : health ? 'System Degraded' : 'Backend Offline'}
            </p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
              Last checked: {lastUpdated ? lastUpdated.toLocaleTimeString() : '—'} · Auto-refreshes every 30s
            </p>
            {failingComponents.length > 0 && (
              <p style={{ fontSize: '0.8rem', color: 'var(--text-warning)', marginTop: 6 }}>
                Failing: {failingComponents.join(', ')}
              </p>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ textAlign: 'right' }}>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.08em' }}>
              Response Time
            </p>
            <p className="font-mono" style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {health?.response_time_ms ?? latency}ms
            </p>
          </div>
          <button className="btn-ghost" onClick={handleRefresh} style={{ padding: '8px 12px' }}>
            <RefreshCw size={14} style={{ animation: manualLoading ? 'spin 1s linear infinite' : 'none' }} />
          </button>
        </div>
      </motion.div>

      {/* Service cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 16 }}>
        <ServiceCard
          name="API"
          icon={<Server size={16} />}
          status={health ? (allOk ? 'HEALTHY' : 'DEGRADED') : 'OFFLINE'}
          detail={health ? `${health.response_time_ms}ms response` : 'Cannot reach backend'}
          variant={health ? (allOk ? 'healthy' : 'warning') : 'error'}
        />
        <ServiceCard
          name="Dynamic URL"
          icon={<Globe2 size={16} />}
          status={!health ? 'UNKNOWN' : dynamicStatus === 'enabled' ? 'ENABLED' : 'DISABLED'}
          detail={health?.components?.dynamic_url?.detail ?? 'No data'}
          variant={!health ? 'unknown' : dynamicStatus === 'enabled' ? 'healthy' : 'warning'}
        />
        <ServiceCard
          name="Database"
          icon={<Database size={16} />}
          status={
            !health ? 'UNKNOWN' :
            dbStatus === 'connected' ? 'HEALTHY' : 'ERROR'
          }
          detail={health?.components?.database?.detail ?? 'No data'}
          variant={
            !health ? 'unknown' :
            dbStatus === 'connected' ? 'healthy' : 'error'
          }
        />
        <ServiceCard
          name="ML Model"
          icon={<Activity size={16} />}
          status={
            !health ? 'UNKNOWN' :
            mlStatus === 'loaded' ? 'LOADED' : 'NOT LOADED'
          }
          detail={health?.components?.ml_model?.detail ?? 'No data'}
          variant={
            !health ? 'unknown' :
            mlStatus === 'loaded' ? 'healthy' : 'warning'
          }
        />
        <ServiceCard
          name="VirusTotal"
          icon={<Shield size={16} />}
          status={
            !health ? 'UNKNOWN' :
            !vtRot ? (vtComponent?.status === 'configured' ? 'CONFIGURED' : 'NOT SET') :
            vtRot.invalid >= vtRot.key_count && vtRot.key_count > 0 ? 'KEYS DEAD' :
            vtRot.available === 0 ? 'COOLDOWN' :
            vtRot.cooling_down > 0 ? 'ROTATING' : 'ACTIVE'
          }
          detail={
            vtRot
              ? `${vtRot.available}/${vtRot.key_count} keys ready · ${vtRot.cooling_down} cooling · ${vtRot.invalid} invalid · ${vtRot.total_calls} calls`
              : vtComponent?.detail ?? 'No data'
          }
          variant={
            !health ? 'unknown' :
            !vtRot ? (vtComponent?.status === 'configured' ? 'healthy' : 'warning') :
            vtRot.invalid >= vtRot.key_count && vtRot.key_count > 0 ? 'error' :
            vtRot.available === 0 ? 'warning' :
            'healthy'
          }
        />
      </div>

      {/* VirusTotal key pool — per-key rotation state */}
      {vtRot?.keys && vtRot.keys.length > 0 && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: '16px 20px', boxShadow: 'var(--shadow-card)' }}>
          <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 4, textTransform: 'uppercase' as const, letterSpacing: '0.06em' }}>
            VirusTotal Key Pool ({vtRot.keys.length})
          </p>
          <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 12 }}>
            Call counters are per backend worker (2 workers) — totals may alternate between refreshes. Key states converge within seconds.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 8 }}>
            {vtRot.keys.map((k) => {
              const stateColor = k.state === 'ready' ? 'var(--text-safe)' : k.state === 'cooldown' ? 'var(--text-warning)' : 'var(--text-danger)';
              const stateBg = k.state === 'ready' ? 'var(--safe-subtle)' : k.state === 'cooldown' ? 'var(--warning-subtle)' : 'var(--danger-subtle)';
              const stateBorder = k.state === 'ready' ? 'var(--safe-border)' : k.state === 'cooldown' ? 'var(--warning-border)' : 'var(--danger-border)';
              const stateLabel = k.state === 'cooldown'
                ? `cooldown ${Math.floor(k.cooldown_remaining / 60)}m ${k.cooldown_remaining % 60}s`
                : k.state;
              return (
                <div
                  key={k.id}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    border: '1px solid var(--border-default)', borderRadius: 6, padding: '8px 12px', gap: 8,
                  }}
                >
                  <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    #{k.id} {k.masked}
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                      {k.calls} calls
                    </span>
                    <span style={{
                      fontSize: '0.66rem', fontWeight: 700, textTransform: 'uppercase' as const,
                      color: stateColor, background: stateBg,
                      border: `1px solid ${stateBorder}`, padding: '2px 7px', borderRadius: 8,
                    }}>
                      {stateLabel}
                    </span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Sparkline History */}
      {history.length > 1 && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: '16px 20px', boxShadow: 'var(--shadow-card)' }}>
          <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase' as const, letterSpacing: '0.06em' }}>
            Response Time History (last {history.length} checks)
          </p>
          <div style={{ height: 80 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <Line
                  type="monotone"
                  dataKey="latency"
                  stroke="var(--primary)"
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Oldest</span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Latest: {latency}ms</span>
          </div>
        </div>
      )}

      {/* Version Info */}
      {health?.version && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 14, padding: '14px 20px', boxShadow: 'var(--shadow-card)' }}>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Backend version: <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{health.version}</span>
          </p>
        </div>
      )}
    </div>
  );
}
