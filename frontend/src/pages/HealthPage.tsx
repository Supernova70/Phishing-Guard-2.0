import { useEffect, useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Activity, Database, Cpu, Server, RefreshCw, CheckCircle, AlertCircle } from 'lucide-react';
import { getHealth } from '../api/client';
import { LineChart, Line, ResponsiveContainer } from 'recharts';
import type { HealthStatus } from '../types';

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
}

function ServiceCard({ name, icon, status, detail }: ServiceCardProps) {
  const isOk = status === 'healthy' || status === 'connected' || status === 'loaded' || status === 'ok' || status === 'operational';
  const color = isOk ? 'var(--safe)' : 'var(--danger)';
  const bg = isOk ? 'var(--safe-subtle)' : 'var(--danger-subtle)';
  const border = isOk ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)';

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      style={{
        background: 'var(--bg-card)',
        border: `1px solid var(--border-default)`,
        borderRadius: 8,
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
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
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          color,
          background: bg,
          border: `1px solid ${border}`,
          padding: '3px 10px',
          borderRadius: 4,
        }}>
          {status}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {isOk
          ? <CheckCircle size={14} style={{ color: 'var(--safe)' }} />
          : <AlertCircle size={14} style={{ color: 'var(--danger)' }} />
        }
        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{detail ?? (isOk ? 'Operating normally' : 'Check required')}</span>
      </div>
    </motion.div>
  );
}

export function HealthPage() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [history, setHistory] = useState<HealthSnapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchHealth = useCallback(async () => {
    const t0 = performance.now();
    try {
      const data = await getHealth();
      const latency = Math.round(performance.now() - t0);
      setHealth(data);
      setHistory((prev) => {
        const entry: HealthSnapshot = { time: Date.now(), latency, status: true };
        return [...prev.slice(-19), entry];
      });
    } catch {
      setHistory((prev) => {
        const entry: HealthSnapshot = { time: Date.now(), latency: 0, status: false };
        return [...prev.slice(-19), entry];
      });
      setHealth(null);
    } finally {
      setLoading(false);
      setLastUpdated(new Date());
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const id = setInterval(fetchHealth, 10000);
    return () => clearInterval(id);
  }, [fetchHealth]);

  const allOk = health && (health.status === 'healthy' || health.status === 'ok');
  const latestLatency = history.length > 0 ? history[history.length - 1].latency : 0;

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Main Status Banner */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          background: allOk ? 'var(--safe-subtle)' : 'var(--danger-subtle)',
          border: `1px solid ${allOk ? 'var(--safe)' : 'var(--danger)'}`,
          borderRadius: 8,
          padding: '28px 32px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          {allOk
            ? <CheckCircle size={36} style={{ color: 'var(--safe)' }} />
            : <AlertCircle size={36} style={{ color: 'var(--danger)' }} />
          }
          <div>
            <p style={{ fontSize: '1.5rem', fontWeight: 900, color: allOk ? 'var(--safe)' : 'var(--danger)', textTransform: 'uppercase', letterSpacing: '-0.01em' }}>
              {loading ? 'Checking...' : allOk ? 'All Systems Operational' : 'System Degraded'}
            </p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
              Last checked: {lastUpdated ? lastUpdated.toLocaleTimeString() : '—'} · Auto-refreshes every 10s
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ textAlign: 'right' }}>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Response Time</p>
            <p className="font-mono" style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>{latestLatency}ms</p>
          </div>
          <button className="btn-ghost" onClick={fetchHealth} style={{ padding: '8px 12px' }}>
            <RefreshCw size={14} />
          </button>
        </div>
      </motion.div>

      {/* Service Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        <ServiceCard
          name="API"
          icon={<Server size={16} />}
          status={health ? 'healthy' : 'offline'}
          detail={`${latestLatency}ms response`}
        />
        <ServiceCard
          name="Database"
          icon={<Database size={16} />}
          status={health?.database ?? 'unknown'}
        />
        <ServiceCard
          name="Redis"
          icon={<Cpu size={16} />}
          status={health?.redis ?? 'n/a'}
        />
        <ServiceCard
          name="ML Model"
          icon={<Activity size={16} />}
          status={health?.ml_model ?? 'n/a'}
        />
      </div>

      {/* Sparkline History */}
      {history.length > 1 && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '16px 20px' }}>
          <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
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
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Latest: {latestLatency}ms</span>
          </div>
        </div>
      )}

      {/* Version Info */}
      {health?.version && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '14px 20px' }}>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Backend version: <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{health.version}</span>
          </p>
        </div>
      )}
    </div>
  );
}
