import type { Classification } from '../../types';

interface BadgeProps {
  classification: Classification;
  size?: 'sm' | 'md';
}

const config: Record<Classification, { label: string; bg: string; text: string; glow: string }> = {
  dangerous: {
    label: 'DANGEROUS',
    bg: 'var(--danger-subtle)',
    text: 'var(--text-danger)',
    glow: '0 0 10px rgba(239,68,68,0.35)',
  },
  suspicious: {
    label: 'SUSPICIOUS',
    bg: 'var(--warning-subtle)',
    text: 'var(--text-warning)',
    glow: '0 0 10px rgba(245,158,11,0.35)',
  },
  safe: {
    label: 'SAFE',
    bg: 'var(--safe-subtle)',
    text: 'var(--text-safe)',
    glow: '0 0 10px rgba(16,185,129,0.25)',
  },
};

export function ClassificationBadge({ classification, size = 'md' }: BadgeProps) {
  const c = config[classification];
  const padding = size === 'sm' ? '2px 8px' : '3px 10px';
  const fontSize = size === 'sm' ? '0.65rem' : '0.7rem';

  return (
    <span
      style={{
        background: c.bg,
        color: c.text,
        boxShadow: c.glow,
        padding,
        fontSize,
        fontWeight: 700,
        letterSpacing: '0.08em',
        borderRadius: '4px',
        display: 'inline-block',
        whiteSpace: 'nowrap',
      }}
    >
      {c.label}
    </span>
  );
}

interface ScoreBadgeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
}

export function ScoreBadge({ score, size = 'md' }: ScoreBadgeProps) {
  const isHigh = score >= 70;
  const isMid = score >= 30 && score < 70;

  const bg = isHigh ? 'var(--danger-subtle)' : isMid ? 'var(--warning-subtle)' : 'var(--safe-subtle)';
  const text = isHigh ? 'var(--text-danger)' : isMid ? 'var(--text-warning)' : 'var(--text-safe)';
  const glow = isHigh
    ? '0 0 12px rgba(239,68,68,0.4)'
    : isMid
    ? '0 0 12px rgba(245,158,11,0.4)'
    : '0 0 12px rgba(16,185,129,0.3)';

  const fontSizes = { sm: '0.75rem', md: '0.875rem', lg: '1.1rem' };
  const paddings = { sm: '2px 8px', md: '3px 10px', lg: '4px 12px' };

  return (
    <span
      className="font-mono"
      style={{
        background: bg,
        color: text,
        boxShadow: glow,
        padding: paddings[size],
        fontSize: fontSizes[size],
        fontWeight: 700,
        borderRadius: '4px',
        display: 'inline-block',
      }}
    >
      {score.toFixed(1)}
    </span>
  );
}

interface StatusDotProps {
  status: 'online' | 'offline' | 'warning';
  pulse?: boolean;
}

export function StatusDot({ status, pulse = false }: StatusDotProps) {
  const colors = {
    online: '#10B981',
    offline: '#EF4444',
    warning: '#F59E0B',
  };

  return (
    <span
      style={{
        display: 'inline-block',
        width: 8,
        height: 8,
        borderRadius: '50%',
        backgroundColor: colors[status],
        boxShadow: `0 0 6px ${colors[status]}`,
        animation: pulse ? 'glow-pulse 2s ease-in-out infinite' : undefined,
        flexShrink: 0,
      }}
    />
  );
}
