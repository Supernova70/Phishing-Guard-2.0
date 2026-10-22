import type { Classification } from '../../types';

interface BadgeProps {
  classification: Classification;
  size?: 'sm' | 'md';
}

const config: Record<Classification, { label: string; bg: string; text: string; border: string; dot: string }> = {
  dangerous: {
    label: 'DANGEROUS',
    bg: 'var(--danger-subtle)',
    text: 'var(--text-danger)',
    border: 'var(--danger-border)',
    dot: 'var(--danger)',
  },
  suspicious: {
    label: 'SUSPICIOUS',
    bg: 'var(--warning-subtle)',
    text: 'var(--text-warning)',
    border: 'var(--warning-border)',
    dot: 'var(--warning)',
  },
  safe: {
    label: 'SAFE',
    bg: 'var(--safe-subtle)',
    text: 'var(--text-safe)',
    border: 'var(--safe-border)',
    dot: 'var(--safe)',
  },
};

export function ClassificationBadge({ classification, size = 'md' }: BadgeProps) {
  const c = config[classification];
  const padding = size === 'sm' ? '2px 8px' : '3px 9px';
  const fontSize = size === 'sm' ? '0.62rem' : '0.66rem';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        background: c.bg,
        color: c.text,
        border: `1px solid ${c.border}`,
        padding,
        fontSize,
        fontWeight: 700,
        letterSpacing: '0.06em',
        borderRadius: 'var(--radius-pill)',
        whiteSpace: 'nowrap',
        lineHeight: 1.35,
      }}
    >
      <span aria-hidden="true" style={{ width: 5, height: 5, borderRadius: '50%', background: c.dot, flexShrink: 0 }} />
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
  const border = isHigh ? 'var(--danger-border)' : isMid ? 'var(--warning-border)' : 'var(--safe-border)';

  const fontSizes = { sm: '0.72rem', md: '0.84rem', lg: '1.08rem' };
  const paddings = { sm: '2px 7px', md: '3px 9px', lg: '4px 11px' };

  return (
    <span
      className="font-mono"
      style={{
        background: bg,
        color: text,
        border: `1px solid ${border}`,
        padding: paddings[size],
        fontSize: fontSizes[size],
        fontWeight: 700,
        borderRadius: 'var(--radius-pill)',
        display: 'inline-block',
        lineHeight: 1.35,
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
    online: 'var(--safe)',
    offline: 'var(--danger)',
    warning: 'var(--warning)',
  };

  return (
    <span
      style={{
        display: 'inline-block',
        width: 7,
        height: 7,
        borderRadius: '50%',
        backgroundColor: colors[status],
        color: colors[status],
        boxShadow: '0 0 0 3px color-mix(in srgb, currentColor 12%, transparent)',
        animation: pulse ? 'glow-pulse 2.4s ease-in-out infinite' : undefined,
        flexShrink: 0,
      }}
    />
  );
}
