import type { ButtonHTMLAttributes, CSSProperties, HTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';
import { Loader2 } from 'lucide-react';

type Tone = 'neutral' | 'primary' | 'danger' | 'warning' | 'safe';

const toneStyles: Record<Tone, { color: string; background: string; border: string }> = {
  neutral: { color: 'var(--text-secondary)', background: 'var(--bg-subtle)', border: 'var(--border-default)' },
  primary: { color: 'var(--primary)', background: 'var(--primary-soft)', border: 'var(--primary-border)' },
  danger: { color: 'var(--text-danger)', background: 'var(--danger-subtle)', border: 'var(--danger-border)' },
  warning: { color: 'var(--text-warning)', background: 'var(--warning-subtle)', border: 'var(--warning-border)' },
  safe: { color: 'var(--text-safe)', background: 'var(--safe-subtle)', border: 'var(--safe-border)' },
};

export function Card({ className = '', children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={`surface ${className}`} {...rest}>
      {children}
    </div>
  );
}

export function SectionHeader({
  title,
  description,
  action,
  eyebrow,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  eyebrow?: string;
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 14 }}>
      <div style={{ minWidth: 0 }}>
        {eyebrow && <p className="section-label" style={{ marginBottom: 4 }}>{eyebrow}</p>}
        <h2 style={{ fontSize: '0.98rem', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>{title}</h2>
        {description && <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 3 }}>{description}</p>}
      </div>
      {action && <div style={{ flexShrink: 0 }}>{action}</div>}
    </div>
  );
}

export function StatTile({
  label,
  value,
  detail,
  icon,
  tone = 'primary',
  onClick,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  icon?: ReactNode;
  tone?: Tone;
  onClick?: () => void;
}) {
  const t = toneStyles[tone];
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag
      onClick={onClick}
      className="metric-tile"
      style={{
        textAlign: 'left',
        padding: '17px 18px',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        border: '1px solid var(--surface-border)',
        cursor: onClick ? 'pointer' : 'default',
        width: '100%',
        minWidth: 0,
        fontFamily: 'inherit',
      }}
      {...(onClick ? { type: 'button' as const } : {})}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, position: 'relative', zIndex: 1 }}>
        <span className="section-label" style={{ fontSize: '0.64rem' }}>{label}</span>
        {icon && (
          <span
            aria-hidden="true"
            style={{
              width: 30,
              height: 30,
              borderRadius: 9,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: t.color,
              background: t.background,
              border: `1px solid ${t.border}`,
            }}
          >
            {icon}
          </span>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, position: 'relative', zIndex: 1 }}>
        <span className="font-mono" style={{ fontSize: '1.65rem', lineHeight: 1, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.04em' }}>
          {value}
        </span>
        {detail && <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{detail}</span>}
      </div>
    </Tag>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  compact = false,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        gap: 9,
        padding: compact ? '26px 18px' : '46px 24px',
        color: 'var(--text-muted)',
      }}
    >
      {icon && (
        <span style={{ width: 42, height: 42, borderRadius: 12, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-input)', color: 'var(--text-muted)', border: '1px solid var(--border-subtle)' }}>
          {icon}
        </span>
      )}
      <p style={{ fontSize: '0.86rem', fontWeight: 650, color: 'var(--text-primary)' }}>{title}</p>
      {description && <p style={{ fontSize: '0.78rem', maxWidth: 360, lineHeight: 1.55 }}>{description}</p>}
      {action && <div style={{ marginTop: 5 }}>{action}</div>}
    </div>
  );
}

export function Button({
  variant = 'primary',
  size = 'md',
  loading = false,
  icon,
  children,
  className = '',
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md';
  loading?: boolean;
  icon?: ReactNode;
}) {
  const cls = variant === 'primary' ? 'btn-primary' : variant === 'danger' ? 'btn-danger' : variant === 'ghost' ? 'btn-ghost' : 'btn-secondary';
  return (
    <button
      className={`${cls} ${size === 'sm' ? 'btn-sm' : ''} ${className}`}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : icon}
      {children}
    </button>
  );
}

export function SearchField({
  icon,
  className = '',
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { icon?: ReactNode }) {
  return (
    <div
      className={className}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '0 10px',
        background: 'var(--input-bg)',
        border: '1px solid var(--border-default)',
        borderRadius: 'var(--radius-sm)',
        boxShadow: 'var(--shadow-xs)',
        minWidth: 0,
      }}
    >
      {icon && <span style={{ color: 'var(--text-faint)', display: 'flex', flexShrink: 0 }}>{icon}</span>}
      <input
        {...rest}
        className="input"
        style={{
          border: 0,
          boxShadow: 'none',
          padding: '9px 0',
          background: 'transparent',
          flex: 1,
          minWidth: 0,
          ...rest.style,
        }}
      />
    </div>
  );
}

export function Skeleton({ width = '100%', height = 14, radius = 4, style }: { width?: number | string; height?: number | string; radius?: number; style?: CSSProperties }) {
  return <div className="skeleton" style={{ width, height, borderRadius: radius, ...style }} />;
}
