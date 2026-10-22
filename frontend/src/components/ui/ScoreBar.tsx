import { motion } from 'framer-motion';

interface ScoreBarProps {
  score: number;       // 0–100
  label?: string;
  showValue?: boolean;
  height?: number;
}

function getBarColor(score: number) {
  if (score >= 70) return 'var(--danger)';
  if (score >= 30) return 'var(--warning)';
  return 'var(--safe)';
}

export function ScoreBar({ score, label, showValue = true, height = 6 }: ScoreBarProps) {
  const color = getBarColor(score);

  return (
    <div style={{ width: '100%' }}>
      {(label || showValue) && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
          {label && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              {label}
            </span>
          )}
          {showValue && (
            <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
              {score.toFixed(1)}
            </span>
          )}
        </div>
      )}
      <div
        style={{
          width: '100%',
          height,
          background: 'var(--border-subtle)',
          borderRadius: 999,
          overflow: 'hidden',
          boxShadow: 'inset 0 1px 2px rgba(15,23,42,0.05)',
        }}
      >
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${Math.min(score, 100)}%` }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          style={{
            height: '100%',
            background: color,
            borderRadius: 999,
          }}
        />
      </div>
    </div>
  );
}
