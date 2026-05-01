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
          background: 'var(--bg-input)',
          borderRadius: 3,
          overflow: 'hidden',
        }}
      >
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${Math.min(score, 100)}%` }}
          transition={{ duration: 0.8, ease: [0.34, 1.56, 0.64, 1] }}
          style={{
            height: '100%',
            background: color,
            borderRadius: 3,
            boxShadow: score >= 70
              ? '0 0 8px rgba(239,68,68,0.5)'
              : score >= 30
              ? '0 0 8px rgba(245,158,11,0.4)'
              : '0 0 8px rgba(16,185,129,0.3)',
          }}
        />
      </div>
    </div>
  );
}
