interface ScoreGaugeProps {
  score: number;  // 0–100
  size?: number;
}

const ScoreGauge = ({ score, size = 160 }: ScoreGaugeProps) => {
  const cx = size / 2;
  const cy = size / 2;
  const radius = size / 2 - 16;

  const circumference = 2 * Math.PI * radius;
  const halfCircum = circumference / 2;
  const filled = (score / 100) * halfCircum;

  const color = score >= 70 ? 'var(--danger)' : score >= 30 ? 'var(--warning)' : 'var(--safe)';
  const label = score >= 70 ? 'HIGH RISK' : score >= 30 ? 'MEDIUM RISK' : 'CLEAN';
  const labelColor = score >= 70 ? 'var(--text-danger)' : score >= 30 ? 'var(--text-warning)' : 'var(--text-safe)';
  const labelBg = score >= 70 ? 'var(--danger-subtle)' : score >= 30 ? 'var(--warning-subtle)' : 'var(--safe-subtle)';
  const labelBorder = score >= 70 ? 'var(--danger-border)' : score >= 30 ? 'var(--warning-border)' : 'var(--safe-border)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg
        width={size}
        height={size * 0.6}
        viewBox={`0 0 ${size} ${size}`}
        style={{ overflow: 'visible' }}
        role="img"
        aria-label={`Risk score ${Math.round(score)} out of 100 — ${label.toLowerCase()}`}
      >
        <circle
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          stroke="var(--border-default)"
          strokeWidth={11}
          strokeDasharray={`${halfCircum} ${circumference - halfCircum}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform={`rotate(180 ${cx} ${cy})`}
        />
        <circle
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={11}
          strokeDasharray={`${filled} ${circumference - filled}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform={`rotate(180 ${cx} ${cy})`}
          style={{ transition: 'stroke-dasharray 0.9s cubic-bezier(0.22,1,0.36,1)' }}
        />
        <text
          x={cx}
          y={cy + 8}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="var(--text-primary)"
          fontSize={size * 0.22}
          fontWeight="700"
          fontFamily="'JetBrains Mono', monospace"
        >
          {Math.round(score)}
        </text>
      </svg>

      <span
        style={{
          fontSize: '10px',
          fontWeight: 700,
          letterSpacing: '0.08em',
          color: labelColor,
          backgroundColor: labelBg,
          border: `1px solid ${labelBorder}`,
          padding: '2px 9px',
          borderRadius: 999,
          marginTop: '4px',
        }}
      >
        {label}
      </span>
    </div>
  );
};

export default ScoreGauge;
export { ScoreGauge };
