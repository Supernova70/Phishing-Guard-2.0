interface ScoreGaugeProps {
  score: number;  // 0–100
  size?: number;
}

const ScoreGauge = ({ score, size = 160 }: ScoreGaugeProps) => {
  const cx = size / 2;
  const cy = size / 2;
  const radius = size / 2 - 16; // 16px padding from edge

  // Circumference of the full circle
  const circumference = 2 * Math.PI * radius;
  // Half = semicircle arc length
  const halfCircum = circumference / 2;

  // How much of the semicircle is filled based on score
  const filled = (score / 100) * halfCircum;

  // Color based on score
  const color = score >= 70 ? '#EF4444' : score >= 30 ? '#F59E0B' : '#10B981';
  const label = score >= 70 ? 'HIGH RISK' : score >= 30 ? 'MEDIUM RISK' : 'CLEAN';
  const labelColor = score >= 70 ? '#FCA5A5' : score >= 30 ? '#FCD34D' : '#6EE7B7';
  const labelBg = score >= 70 ? '#EF444420' : score >= 30 ? '#F59E0B20' : '#10B98120';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      {/* SVG height = size*0.6 clips at the equator, showing only top semicircle */}
      <svg
        width={size}
        height={size * 0.6}
        viewBox={`0 0 ${size} ${size}`}
        style={{ overflow: 'visible' }}
      >
        {/* Background track — full semicircle in muted color */}
        <circle
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          stroke="#1E2736"
          strokeWidth={12}
          strokeDasharray={`${halfCircum} ${circumference - halfCircum}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform={`rotate(180 ${cx} ${cy})`}
        />

        {/* Filled arc — proportional to score */}
        <circle
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={12}
          strokeDasharray={`${filled} ${circumference - filled}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform={`rotate(180 ${cx} ${cy})`}
          style={{
            transition: 'stroke-dasharray 1s ease-out',
            filter: `drop-shadow(0 0 6px ${color}80)`,
          }}
        />

        {/* Score number in center */}
        <text
          x={cx}
          y={cy + 8}
          textAnchor="middle"
          dominantBaseline="middle"
          fill={color}
          fontSize={size * 0.22}
          fontWeight="700"
          fontFamily="'JetBrains Mono', monospace"
        >
          {Math.round(score)}
        </text>
      </svg>

      {/* Risk label below gauge */}
      <span
        style={{
          fontSize: '11px',
          fontWeight: '600',
          letterSpacing: '0.08em',
          color: labelColor,
          backgroundColor: labelBg,
          padding: '2px 10px',
          borderRadius: '4px',
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
