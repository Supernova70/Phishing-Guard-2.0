import { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

interface ScoreGaugeProps {
  score: number;  // 0–100
  size?: number;
}

function getColor(score: number) {
  if (score >= 70) return '#EF4444';
  if (score >= 30) return '#F59E0B';
  return '#10B981';
}

export function ScoreGauge({ score, size = 120 }: ScoreGaugeProps) {
  const color = getColor(score);
  const strokeWidth = size * 0.08;
  const radius = (size - strokeWidth * 2) / 2;
  const cx = size / 2;
  const cy = size / 2;

  // Semicircle: starts at 180deg (left), sweeps 180deg (right)
  const startAngle = Math.PI;
  const endAngle = 0;

  // Full arc path (background)
  const startX = cx + radius * Math.cos(startAngle);
  const startY = cy + radius * Math.sin(startAngle);
  const endX = cx + radius * Math.cos(endAngle);
  const endY = cy + radius * Math.sin(endAngle);

  const arcPath = `M ${startX} ${startY} A ${radius} ${radius} 0 0 1 ${endX} ${endY}`;

  // Score arc: 0 maps to startAngle, 100 maps to endAngle
  const scoreRatio = Math.min(score, 100) / 100;
  const scoreAngle = startAngle + scoreRatio * (endAngle - startAngle);
  // When going left→right, angle decreases from Math.PI to 0
  const actualAngle = Math.PI - scoreRatio * Math.PI;
  const scoreEndX = cx + radius * Math.cos(actualAngle);
  const scoreEndY = cy + radius * Math.sin(actualAngle);

  const scorePath =
    scoreRatio === 0
      ? ''
      : `M ${startX} ${startY} A ${radius} ${radius} 0 ${scoreRatio > 0.5 ? 1 : 0} 1 ${scoreEndX} ${scoreEndY}`;

  return (
    <div style={{ position: 'relative', width: size, height: size * 0.6 }}>
      <svg width={size} height={size * 0.65} style={{ overflow: 'visible' }}>
        {/* Background arc */}
        <path
          d={arcPath}
          fill="none"
          stroke="var(--bg-input)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
        {/* Score arc */}
        {scorePath && (
          <motion.path
            d={scorePath}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 1 }}
            transition={{ duration: 1, ease: 'easeOut', delay: 0.2 }}
            style={{
              filter: `drop-shadow(0 0 6px ${color}80)`,
            }}
          />
        )}
        {/* Score text */}
        <text
          x={cx}
          y={cy + 4}
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize={size * 0.2}
          fontWeight="700"
          fontFamily="'JetBrains Mono', monospace"
          fill={color}
        >
          {score.toFixed(0)}
        </text>
      </svg>
    </div>
  );
}
