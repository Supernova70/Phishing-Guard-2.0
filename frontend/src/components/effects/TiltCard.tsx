import { useCallback, useRef, useState, type CSSProperties, type PointerEvent, type ReactNode } from 'react';
import {
  motion,
  useMotionTemplate,
  useMotionValue,
  useReducedMotion,
  useSpring,
} from 'framer-motion';
import { useFinePointer } from '../../hooks/useFinePointer';

type TiltTag = 'div' | 'button';

export interface TiltCardProps {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
  /** Maximum rotation in degrees at the card edges. */
  intensity?: number;
  /** Draw the pointer-following light. */
  glow?: boolean;
  enabled?: boolean;
  as?: TiltTag;
  onClick?: () => void;
  type?: 'button' | 'submit';
  ariaLabel?: string;
  title?: string;
}

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

/**
 * Perspective tilt with spring return and a restrained pointer light.
 * Pointer movement only updates motion values — React never re-renders until
 * the pointer enters or leaves the surface.
 */
export function TiltCard({
  children,
  className = '',
  style,
  intensity = 6,
  glow = true,
  enabled = true,
  as = 'div',
  onClick,
  type = 'button',
  ariaLabel,
  title,
}: TiltCardProps) {
  const finePointer = useFinePointer();
  const reduceMotion = useReducedMotion();
  const active = enabled && finePointer && !reduceMotion;
  const cardRef = useRef<HTMLDivElement | null>(null);
  const [hovered, setHovered] = useState(false);

  const rotateX = useSpring(0, { stiffness: 260, damping: 26, mass: 0.6 });
  const rotateY = useSpring(0, { stiffness: 260, damping: 26, mass: 0.6 });
  const scale = useSpring(1, { stiffness: 320, damping: 28, mass: 0.5 });
  const glowX = useMotionValue(50);
  const glowY = useMotionValue(50);
  const glowOpacity = useSpring(0, { stiffness: 220, damping: 26, mass: 0.5 });

  const light = useMotionTemplate`radial-gradient(420px circle at ${glowX}% ${glowY}%, var(--tilt-highlight), transparent 58%), radial-gradient(520px circle at ${glowX}% ${glowY}%, var(--tilt-tint), transparent 64%)`;

  const reset = useCallback(() => {
    rotateX.set(0);
    rotateY.set(0);
    scale.set(1);
    glowOpacity.set(0);
    setHovered(false);
  }, [glowOpacity, rotateX, rotateY, scale]);

  const onPointerMove = useCallback(
    (event: PointerEvent<HTMLElement>) => {
      if (!active || event.pointerType === 'touch') return;
      const node = cardRef.current;
      if (!node) return;

      const rect = node.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return;

      const x = clamp((event.clientX - rect.left) / rect.width, 0, 1);
      const y = clamp((event.clientY - rect.top) / rect.height, 0, 1);

      rotateX.set((0.5 - y) * intensity * 2);
      rotateY.set((x - 0.5) * intensity * 2);
      glowX.set(x * 100);
      glowY.set(y * 100);
      scale.set(1.006);
      glowOpacity.set(1);
      if (!hovered) setHovered(true);
    },
    [active, glowOpacity, glowX, glowY, hovered, intensity, rotateX, rotateY, scale]
  );

  const onPointerLeave = useCallback(
    (event: PointerEvent<HTMLElement>) => {
      if (event.pointerType === 'touch') return;
      reset();
    },
    [reset]
  );

  const sharedProps = {
    className: `${className}${active ? ' tilt-card' : ''}${hovered ? ' is-active' : ''}`.trim(),
    style,
    onClick,
    onPointerMove,
    onPointerLeave,
    onPointerCancel: onPointerLeave,
    onBlur: reset,
    'data-cursor': active ? 'hover' : undefined,
    title,
    'aria-label': ariaLabel,
  } as const;

  if (!active) {
    if (as === 'button') {
      return (
        <button {...sharedProps} type={type}>
          {children}
        </button>
      );
    }
    return <div {...sharedProps}>{children}</div>;
  }

  return (
    <div className="tilt-card-frame" style={{ perspective: 1200 }}>
      {as === 'button' ? (
        <motion.button
          {...sharedProps}
          ref={cardRef as React.Ref<HTMLButtonElement>}
          type={type}
          style={{
            ...style,
            rotateX,
            rotateY,
            scale,
            transformStyle: 'preserve-3d',
            willChange: 'transform',
          }}
        >
          {children}
          {glow && (
            <motion.span
              className="tilt-glow"
              aria-hidden="true"
              style={{ background: light, opacity: glowOpacity }}
            />
          )}
        </motion.button>
      ) : (
        <motion.div
          {...sharedProps}
          ref={cardRef}
          style={{
            ...style,
            rotateX,
            rotateY,
            scale,
            transformStyle: 'preserve-3d',
            willChange: 'transform',
          }}
        >
          {children}
          {glow && (
            <motion.span
              className="tilt-glow"
              aria-hidden="true"
              style={{ background: light, opacity: glowOpacity }}
            />
          )}
        </motion.div>
      )}
    </div>
  );
}
