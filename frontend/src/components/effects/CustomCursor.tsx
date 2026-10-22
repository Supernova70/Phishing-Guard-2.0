import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { motion, useMotionValue, useReducedMotion, useSpring } from 'framer-motion';
import { useFinePointer } from '../../hooks/useFinePointer';

const INTERACTIVE_SELECTOR =
  'a, button, [role="button"], [role="link"], [role="tab"], [role="menuitem"], [data-cursor="hover"]';

const NATIVE_CURSOR_SELECTOR =
  'input, textarea, select, [contenteditable="true"], [data-native-cursor]';

/**
 * A dot + trailing ring cursor inspired by the reference site, rebuilt for a
 * light operations console. The native cursor is hidden only while this is
 * active; text fields, selects and other native-cursor surfaces keep theirs.
 */
export function CustomCursor() {
  const finePointer = useFinePointer();
  const reduceMotion = useReducedMotion();
  const enabled = finePointer && !reduceMotion;

  const dotX = useMotionValue(-100);
  const dotY = useMotionValue(-100);
  const ringX = useSpring(dotX, { stiffness: 360, damping: 32, mass: 0.55 });
  const ringY = useSpring(dotY, { stiffness: 360, damping: 32, mass: 0.55 });

  const [hovering, setHovering] = useState(false);
  const [pressed, setPressed] = useState(false);
  const interactiveRef = useRef(false);
  const layerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const root = document.documentElement;
    if (!enabled) {
      root.classList.remove('has-custom-cursor');
      return;
    }

    root.classList.add('has-custom-cursor');
    return () => root.classList.remove('has-custom-cursor');
  }, [enabled]);

  useEffect(() => {
    if (!enabled) return;

    let frame = 0;
    let nextX = -100;
    let nextY = -100;

    const paint = () => {
      frame = 0;
      dotX.set(nextX);
      dotY.set(nextY);
    };

    const onPointerMove = (event: PointerEvent) => {
      if (event.pointerType === 'touch') return;

      const layer = layerRef.current;
      if (!layer) return;

      const target = event.target instanceof Element ? event.target : null;
      const nativeCursor = Boolean(target?.closest(NATIVE_CURSOR_SELECTOR));
      // Class-based visibility avoids a React re-render on every pointer move
      // and keeps native-cursor fields reliable even if hover state changes.
      layer.classList.toggle('is-native', nativeCursor);
      if (nativeCursor) {
        layer.classList.remove('is-visible');
        return;
      }

      layer.classList.add('is-visible');
      nextX = event.clientX;
      nextY = event.clientY;

      const interactive = Boolean(target?.closest(INTERACTIVE_SELECTOR));
      if (interactive !== interactiveRef.current) {
        interactiveRef.current = interactive;
        setHovering(interactive);
      }

      if (!frame) frame = window.requestAnimationFrame(paint);
    };

    const onPointerDown = (event: PointerEvent) => {
      if (event.pointerType === 'touch') return;
      setPressed(true);
    };

    const onPointerUp = () => setPressed(false);

    // `pointerenter` fires for every descendant an element enters, including
    // when moving into a text field. Use `pointerout` + relatedTarget only to
    // detect leaving the document, so native-cursor fields stay hidden.
    const onPointerOut = (event: PointerEvent) => {
      if (event.relatedTarget === null) layerRef.current?.classList.remove('is-visible');
    };

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('pointerdown', onPointerDown, { passive: true });
    window.addEventListener('pointerup', onPointerUp, { passive: true });
    window.addEventListener('pointercancel', onPointerUp, { passive: true });
    window.addEventListener('pointerout', onPointerOut, { passive: true });

    return () => {
      if (frame) window.cancelAnimationFrame(frame);
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('pointerup', onPointerUp);
      window.removeEventListener('pointercancel', onPointerUp);
      window.removeEventListener('pointerout', onPointerOut);
    };
  }, [dotX, dotY, enabled]);

  const hide = useCallback(() => layerRef.current?.classList.remove('is-visible'), []);

  useEffect(() => {
    if (!enabled) return;
    window.addEventListener('blur', hide);
    return () => window.removeEventListener('blur', hide);
  }, [enabled, hide]);

  if (!enabled) return null;

  return createPortal(
    <div ref={layerRef} className="custom-cursor-layer" aria-hidden="true">
      <motion.div
        className="custom-cursor-ring-wrap"
        style={{ x: ringX, y: ringY }}
      >
        <motion.span
          className="custom-cursor-ring"
          animate={{
            scale: pressed ? 0.78 : hovering ? 1.55 : 1,
          }}
          transition={{ type: 'spring', stiffness: 420, damping: 28, mass: 0.5 }}
        />
      </motion.div>

      <motion.div
        className="custom-cursor-dot-wrap"
        style={{ x: dotX, y: dotY }}
      >
        <motion.span
          className="custom-cursor-dot"
          animate={{ scale: pressed ? 0.8 : hovering ? 0.6 : 1 }}
          transition={{ type: 'spring', stiffness: 500, damping: 30, mass: 0.4 }}
        />
      </motion.div>
    </div>,
    document.body
  );
}
