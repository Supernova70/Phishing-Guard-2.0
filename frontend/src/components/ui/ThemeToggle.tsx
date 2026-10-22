import { Moon, Sun } from 'lucide-react';
import { useTheme } from '../../lib/theme';

interface ThemeToggleProps {
  className?: string;
}

/** Compact icon-only toggle for headers and auth screens. */
export function ThemeToggle({ className = '' }: ThemeToggleProps) {
  const { isDark, toggle } = useTheme();
  const label = isDark ? 'Switch to light mode' : 'Switch to dark mode';

  return (
    <button
      type="button"
      className={`btn-icon theme-toggle ${className}`.trim()}
      onClick={toggle}
      aria-label={label}
      aria-pressed={isDark}
      title={label}
    >
      {isDark ? <Sun size={16} aria-hidden="true" /> : <Moon size={16} aria-hidden="true" />}
    </button>
  );
}

/** Full-width row with a visible switch for drawers and account menus. */
export function ThemeToggleRow({ className = '' }: ThemeToggleProps) {
  const { isDark, toggle } = useTheme();
  const label = isDark ? 'Switch to light mode' : 'Switch to dark mode';

  return (
    <button
      type="button"
      className={`theme-toggle-row ${className}`.trim()}
      onClick={toggle}
      aria-label={label}
      aria-pressed={isDark}
      title={label}
    >
      <span className="theme-toggle-row-icon" aria-hidden="true">
        {isDark ? <Sun size={14} /> : <Moon size={14} />}
      </span>
      <span className="theme-toggle-row-label">{isDark ? 'Dark mode' : 'Light mode'}</span>
      <span className={`theme-switch ${isDark ? 'is-on' : ''}`} aria-hidden="true">
        <span className="theme-switch-knob" />
      </span>
    </button>
  );
}
