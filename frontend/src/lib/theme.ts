import { useCallback, useEffect, useState } from 'react';

export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'pg-theme';
const THEME_EVENT = 'pg-theme-change';

function normalize(value: string | null | undefined): Theme | null {
  return value === 'light' || value === 'dark' ? value : null;
}

export function getStoredTheme(): Theme | null {
  try {
    return normalize(localStorage.getItem(STORAGE_KEY));
  } catch {
    return null;
  }
}

export function getTheme(): Theme {
  const fromDom = normalize(document.documentElement.dataset.theme);
  return fromDom ?? getStoredTheme() ?? 'light';
}

export function applyTheme(theme: Theme, persist = true): void {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;

  const meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (meta) meta.content = theme === 'dark' ? '#080e1a' : '#f3f6fb';

  if (persist) {
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      /* storage can be unavailable in private/locked-down contexts */
    }
  }

  window.dispatchEvent(new CustomEvent<Theme>(THEME_EVENT, { detail: theme }));
}

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(() => getTheme());

  useEffect(() => {
    const sync = () => setThemeState(getTheme());

    const onTheme = (event: Event) => {
      const next = normalize((event as CustomEvent<Theme>).detail);
      if (next) setThemeState(next);
    };

    const onStorage = (event: StorageEvent) => {
      if (event.key === STORAGE_KEY) sync();
    };

    window.addEventListener(THEME_EVENT, onTheme);
    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener(THEME_EVENT, onTheme);
      window.removeEventListener('storage', onStorage);
    };
  }, []);

  const setTheme = useCallback((next: Theme) => {
    applyTheme(next);
    setThemeState(next);
  }, []);

  const toggle = useCallback(() => {
    const next: Theme = getTheme() === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    setThemeState(next);
  }, []);

  return { theme, isDark: theme === 'dark', setTheme, toggle };
}
