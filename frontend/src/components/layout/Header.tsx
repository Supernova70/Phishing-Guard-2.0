import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

import { RefreshCw, AlertTriangle, Clock, LogOut, Search, Loader2, Mail, ShieldCheck, Fingerprint, Menu, X } from 'lucide-react';
import { format } from 'date-fns';
import { fetchEmails } from '../../api/client';
import { globalSearch, type SearchResult } from '../../api/forensics';
import { useAuth } from '../../auth/AuthContext';
import { AlertBell } from './AlertBell';
import { ThemeToggle, ThemeToggleRow } from '../ui/ThemeToggle';

interface HeaderProps {
  title: string;
  breadcrumbs?: Array<{ label: string; to?: string }>;
  threatCount?: number;
  onEmailsFetched?: () => void;
  toast?: (title: string, msg?: string) => void;
  toastError?: (title: string, msg?: string) => void;
  onOpenMenu?: () => void;
}

export function Header({
  title,
  breadcrumbs = [],
  threatCount = 0,
  onEmailsFetched,
  toast,
  toastError,
  onOpenMenu,
}: HeaderProps) {
  const [time, setTime] = useState(() => format(new Date(), 'HH:mm:ss'));
  const [fetching, setFetching] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [mobileSearch, setMobileSearch] = useState(false);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  // ── Global search (header palette) ────────────────────────
  const searchRef = useRef<HTMLInputElement>(null);
  const mobileSearchRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => {
    const term = query.trim();
    if (!term) {
      setResults([]);
      setSearching(false);
      return;
    }
    let cancelled = false;
    setSearching(true);
    const timer = setTimeout(() => {
      globalSearch(term)
        .then((rows) => {
          if (cancelled) return;
          setResults(rows);
          setSearchOpen(true);
        })
        .catch(() => { if (!cancelled) setResults([]); })
        .finally(() => { if (!cancelled) setSearching(false); });
    }, 220);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [query]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        searchRef.current?.focus();
        setSearchOpen(true);
      }
      if (event.key === 'Escape') {
        setSearchOpen(false);
        setMobileSearch(false);
        if (document.activeElement === searchRef.current) searchRef.current?.blur();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  useEffect(() => {
    if (mobileSearch) {
      const id = window.setTimeout(() => mobileSearchRef.current?.focus(), 60);
      return () => window.clearTimeout(id);
    }
  }, [mobileSearch]);

  const openResult = (row: SearchResult) => {
    setSearchOpen(false);
    setMobileSearch(false);
    setQuery('');
    setResults([]);
    navigate(row.url);
  };

  const searchGroups = [
    { type: 'scan' as const, label: 'Scans', icon: <ShieldCheck size={12} /> },
    { type: 'email' as const, label: 'Emails', icon: <Mail size={12} /> },
    { type: 'indicator' as const, label: 'Indicators', icon: <Fingerprint size={12} /> },
  ];

  useEffect(() => {
    const id = setInterval(() => setTime(format(new Date(), 'HH:mm:ss')), 1000);
    return () => clearInterval(id);
  }, []);

  const handleFetch = async () => {
    if (fetching) return;
    setFetching(true);
    try {
      const result = await fetchEmails(20);
      const fetched = result.new_emails ?? 0;
      toast?.(`Fetched ${fetched} new email${fetched !== 1 ? 's' : ''}`, `${result.total_fetched} total processed`);
      onEmailsFetched?.();
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      const msg = err instanceof Error && err.message === 'BACKEND_OFFLINE'
        ? 'Backend is offline'
        : detail || 'Failed to fetch emails';
      toastError?.(msg);
    } finally {
      setFetching(false);
    }
  };

  const renderSearchResults = () => {
    if (!query.trim()) {
      return (
        <p style={{ padding: '14px 15px', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
          Search across scans, emails and indicators.
        </p>
      );
    }
    if (results.length === 0 && !searching) {
      return (
        <p style={{ padding: '14px 15px', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
          No matches for “{query.trim()}”.
        </p>
      );
    }
    return searchGroups.map((group) => {
      const rows = results.filter((row) => row.type === group.type);
      if (rows.length === 0) return null;
      return (
        <div key={group.type}>
          <p
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              padding: '8px 15px 4px',
              fontSize: '0.6rem',
              fontWeight: 700,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
            }}
          >
            {group.icon}
            {group.label}
          </p>
          {rows.map((row) => (
            <button
              key={`${row.type}-${row.id}-${row.title}`}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => openResult(row)}
              style={{
                display: 'flex',
                width: '100%',
                alignItems: 'center',
                gap: 10,
                padding: '8px 15px',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                textAlign: 'left',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--bg-subtle)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
            >
              <span style={{ flex: 1, minWidth: 0 }}>
                <span
                  style={{
                    display: 'block',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    color: 'var(--text-primary)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {row.title}
                </span>
                <span
                  style={{
                    display: 'block',
                    fontSize: '0.66rem',
                    color: 'var(--text-muted)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    marginTop: 1,
                  }}
                >
                  {row.subtitle}
                </span>
              </span>
              {row.classification ? (
                <span
                  className="font-mono"
                  style={{
                    fontSize: '0.64rem',
                    fontWeight: 700,
                    flexShrink: 0,
                    textTransform: 'capitalize',
                    color: row.classification === 'dangerous'
                      ? 'var(--text-danger)'
                      : row.classification === 'suspicious'
                        ? 'var(--text-warning)'
                        : 'var(--text-safe)',
                  }}
                >
                  {row.score ?? row.classification}
                </span>
              ) : row.kind ? (
                <span style={{ fontSize: '0.62rem', color: 'var(--text-muted)', flexShrink: 0 }}>
                  {row.kind}
                </span>
              ) : null}
            </button>
          ))}
        </div>
      );
    });
  };

  return (
    <>
      <header
        className="app-header no-print"
        style={{
          height: 64,
          background: 'var(--header-bg)',
          borderBottom: '1px solid var(--border-default)',
          display: 'flex',
          alignItems: 'center',
          padding: '0 20px',
          gap: 14,
          position: 'relative',
          zIndex: 40,
          flexShrink: 0,
          backdropFilter: 'blur(18px) saturate(165%)',
          WebkitBackdropFilter: 'blur(18px) saturate(165%)',
          boxShadow: '0 1px 0 rgba(15,23,42,0.02)',
        }}
      >
        <button
          type="button"
          className="btn-icon mobile-menu-btn"
          onClick={onOpenMenu}
          aria-label="Open navigation"
          style={{ flexShrink: 0 }}
        >
          <Menu size={17} />
        </button>

        {/* Title + Breadcrumb */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="hide-mobile" style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 2 }}>
            {breadcrumbs.map((crumb, i) => (
              <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-faint)', fontWeight: 500 }}>{crumb.label}</span>
                {i < breadcrumbs.length - 1 && <span style={{ color: 'var(--border-emphasis)', fontSize: '0.62rem' }}>/</span>}
              </span>
            ))}
          </div>
          <h1 className="header-page-title" style={{ fontSize: '1.06rem', fontWeight: 680, color: 'var(--text-primary)', lineHeight: 1.2, letterSpacing: '-0.02em', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {title}
          </h1>
        </div>

        {/* Global search palette */}
        <div className="global-search" style={{ position: 'relative', zIndex: 3 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              padding: '6px 10px',
              borderRadius: 9,
              border: `1px solid ${searchOpen ? 'var(--primary)' : 'var(--border-default)'}`,
              background: 'var(--search-bg)',
              boxShadow: searchOpen ? '0 0 0 3px var(--primary-ring)' : 'inset 0 1px 2px rgba(15,23,42,0.03)',
              transition: 'border-color 140ms ease, box-shadow 140ms ease',
            }}
          >
            {searching ? (
              <Loader2 size={13} style={{ color: 'var(--primary)', flexShrink: 0, animation: 'spin 1s linear infinite' }} />
            ) : (
              <Search size={13} style={{ color: 'var(--text-faint)', flexShrink: 0 }} />
            )}
            <input
              ref={searchRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onFocus={() => { if (query.trim()) setSearchOpen(true); }}
              onBlur={() => setTimeout(() => setSearchOpen(false), 160)}
              placeholder="Search emails, scans, IOCs…"
              aria-label="Global search"
              style={{
                flex: 1,
                minWidth: 0,
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: 'var(--text-primary)',
                fontSize: '0.76rem',
                fontFamily: 'inherit',
              }}
            />
            <kbd
              className="font-mono"
              style={{
                fontSize: '0.59rem',
                color: 'var(--text-faint)',
                border: '1px solid var(--border-default)',
                background: 'var(--bg-card)',
                borderRadius: 4,
                padding: '1px 4px',
                flexShrink: 0,
              }}
            >
              ⌘K
            </kbd>
          </div>

          {searchOpen && (
            <div className="popover-surface" style={{ position: 'absolute', top: 'calc(100% + 7px)', left: 0, width: 440, maxHeight: 430, overflowY: 'auto', padding: '6px 0' }}>
              {renderSearchResults()}
            </div>
          )}
        </div>

        <button
          type="button"
          className="btn-icon header-search-mobile"
          onClick={() => setMobileSearch(true)}
          aria-label="Open search"
          style={{ flexShrink: 0 }}
        >
          <Search size={16} />
        </button>

        {/* Right Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, zIndex: 1, flexShrink: 0 }}>
          {threatCount > 0 && (
            <div
              className="hide-tablet"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                background: 'var(--danger-subtle)',
                border: '1px solid var(--danger-border)',
                borderRadius: 999,
                padding: '4px 10px',
              }}
            >
              <AlertTriangle size={13} style={{ color: 'var(--danger)' }} />
              <span style={{ fontSize: '0.74rem', fontWeight: 650, color: 'var(--text-danger)' }}>
                {threatCount} threat{threatCount !== 1 ? 's' : ''}
              </span>
            </div>
          )}

          <AlertBell />

          <ThemeToggle className="theme-toggle-header" />

          <button className="btn-primary" onClick={handleFetch} disabled={fetching} style={{ fontSize: '0.78rem', padding: '7px 12px' }}>
            <RefreshCw size={14} style={{ animation: fetching ? 'spin 1s linear infinite' : 'none' }} />
            <span className="hide-phone">{fetching ? 'Fetching…' : 'Fetch Emails'}</span>
          </button>

          <div className="hide-tablet" style={{ display: 'flex', alignItems: 'center', gap: 5, color: 'var(--text-muted)' }}>
            <Clock size={13} />
            <span className="font-mono" style={{ fontSize: '0.75rem' }}>{time}</span>
          </div>

          {user && (
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setMenuOpen((o) => !o)}
                aria-label="Account menu"
                aria-expanded={menuOpen}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  background: menuOpen ? 'var(--bg-card)' : 'transparent',
                  border: '1px solid var(--border-default)',
                  borderRadius: 999,
                  padding: '3px 9px 3px 3px',
                  cursor: 'pointer',
                  boxShadow: menuOpen ? 'var(--shadow-xs)' : 'none',
                  transition: 'background 140ms ease, box-shadow 140ms ease',
                }}
              >
                <span
                  style={{
                    position: 'relative',
                    width: 24,
                    height: 24,
                    borderRadius: '50%',
                    overflow: 'hidden',
                    background: 'var(--primary-soft)',
                    color: 'var(--primary)',
                    border: '1px solid var(--primary-border)',
                    fontSize: '0.68rem',
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}
                >
                  {(user.name || user.email).slice(0, 1).toUpperCase()}
                  {user.picture && (
                    <img
                      src={user.picture}
                      alt=""
                      width={24}
                      height={24}
                      onError={(e) => { e.currentTarget.style.display = 'none'; }}
                      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover', display: 'block' }}
                    />
                  )}
                </span>
                <span className="hide-mobile" style={{ fontSize: '0.76rem', color: 'var(--text-primary)', maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 550 }}>
                  {user.name || user.email.split('@')[0]}
                </span>
              </button>

              {menuOpen && (
                <>
                  <div
                    onClick={() => setMenuOpen(false)}
                    style={{ position: 'fixed', inset: 0, zIndex: 30 }}
                  />
                  <div
                    className="popover-surface"
                    style={{
                      position: 'absolute',
                      right: 0,
                      top: 'calc(100% + 8px)',
                      width: 250,
                      padding: 13,
                      zIndex: 31,
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 8,
                    }}
                  >
                    <div style={{ fontSize: '0.8rem', fontWeight: 650, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                      {user.name || user.email}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                      {user.email}
                    </div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <span className={user.role === 'admin' ? 'pill pill-primary' : 'pill pill-info'} style={{ textTransform: 'uppercase', letterSpacing: '0.04em', fontSize: '0.6rem' }}>
                        {user.role}
                      </span>
                      <span className={user.gmail_connected ? 'pill pill-safe' : 'pill pill-warning'} style={{ textTransform: 'uppercase', letterSpacing: '0.04em', fontSize: '0.6rem' }}>
                        {user.gmail_connected ? 'gmail linked' : 'gmail pending'}
                      </span>
                    </div>
                    <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
                      <ThemeToggleRow />
                      <button
                        onClick={() => {
                          setMenuOpen(false);
                          void logout();
                        }}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                          background: 'transparent', border: 'none', borderRadius: 7,
                          padding: '7px 8px', cursor: 'pointer', color: 'var(--text-danger)',
                          fontSize: '0.78rem', fontWeight: 600,
                        }}
                      >
                        <LogOut size={14} />
                        Sign out
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </header>

      {/* Mobile search overlay */}
      {mobileSearch && (
        <div className="no-print" style={{ position: 'fixed', inset: 0, zIndex: 80 }}>
          <div
            style={{ position: 'absolute', inset: 0, background: 'var(--overlay)', backdropFilter: 'blur(3px)' }}
            onClick={() => setMobileSearch(false)}
          />
          <div
            className="popover-surface"
            style={{ position: 'absolute', top: 12, left: 12, right: 12, maxHeight: 'calc(100vh - 24px)', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '11px 13px', borderBottom: '1px solid var(--border-subtle)' }}>
              <Search size={16} style={{ color: 'var(--text-faint)' }} />
              <input
                ref={mobileSearchRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search emails, scans, IOCs…"
                aria-label="Search"
                style={{ flex: 1, border: 0, outline: 0, background: 'transparent', fontSize: '0.9rem', color: 'var(--text-primary)' }}
              />
              <button type="button" className="btn-icon" onClick={() => setMobileSearch(false)} aria-label="Close search">
                <X size={15} />
              </button>
            </div>
            <div style={{ overflowY: 'auto', padding: '5px 0' }}>
              {renderSearchResults()}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
