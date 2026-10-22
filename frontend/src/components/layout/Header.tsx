import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

import { RefreshCw, AlertTriangle, Clock, LogOut, Search, Loader2, Mail, ShieldCheck, Fingerprint } from 'lucide-react';
import { format } from 'date-fns';
import { fetchEmails } from '../../api/client';
import { globalSearch, type SearchResult } from '../../api/forensics';
import { useAuth } from '../../auth/AuthContext';
import { AlertBell } from './AlertBell';

interface HeaderProps {
  title: string;
  breadcrumbs?: Array<{ label: string; to?: string }>;
  threatCount?: number;
  onEmailsFetched?: () => void;
  toast?: (title: string, msg?: string) => void;
  toastError?: (title: string, msg?: string) => void;
}

export function Header({
  title,
  breadcrumbs = [],
  threatCount = 0,
  onEmailsFetched,
  toast,
  toastError,
}: HeaderProps) {
  const [time, setTime] = useState(() => format(new Date(), 'HH:mm:ss'));
  const [fetching, setFetching] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  // ── Global search (header palette) ────────────────────────
  const searchRef = useRef<HTMLInputElement>(null);
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
      if (event.key === 'Escape' && document.activeElement === searchRef.current) {
        setSearchOpen(false);
        searchRef.current?.blur();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const openResult = (row: SearchResult) => {
    setSearchOpen(false);
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

  return (
    <header className="app-header no-print" style={{
      height: 56,
      background: 'var(--bg-panel)',
      borderBottom: '1px solid var(--border-default)',
      display: 'flex',
      alignItems: 'center',
      padding: '0 20px',
      gap: 16,
      position: 'relative',
      // Above <main>: page panels use transforms (framer-motion) which
      // create z-index:0 stacking contexts that would otherwise paint
      // over the header's dropdowns (alert bell).
      zIndex: 10,
      flexShrink: 0,
    }}>
      {/* Scanline animation — clipped to the header box by its own
          wrapper so the header itself can keep overflow: visible */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          overflow: 'hidden',
          pointerEvents: 'none',
          zIndex: 0,
        }}
      >
        <div
          className="animate-scanline"
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: 60,
            height: '100%',
            background: 'linear-gradient(90deg, transparent, rgba(59,130,246,0.06), transparent)',
          }}
        />
      </div>

      {/* Title + Breadcrumb */}
      <div style={{ flex: 1, zIndex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {breadcrumbs.map((crumb, i) => (
            <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{crumb.label}</span>
              {i < breadcrumbs.length - 1 && <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>/</span>}
            </span>
          ))}
        </div>
        <h1 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
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
            padding: '5px 10px',
            borderRadius: 6,
            border: `1px solid ${searchOpen ? 'var(--primary)' : 'var(--border-default)'}`,
            background: 'var(--bg-input)',
          }}
        >
          {searching ? (
            <Loader2 size={13} style={{ color: 'var(--primary)', flexShrink: 0, animation: 'spin 1s linear infinite' }} />
          ) : (
            <Search size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
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
              fontSize: '0.6rem',
              color: 'var(--text-muted)',
              border: '1px solid var(--border-default)',
              borderRadius: 3,
              padding: '0 4px',
              flexShrink: 0,
            }}
          >
            ⌘K
          </kbd>
        </div>

        {searchOpen && (
          <div
            style={{
              position: 'absolute',
              top: 'calc(100% + 6px)',
              left: 0,
              width: 440,
              maxHeight: 430,
              overflowY: 'auto',
              background: 'var(--bg-panel)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              boxShadow: '0 16px 40px rgba(0,0,0,0.45)',
              padding: '6px 0',
            }}
          >
            {results.length === 0 && !searching ? (
              <p style={{ padding: '12px 14px', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                No matches for “{query.trim()}”.
              </p>
            ) : (
              searchGroups.map((group) => {
                const rows = results.filter((row) => row.type === group.type);
                if (rows.length === 0) return null;
                return (
                  <div key={group.type}>
                    <p
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 5,
                        padding: '7px 14px 4px',
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
                          padding: '7px 14px',
                          background: 'transparent',
                          border: 'none',
                          cursor: 'pointer',
                          textAlign: 'left',
                        }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--bg-input)'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                      >
                        <span style={{ flex: 1, minWidth: 0 }}>
                          <span
                            style={{
                              display: 'block',
                              fontSize: '0.76rem',
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
                                ? 'var(--danger)'
                                : row.classification === 'suspicious'
                                  ? 'var(--warning)'
                                  : 'var(--safe)',
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
              })
            )}
          </div>
        )}
      </div>

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, zIndex: 1 }}>
        {/* Threat Counter */}
        {threatCount > 0 && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            background: 'var(--danger-subtle)',
            border: '1px solid var(--danger)',
            borderRadius: 6,
            padding: '4px 10px',
          }}>
            <AlertTriangle size={13} style={{ color: 'var(--danger)' }} />
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-danger)' }}>
              {threatCount} threat{threatCount !== 1 ? 's' : ''} detected
            </span>
          </div>
        )}

        {/* Alert feed bell */}
        <AlertBell />

        {/* Fetch Button */}
        <button className="btn-primary" onClick={handleFetch} disabled={fetching} style={{ fontSize: '0.8rem', padding: '6px 14px' }}>
          <RefreshCw
            size={14}
            style={{ animation: fetching ? 'spin 1s linear infinite' : 'none' }}
          />
          {fetching ? 'Fetching...' : 'Fetch Emails'}
        </button>

        {/* Clock */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: 'var(--text-muted)' }}>
          <Clock size={13} />
          <span className="font-mono" style={{ fontSize: '0.8rem' }}>{time}</span>
        </div>

        {/* Account avatar + menu */}
        {user && (
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setMenuOpen((o) => !o)}
              aria-label="Account menu"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                background: menuOpen ? 'var(--bg-hover, rgba(255,255,255,0.06))' : 'transparent',
                border: '1px solid var(--border-default)',
                borderRadius: 20,
                padding: '3px 10px 3px 3px',
                cursor: 'pointer',
              }}
            >
              {user.picture ? (
                <img
                  src={user.picture}
                  alt=""
                  width={22}
                  height={22}
                  style={{ borderRadius: '50%', display: 'block' }}
                />
              ) : (
                <span
                  style={{
                    width: 22,
                    height: 22,
                    borderRadius: '50%',
                    background: 'rgba(59,130,246,0.25)',
                    color: '#93c5fd',
                    fontSize: '0.68rem',
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  {(user.name || user.email).slice(0, 1).toUpperCase()}
                </span>
              )}
              <span style={{ fontSize: '0.78rem', color: 'var(--text-primary)', maxWidth: 110, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
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
                  style={{
                    position: 'absolute',
                    right: 0,
                    top: 'calc(100% + 8px)',
                    width: 240,
                    background: 'var(--bg-card, #111827)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 10,
                    boxShadow: '0 12px 32px rgba(0,0,0,0.45)',
                    padding: 12,
                    zIndex: 31,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                  }}
                >
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                    {user.name || user.email}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                    {user.email}
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    <span style={{
                      fontSize: '0.66rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em',
                      padding: '2px 7px', borderRadius: 5,
                      background: user.role === 'admin' ? 'rgba(168,85,247,0.15)' : 'rgba(59,130,246,0.12)',
                      color: user.role === 'admin' ? '#d8b4fe' : '#93c5fd',
                      border: `1px solid ${user.role === 'admin' ? 'rgba(168,85,247,0.4)' : 'rgba(59,130,246,0.35)'}`,
                    }}>
                      {user.role}
                    </span>
                    <span style={{
                      fontSize: '0.66rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em',
                      padding: '2px 7px', borderRadius: 5,
                      background: user.gmail_connected ? 'rgba(16,185,129,0.12)' : 'rgba(245,158,11,0.12)',
                      color: user.gmail_connected ? '#6ee7b7' : '#fcd34d',
                      border: `1px solid ${user.gmail_connected ? 'rgba(16,185,129,0.35)' : 'rgba(245,158,11,0.35)'}`,
                    }}>
                      {user.gmail_connected ? 'gmail linked' : 'gmail pending'}
                    </span>
                  </div>
                  <div style={{ borderTop: '1px solid var(--border-default)', paddingTop: 8 }}>
                    <button
                      onClick={() => {
                        setMenuOpen(false);
                        void logout();
                      }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                        background: 'transparent', border: 'none', borderRadius: 6,
                        padding: '7px 8px', cursor: 'pointer', color: '#fca5a5',
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
  );
}
