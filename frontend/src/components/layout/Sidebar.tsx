import { NavLink, useLocation } from 'react-router-dom';

import {
  Shield,
  LayoutDashboard,
  Inbox,
  ScanLine,
  ShieldCheck,
  Link2,
  Paperclip,
  Settings,
  Activity,
  Share2,
  Megaphone,
  Bell,
  Users,
  FileCheck2,
  Crosshair,
  ShieldAlert,
  Radar,
  X,
} from 'lucide-react';
import { StatusDot } from '../ui/Badge';
import { ThemeToggleRow } from '../ui/ThemeToggle';
import type { HealthResponse } from '../../hooks/useSystemHealth';
import { useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/permissions';

interface NavItem {
  to: string;
  icon: React.ReactNode;
  label: string;
  badge?: number | string | null;
  badgeType?: 'count' | 'dot';
  dotStatus?: 'online' | 'offline' | 'warning';
}

interface NavSectionProps {
  title: string;
  items: NavItem[];
  currentPath: string;
  onNavigate?: () => void;
}

function NavSection({ title, items, currentPath, onNavigate }: NavSectionProps) {
  return (
    <div style={{ marginBottom: 16 }}>
      <p className="section-label" style={{ fontSize: '0.6rem', padding: '0 14px', marginBottom: 6 }}>
        {title}
      </p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {items.map((item) => {
          const isActive = currentPath === item.to || (item.to !== '/' && currentPath.startsWith(item.to));
          return (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={onNavigate}
              aria-current={isActive ? 'page' : undefined}
              className="sidebar-nav-link"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '8px 12px',
                margin: '0 8px',
                borderRadius: 9,
                cursor: 'pointer',
                position: 'relative',
                textDecoration: 'none',
                background: isActive ? 'var(--primary-soft)' : 'transparent',
                boxShadow: isActive ? 'inset 0 0 0 1px var(--primary-border)' : 'none',
                transition: 'background 140ms ease, box-shadow 140ms ease, color 140ms ease',
                color: isActive ? 'var(--primary-hover)' : 'var(--text-muted)',
              }}
            >
              <span
                aria-hidden="true"
                style={{
                  flexShrink: 0,
                  display: 'flex',
                  alignItems: 'center',
                  color: isActive ? 'var(--primary)' : 'var(--text-faint)',
                }}
              >
                {item.icon}
              </span>
              <span style={{ fontSize: '0.815rem', fontWeight: isActive ? 650 : 500, flex: 1, letterSpacing: '-0.005em' }}>
                {item.label}
              </span>
              {item.badge != null && item.badgeType === 'count' && (
                <span
                  style={{
                    background: isActive ? 'var(--primary)' : 'var(--danger)',
                    color: isActive ? 'var(--primary-contrast)' : 'white',
                    fontSize: '0.62rem',
                    fontWeight: 700,
                    padding: '1px 6px',
                    borderRadius: 999,
                    minWidth: 18,
                    textAlign: 'center',
                    lineHeight: 1.5,
                  }}
                >
                  {item.badge}
                </span>
              )}
              {item.badgeType === 'dot' && item.dotStatus && (
                <StatusDot status={item.dotStatus} pulse />
              )}
            </NavLink>
          );
        })}
      </div>
    </div>
  );
}

interface SidebarProps {
  unreadCount?: number;
  runningScans?: number;
  apiStatus?: 'online' | 'offline' | 'warning';
  health?: HealthResponse | null;
  open?: boolean;
  onClose?: () => void;
}

export function Sidebar({
  unreadCount = 0,
  runningScans = 0,
  apiStatus = 'online',
  health = null,
  open = false,
  onClose,
}: SidebarProps) {
  const location = useLocation();
  const { user } = useAuth();

  const monitorItems: NavItem[] = [
    { to: '/', icon: <LayoutDashboard size={15} />, label: 'Dashboard' },
    { to: '/emails', icon: <Inbox size={15} />, label: 'Email Inbox', badge: unreadCount || null, badgeType: 'count' },
    { to: '/active-scans', icon: <ScanLine size={15} />, label: 'Active Scans', badge: runningScans || null, badgeType: 'count' },
    { to: '/alerts', icon: <Bell size={15} />, label: 'Alerts' },
    { to: '/incidents', icon: <ShieldAlert size={15} />, label: 'Incident Response' },
  ];

  const analyzeItems: NavItem[] = [
    { to: '/scans', icon: <ShieldCheck size={15} />, label: 'Scan Results' },
    { to: '/graph', icon: <Share2 size={15} />, label: 'Attribution Graph' },
    { to: '/campaigns', icon: <Megaphone size={15} />, label: 'Campaigns' },
    { to: '/hunts', icon: <Crosshair size={15} />, label: 'Retroactive Hunts' },
    { to: '/detection', icon: <Radar size={15} />, label: 'Detection Coverage' },
    { to: '/url-analysis', icon: <Link2 size={15} />, label: 'URL Analysis' },
    { to: '/attachments', icon: <Paperclip size={15} />, label: 'Attachments' },
    { to: '/compliance', icon: <FileCheck2 size={15} />, label: 'Evidence & Audit' },
  ];

  // System section is RBAC-gated: each item appears only with its grant,
  // the section disappears entirely for users with no system capability.
  const systemItems: NavItem[] = [
    ...(can(user, 'system.settings')
      ? [{ to: '/settings', icon: <Settings size={15} />, label: 'Settings' }]
      : []),
    ...(can(user, 'system.health')
      ? [{ to: '/system-health', icon: <Activity size={15} />, label: 'API Health', badgeType: 'dot' as const, dotStatus: apiStatus }]
      : []),
    ...(can(user, 'users.manage')
      ? [{ to: '/users', icon: <Users size={15} />, label: 'User Management' }]
      : []),
  ];

  const showStatusPanel = can(user, 'system.health');

  const dbStatus = health?.components?.database?.status === 'connected' ? 'online' : health ? 'offline' : 'warning' as const;
  const mlStatus = health?.components?.ml_model?.status === 'loaded' ? 'online' : 'warning' as const;

  const statusItems = [
    {
      label: 'Database',
      dot: dbStatus,
      text: health?.components?.database?.status === 'connected' ? 'Connected' : health ? 'Error' : 'Unknown',
      textColor: health?.components?.database?.status === 'connected' ? 'var(--text-safe)' : 'var(--text-muted)',
    },
    {
      label: 'ML model',
      dot: mlStatus,
      text: health?.components?.ml_model?.status === 'loaded' ? 'Loaded' : health ? 'Not loaded' : 'Unknown',
      textColor: health?.components?.ml_model?.status === 'loaded' ? 'var(--text-safe)' : 'var(--text-muted)',
    },
  ];

  return (
    <aside
      className={`app-sidebar no-print ${open ? 'is-open' : ''}`}
      aria-label="Primary navigation"
      style={{
        width: 252,
        minWidth: 252,
        height: '100vh',
        background: 'var(--sidebar-bg)',
        borderRight: '1px solid var(--border-default)',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        backdropFilter: 'blur(18px) saturate(160%)',
        WebkitBackdropFilter: 'blur(18px) saturate(160%)',
      }}
    >
      {/* Brand */}
      <div
        style={{
          padding: '18px 16px 16px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
          <div
            style={{
              width: 34,
              height: 34,
              background: 'var(--brand-tile-bg)',
              border: '1px solid var(--brand-tile-border)',
              borderRadius: 10,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: 'var(--shadow-raised)',
              flexShrink: 0,
            }}
          >
            <Shield size={18} style={{ color: 'var(--primary)' }} />
          </div>
          <div style={{ minWidth: 0 }}>
            <p style={{ fontSize: '0.79rem', fontWeight: 750, letterSpacing: '-0.01em', color: 'var(--text-primary)', lineHeight: 1.25 }}>
              Phishing-Guard
            </p>
            <span
              className="font-mono"
              style={{
                fontSize: '0.58rem',
                color: 'var(--text-muted)',
                letterSpacing: '0.04em',
              }}
            >
              SOC CONSOLE · 2.0
            </span>
          </div>
        </div>
        <button
          type="button"
          className="btn-icon"
          onClick={onClose}
          aria-label="Close navigation"
          style={{ display: open ? 'inline-flex' : 'none' }}
          data-sidebar-close
        >
          <X size={15} />
        </button>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, minHeight: 0, padding: '12px 0 6px', overflowY: 'auto' }}>
        <NavSection title="Monitor" items={monitorItems} currentPath={location.pathname} onNavigate={onClose} />
        <NavSection title="Analyze" items={analyzeItems} currentPath={location.pathname} onNavigate={onClose} />
        {systemItems.length > 0 && (
          <NavSection title="System" items={systemItems} currentPath={location.pathname} onNavigate={onClose} />
        )}
      </nav>

      {/* Theme: header owns the desktop control; the drawer keeps this row. */}
      <div className="sidebar-theme-control" style={{ padding: '0 10px 10px', flexShrink: 0 }}>
        <ThemeToggleRow />
      </div>

      {/* System status */}
      {showStatusPanel && (
        <div
          style={{
            flexShrink: 0,
            margin: '0 10px 10px',
            padding: '11px 12px',
            border: '1px solid var(--border-subtle)',
            borderRadius: 11,
            background: 'var(--bg-subtle)',
          }}
        >
          <p className="section-label" style={{ fontSize: '0.58rem', marginBottom: 7 }}>
            System status
          </p>
          {statusItems.map((item) => (
            <div key={item.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 5 }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{item.label}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <StatusDot status={item.dot as 'online' | 'offline' | 'warning'} pulse={false} />
                <span style={{ fontSize: '0.68rem', color: item.textColor, fontWeight: 550 }}>{item.text}</span>
              </div>
            </div>
          ))}
          <p className="font-mono" style={{ fontSize: '0.6rem', color: 'var(--text-faint)', marginTop: 7 }}>
            build 2026.04
          </p>
        </div>
      )}

      {/* Mobile close */}
      <div style={{ padding: '0 10px 12px', display: open ? 'block' : 'none', flexShrink: 0 }}>
        <button type="button" className="btn-secondary" onClick={onClose} style={{ width: '100%' }}>
          Close menu
        </button>
      </div>
    </aside>
  );
}
