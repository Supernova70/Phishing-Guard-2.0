import { NavLink, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
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
} from 'lucide-react';
import { StatusDot } from '../ui/Badge';

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
}

function NavSection({ title, items, currentPath }: NavSectionProps) {
  return (
    <div style={{ marginBottom: 24 }}>
      <p style={{
        fontSize: '0.6rem',
        fontWeight: 700,
        letterSpacing: '0.12em',
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        padding: '0 12px',
        marginBottom: 4,
      }}>
        {title}
      </p>
      {items.map((item) => {
        const isActive = currentPath === item.to || (item.to !== '/' && currentPath.startsWith(item.to));
        return (
          <NavLink
            key={item.to}
            to={item.to}
            style={{ textDecoration: 'none' }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '8px 12px',
                margin: '1px 8px',
                borderRadius: 6,
                cursor: 'pointer',
                position: 'relative',
                background: isActive ? 'var(--primary-glow)' : 'transparent',
                borderLeft: isActive ? '2px solid var(--primary)' : '2px solid transparent',
                transition: 'all 200ms ease',
                color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-input)';
                  (e.currentTarget as HTMLDivElement).style.color = 'var(--text-secondary)';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  (e.currentTarget as HTMLDivElement).style.background = 'transparent';
                  (e.currentTarget as HTMLDivElement).style.color = 'var(--text-muted)';
                }
              }}
            >
              <span style={{ flexShrink: 0, display: 'flex', alignItems: 'center', color: isActive ? 'var(--primary)' : 'inherit' }}>
                {item.icon}
              </span>
              <span style={{ fontSize: '0.875rem', fontWeight: isActive ? 600 : 400, flex: 1 }}>
                {item.label}
              </span>
              {item.badge != null && item.badgeType === 'count' && (
                <span style={{
                  background: 'var(--danger)',
                  color: 'white',
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  padding: '1px 6px',
                  borderRadius: 10,
                  minWidth: 18,
                  textAlign: 'center',
                }}>
                  {item.badge}
                </span>
              )}
              {item.badgeType === 'dot' && item.dotStatus && (
                <StatusDot status={item.dotStatus} pulse />
              )}
            </div>
          </NavLink>
        );
      })}
    </div>
  );
}

interface SidebarProps {
  unreadCount?: number;
  runningScans?: number;
  apiStatus?: 'online' | 'offline' | 'warning';
}

export function Sidebar({ unreadCount = 0, runningScans = 0, apiStatus = 'online' }: SidebarProps) {
  const location = useLocation();

  const monitorItems: NavItem[] = [
    { to: '/', icon: <LayoutDashboard size={16} />, label: 'Dashboard' },
    { to: '/emails', icon: <Inbox size={16} />, label: 'Email Inbox', badge: unreadCount || null, badgeType: 'count' },
    { to: '/active-scans', icon: <ScanLine size={16} />, label: 'Active Scans', badge: runningScans || null, badgeType: 'count' },
  ];

  const analyzeItems: NavItem[] = [
    { to: '/scans', icon: <ShieldCheck size={16} />, label: 'Scan Results' },
    { to: '/url-analysis', icon: <Link2 size={16} />, label: 'URL Analysis' },
    { to: '/attachments', icon: <Paperclip size={16} />, label: 'Attachments' },
  ];

  const systemItems: NavItem[] = [
    { to: '/settings', icon: <Settings size={16} />, label: 'Settings' },
    { to: '/health', icon: <Activity size={16} />, label: 'API Health', badgeType: 'dot', dotStatus: apiStatus },
  ];

  return (
    <aside style={{
      width: 240,
      minWidth: 240,
      height: '100vh',
      background: 'var(--bg-panel)',
      borderRight: '1px solid var(--border-default)',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Logo */}
      <div style={{
        padding: '20px 16px 16px',
        borderBottom: '1px solid var(--border-subtle)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 32,
            height: 32,
            background: 'var(--primary-glow)',
            border: '1px solid var(--primary)',
            borderRadius: 8,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <Shield size={18} style={{ color: 'var(--primary)' }} />
          </div>
          <div>
            <p style={{ fontSize: '0.8rem', fontWeight: 700, letterSpacing: '0.1em', color: 'var(--primary)' }}>
              PHISHING GUARD
            </p>
            <span style={{
              fontSize: '0.6rem',
              fontFamily: 'JetBrains Mono, monospace',
              color: 'var(--text-muted)',
              background: 'var(--bg-input)',
              padding: '1px 5px',
              borderRadius: 3,
            }}>
              v2.0
            </span>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '16px 0', overflowY: 'auto' }}>
        <NavSection title="Monitor" items={monitorItems} currentPath={location.pathname} />
        <NavSection title="Analyze" items={analyzeItems} currentPath={location.pathname} />
        <NavSection title="System" items={systemItems} currentPath={location.pathname} />
      </nav>

      {/* System Status Panel */}
      <div style={{
        padding: '12px 16px',
        borderTop: '1px solid var(--border-subtle)',
        background: 'var(--bg-page)',
      }}>
        <p style={{ fontSize: '0.65rem', fontWeight: 700, letterSpacing: '0.1em', color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>
          System Status
        </p>
        {[
          { label: 'DB', status: apiStatus === 'online' ? 'Connected' : 'Unknown' },
          { label: 'Redis', status: apiStatus === 'online' ? 'Connected' : 'Unknown' },
          { label: 'ML Model', status: apiStatus === 'online' ? 'Loaded' : 'Unknown' },
        ].map((item) => (
          <div key={item.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{item.label}</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <StatusDot status={apiStatus === 'online' ? 'online' : 'warning'} pulse={false} />
              <span style={{ fontSize: '0.7rem', color: apiStatus === 'online' ? 'var(--text-safe)' : 'var(--text-muted)' }}>{item.status}</span>
            </div>
          </div>
        ))}
        <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 8, fontFamily: 'JetBrains Mono, monospace' }}>
          build 2026.04
        </p>
      </div>
    </aside>
  );
}
