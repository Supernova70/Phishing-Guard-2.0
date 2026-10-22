import { useEffect, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { Shield, Lock, Mail, ScanLine, Radar, Fingerprint, ArrowRight } from 'lucide-react';
import {
  getAuthConfig,
  postCredential,
  startGoogleSignIn,
  type AuthConfig,
} from '../api/auth';
import { useAuth } from '../auth/AuthContext';
import { ThemeToggle } from '../components/ui/ThemeToggle';

interface GisId {
  initialize(opts: {
    client_id: string;
    callback: (resp: { credential: string }) => void;
  }): void;
  prompt(): void;
}

declare global {
  interface Window {
    google?: { accounts?: { id?: GisId } };
  }
}

const GIS_SRC = 'https://accounts.google.com/gsi/client';

const ERROR_MESSAGES: Record<string, string> = {
  invalid_state: 'Your sign-in session expired — please try again.',
  token_exchange_failed: 'Google sign-in failed during token exchange — please try again.',
  missing_id_token: 'Google did not return an identity token — please try again.',
  invalid_id_token: 'Google identity verification failed — please try again.',
  'google:access_denied': 'You declined the Google consent screen.',
};

function friendlyError(code: string | null): string | null {
  if (!code) return null;
  if (ERROR_MESSAGES[code]) return ERROR_MESSAGES[code];
  if (code.startsWith('google:')) return `Google returned an error: ${code.slice(7)}`;
  return 'Sign-in failed — please try again.';
}

function GoogleGIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
    </svg>
  );
}

export function LoginPage() {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const reduceMotion = useReducedMotion();
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [signingIn, setSigningIn] = useState(false);
  const [error, setError] = useState<string | null>(
    friendlyError(new URLSearchParams(window.location.search).get('error'))
  );

  useEffect(() => {
    let cancelled = false;
    getAuthConfig()
      .then((c) => {
        if (!cancelled) {
          setConfig(c);
          setConfigLoading(false);
          if (c.configured) initOneTap(c.google_client_id);
        }
      })
      .catch(() => !cancelled && setConfigLoading(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const initOneTap = (clientId: string) => {
    const boot = () => {
      const gis = window.google?.accounts?.id;
      if (!gis) return;
      gis.initialize({
        client_id: clientId,
        callback: async (resp) => {
          try {
            const gCsrf =
              document.cookie
                .split('; ')
                .find((c) => c.startsWith('g_csrf_token='))
                ?.split('=')[1] ?? null;
            await postCredential(resp.credential, gCsrf);
            navigate('/', { replace: true });
          } catch (err) {
            const detail =
              (err as { response?: { data?: { detail?: string } } })?.response
                ?.data?.detail;
            if (detail && !detail.includes('Account not found')) {
              setError(detail);
            }
          }
        },
      });
      gis.prompt();
    };
    if (window.google?.accounts?.id) {
      boot();
      return;
    }
    const existing = document.querySelector<HTMLScriptElement>(
      `script[src="${GIS_SRC}"]`
    );
    if (existing) {
      existing.addEventListener('load', boot);
      return;
    }
    const script = document.createElement('script');
    script.src = GIS_SRC;
    script.async = true;
    script.defer = true;
    script.onload = boot;
    document.head.appendChild(script);
  };

  if (!loading && user) return <Navigate to="/" replace />;

  const configured = config?.configured ?? false;

  const fade = reduceMotion
    ? {}
    : {
        initial: { opacity: 0, y: 14 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] as const },
      };

  const features = [
    { icon: <Radar size={15} />, title: 'Real-time triage', text: 'Live scan state, verdicts and alert streaming in one console.' },
    { icon: <Fingerprint size={15} />, title: 'Forensic depth', text: 'Headers, routing, IOCs and evidence linked to every decision.' },
    { icon: <Shield size={15} />, title: 'Read-only by design', text: 'Your mailbox is never modified, moved or deleted.' },
  ];

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 1.1fr) minmax(420px, 0.9fr)',
        background: 'var(--login-bg)',
        overflow: 'hidden',
        position: 'relative',
      }}
      className="login-shell"
    >
      <div style={{ position: 'absolute', top: 18, right: 18, zIndex: 20 }}>
        <ThemeToggle />
      </div>

      {/* Brand / narrative */}
      <div
        style={{
          position: 'relative',
          padding: 'clamp(28px, 5vw, 64px)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          overflow: 'hidden',
        }}
      >
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            width: 620,
            height: 620,
            right: '-18%',
            top: '8%',
            borderRadius: '50%',
            border: '1px solid var(--primary-ring)',
            boxShadow: 'inset 0 0 80px var(--primary-glow)',
          }}
        />
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            width: 390,
            height: 390,
            right: '2%',
            top: '24%',
            borderRadius: '50%',
            border: '1px dashed var(--primary-ring)',
          }}
        />
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            width: 10,
            height: 10,
            borderRadius: '50%',
            background: 'var(--primary)',
            right: '18%',
            top: '27%',
            boxShadow: '0 0 0 6px var(--primary-glow)',
          }}
        />

        <motion.div {...fade} style={{ position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 42 }}>
            <div
              style={{
                width: 40,
                height: 40,
                borderRadius: 12,
                background: 'var(--brand-tile-bg)',
                border: '1px solid var(--brand-tile-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: 'var(--shadow-raised)',
              }}
            >
              <Shield size={21} style={{ color: 'var(--primary)' }} />
            </div>
            <div>
              <p style={{ fontSize: '0.86rem', fontWeight: 750, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>Phishing-Guard</p>
              <p className="font-mono" style={{ fontSize: '0.58rem', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>SOC CONSOLE · 2.0</p>
            </div>
          </div>

          <p className="section-label" style={{ marginBottom: 12 }}>Email threat intelligence</p>
          <h1 style={{ fontSize: 'clamp(2.1rem, 4.2vw, 3.6rem)', lineHeight: 1.02, letterSpacing: '-0.045em', fontWeight: 760, color: 'var(--text-primary)', maxWidth: 620 }}>
            See the threat
            <br />
            <span style={{ color: 'var(--primary)' }}>before it lands.</span>
          </h1>
          <p style={{ marginTop: 20, maxWidth: 500, fontSize: '0.95rem', lineHeight: 1.72, color: 'var(--text-secondary)' }}>
            An analyst-grade workspace for AI email threat detection, geolocation,
            attribution and forensic evidence — built for decisions, not dashboards.
          </p>
        </motion.div>

        <motion.div
          {...(reduceMotion ? {} : { initial: { opacity: 0 }, animate: { opacity: 1 }, transition: { delay: 0.18, duration: 0.4 } })}
          style={{ position: 'relative', zIndex: 1, display: 'grid', gap: 11, maxWidth: 540, marginTop: 40 }}
        >
          {features.map((f) => (
            <div key={f.title} style={{ display: 'flex', gap: 11, alignItems: 'flex-start' }}>
              <span style={{ width: 28, height: 28, borderRadius: 8, background: 'var(--bg-card)', border: '1px solid var(--border-default)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: 'var(--primary)', flexShrink: 0, boxShadow: 'var(--shadow-xs)' }}>
                {f.icon}
              </span>
              <div>
                <p style={{ fontSize: '0.78rem', fontWeight: 650, color: 'var(--text-primary)' }}>{f.title}</p>
                <p style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: 1, lineHeight: 1.5 }}>{f.text}</p>
              </div>
            </div>
          ))}
        </motion.div>
      </div>

      {/* Auth card */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 'clamp(22px, 4vw, 48px)',
          position: 'relative',
        }}
      >
        <motion.div
          {...(reduceMotion ? {} : { initial: { opacity: 0, y: 18, scale: 0.985 }, animate: { opacity: 1, y: 0, scale: 1 }, transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] } })}
          style={{
            width: '100%',
            maxWidth: 420,
            background: 'var(--glass-bg)',
            border: '1px solid var(--glass-border)',
            borderRadius: 20,
            padding: 'clamp(26px, 3.2vw, 38px)',
            display: 'flex',
            flexDirection: 'column',
            gap: 20,
            boxShadow: 'var(--shadow-float)',
            backdropFilter: 'blur(26px) saturate(175%)',
            WebkitBackdropFilter: 'blur(26px) saturate(175%)',
          }}
        >
          <div>
            <div style={{ width: 38, height: 38, borderRadius: 11, background: 'var(--primary-soft)', border: '1px solid var(--primary-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16 }}>
              <Lock size={18} style={{ color: 'var(--primary)' }} />
            </div>
            <h2 style={{ fontSize: '1.4rem', fontWeight: 730, letterSpacing: '-0.025em', color: 'var(--text-primary)' }}>Sign in to your workspace</h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 6, lineHeight: 1.6 }}>
              Use your authorised Google account. Access is governed by your assigned role.
            </p>
          </div>

          {error && (
            <div
              role="alert"
              style={{
                background: 'var(--danger-subtle)',
                border: '1px solid var(--danger-border)',
                color: 'var(--text-danger)',
                borderRadius: 10,
                padding: '10px 12px',
                fontSize: '0.78rem',
                lineHeight: 1.5,
              }}
            >
              {error}
            </div>
          )}

          <button
            onClick={() => {
              if (!configured || signingIn) return;
              setSigningIn(true);
              startGoogleSignIn();
            }}
            disabled={!configured || configLoading || signingIn}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 10,
              width: '100%',
              padding: '12px 16px',
              borderRadius: 10,
              border: '1px solid var(--border-default)',
              background: 'var(--bg-card)',
              color: 'var(--text-primary)',
              fontSize: '0.86rem',
              fontWeight: 650,
              cursor: configured ? 'pointer' : 'not-allowed',
              opacity: signingIn ? 0.7 : 1,
              boxShadow: 'var(--shadow-xs)',
              transition: 'border-color 140ms ease, box-shadow 140ms ease, transform 100ms ease',
            }}
          >
            <GoogleGIcon />
            {signingIn ? 'Opening Google…' : 'Continue with Google'}
            {!signingIn && <ArrowRight size={15} style={{ marginLeft: 'auto', color: 'var(--text-faint)' }} />}
          </button>

          {!configLoading && !configured && (
            <p style={{ fontSize: '0.72rem', color: 'var(--text-warning)', textAlign: 'center', margin: 0, background: 'var(--warning-subtle)', border: '1px solid var(--warning-border)', borderRadius: 8, padding: '8px 10px' }}>
              Google sign-in is not configured yet. Add a Google Cloud Console client ID to enable access.
            </p>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ flex: 1, height: 1, background: 'var(--border-subtle)' }} />
            <span className="section-label" style={{ fontSize: '0.58rem' }}>Secure by design</span>
            <div style={{ flex: 1, height: 1, background: 'var(--border-subtle)' }} />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <Mail size={14} style={{ color: 'var(--primary)', flexShrink: 0 }} />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Read-only Gmail analysis. Nothing is sent or deleted.</span>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <ScanLine size={14} style={{ color: 'var(--primary)', flexShrink: 0 }} />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Every verdict keeps its evidence trail.</span>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'center', gap: 14, fontSize: '0.68rem', marginTop: 2 }}>
            <a href="/privacy-policy.html" target="_blank" rel="noopener" style={{ color: 'var(--text-muted)', textDecoration: 'none' }}>
              Privacy Policy
            </a>
            <span style={{ color: 'var(--border-default)' }}>·</span>
            <a href="/terms-of-service.html" target="_blank" rel="noopener" style={{ color: 'var(--text-muted)', textDecoration: 'none' }}>
              Terms of Service
            </a>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
