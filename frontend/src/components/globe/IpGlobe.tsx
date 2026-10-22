import { useEffect, useMemo, useRef, useState } from 'react';
import Globe, { type GlobeMethods } from 'react-globe.gl';
import { useReducedMotion } from 'framer-motion';
import { Globe2, Loader2 } from 'lucide-react';
import { getIpGeo, type IpGeoPoint } from '../../api/forensics';
import { useTheme } from '../../lib/theme';

const COLORS = {
  tor: '#dc2626',
  vpn: '#d97706',
  proxy: '#db2777',
  hosting: '#7c3aed',
  dnsbl: '#dc2626',
  base: '#0891b2',
} as const;

function pointColor(p: IpGeoPoint): string {
  if (p.is_tor) return COLORS.tor;
  if (p.is_dnsbl_listed) return COLORS.dnsbl;
  if (p.is_vpn) return COLORS.vpn;
  if (p.is_proxy) return COLORS.proxy;
  if (p.is_hosting) return COLORS.hosting;
  return COLORS.base;
}

function flagsOf(p: IpGeoPoint): string[] {
  const flags: string[] = [];
  if (p.is_tor) flags.push('TOR exit');
  if (p.is_vpn) flags.push('VPN');
  if (p.is_proxy) flags.push('Proxy');
  if (p.is_hosting) flags.push('Hosting');
  if (p.is_dnsbl_listed) flags.push('DNSBL-listed');
  return flags;
}

function pointLabel(p: IpGeoPoint): string {
  const where = [p.city, p.country].filter(Boolean).join(', ') || 'unknown location';
  const flags = flagsOf(p);
  const tag = flags.length ? ` [${flags.join(' · ')}]` : '';
  const asn = p.asn ? ` · AS${p.asn}${p.asn_org ? ` ${p.asn_org}` : ''}` : '';
  return `${p.ip} — ${where}${tag}${asn}`;
}

function withAlpha(hex: string, alpha: number): string {
  const n = parseInt(hex.slice(1), 16);
  const r = (n >> 16) & 255;
  const g = (n >> 8) & 255;
  const b = n & 255;
  return `rgba(${r}, ${g}, ${b}, ${Math.max(0, Math.min(1, alpha)).toFixed(3)})`;
}

interface GlobeLabel {
  lat: number;
  lng: number;
  text: string;
}

const LEGEND: Array<{ color: string; label: string }> = [
  { color: COLORS.base, label: 'Resolved' },
  { color: COLORS.tor, label: 'TOR' },
  { color: COLORS.vpn, label: 'VPN' },
  { color: COLORS.hosting, label: 'Hosting' },
];

export default function IpGlobe() {
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const reduceMotion = useReducedMotion();
  const { isDark } = useTheme();
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [points, setPoints] = useState<IpGeoPoint[]>([]);
  const [total, setTotal] = useState(0);
  const [geoed, setGeoed] = useState(0);
  const [loaded, setLoaded] = useState(false);
  const [ready, setReady] = useState(false);
  const [hovered, setHovered] = useState<IpGeoPoint | null>(null);
  const [webglAvailable] = useState(() => {
    try {
      const canvas = document.createElement('canvas');
      return Boolean(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
    } catch {
      return false;
    }
  });

  useEffect(() => {
    let cancelled = false;
    getIpGeo()
      .then((d) => {
        if (cancelled) return;
        setPoints(d.points);
        setTotal(d.total_ips);
        setGeoed(d.geoed);
      })
      .catch(() => {
        if (!cancelled) setPoints([]);
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (!rect) return;
      const w = Math.round(rect.width);
      const h = Math.round(rect.height);
      if (w > 0 && h > 0) setSize((prev) => (prev.w === w && prev.h === h ? prev : { w, h }));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Interaction gate: only a zone extending 40% beyond the globe's screen
  // silhouette drives the globe (spin/zoom). Everything else — the empty
  // side areas of the section — falls through to normal page scrolling.
  const inGlobeZone = (clientX: number, clientY: number): boolean => {
    const el = wrapRef.current;
    if (!el) return false;
    const rect = el.getBoundingClientRect();
    const cam = globeRef.current?.camera() as unknown as
      | { position: { x: number; y: number; z: number }; fov?: number }
      | undefined;
    let r = rect.height * 0.45;
    if (cam && cam.fov) {
      const d = Math.hypot(cam.position.x, cam.position.y, cam.position.z);
      const ratio = Math.min(0.999, 100 / d);
      r =
        ((rect.height / 2) * (ratio / Math.sqrt(1 - ratio * ratio))) /
        Math.tan(((cam.fov * Math.PI) / 180) / 2);
    }
    const zoneR = r * 1.4;
    const dx = clientX - (rect.left + rect.width / 2);
    const dy = clientY - (rect.top + rect.height / 2);
    return dx * dx + dy * dy <= zoneR * zoneR;
  };

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!inGlobeZone(e.clientX, e.clientY)) e.stopPropagation();
    };
    const onPointerDown = (e: PointerEvent) => {
      const inside = inGlobeZone(e.clientX, e.clientY);
      const canvas = el.querySelector('canvas');
      if (canvas) canvas.style.touchAction = inside ? 'none' : 'auto';
      if (!inside) e.stopPropagation();
    };
    const onContextMenu = (e: MouseEvent) => {
      if (!inGlobeZone(e.clientX, e.clientY)) e.stopPropagation();
    };
    el.addEventListener('wheel', onWheel, true);
    el.addEventListener('pointerdown', onPointerDown, true);
    el.addEventListener('contextmenu', onContextMenu, true);
    return () => {
      el.removeEventListener('wheel', onWheel, true);
      el.removeEventListener('pointerdown', onPointerDown, true);
      el.removeEventListener('contextmenu', onContextMenu, true);
    };
  }, []);

  // One label per country (first point wins) plus every flagged point.
  const labels = useMemo<GlobeLabel[]>(() => {
    const seen = new Set<string>();
    const out: GlobeLabel[] = [];
    for (const p of points) {
      const key = p.country || p.country_code || p.ip;
      const flags = flagsOf(p);
      if (flags.length > 0) {
        out.push({
          lat: p.lat,
          lng: p.lng,
          text: `${flags[0]} · ${p.city || p.country || p.ip}`,
        });
        seen.add(key);
      } else if (!seen.has(key) && p.country) {
        out.push({ lat: p.lat, lng: p.lng, text: p.country });
        seen.add(key);
      }
    }
    return out;
  }, [points]);

  // Auto-rotate: spin gently, stop while the user hovers a marker.
  useEffect(() => {
    const controls = globeRef.current?.controls();
    if (!controls) return;
    controls.autoRotate = !hovered && !reduceMotion;
    controls.autoRotateSpeed = 0.5;
  }, [hovered, ready, size.w, points, reduceMotion]);

  const handleReady = () => {
    globeRef.current?.pointOfView({ lat: 22, lng: 32, altitude: 1.7 }, 0);
    setReady(true);
  };

  return (
    <section
      style={{
        background: 'var(--globe-surface)',
        border: '1px solid var(--border-default)',
        borderRadius: 14,
        overflow: 'hidden',
        boxShadow: 'var(--shadow-card)',
      }}
    >
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          flexWrap: 'wrap',
          background: 'var(--globe-header-bg)',
          backdropFilter: 'blur(16px)',
        }}
      >
        <div>
          <p style={{ fontSize: '0.88rem', fontWeight: 680, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Globe2 size={15} style={{ color: 'var(--primary)' }} />
            Global threat origins
          </p>
          <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 3 }}>
            {loaded
              ? `${geoed} of ${total} IPs geolocated · drag to spin · scroll to zoom`
              : 'Loading IP intelligence…'}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', padding: '5px 9px', background: 'var(--globe-legend-bg)', border: '1px solid var(--border-default)', borderRadius: 999 }}>
          {LEGEND.map((item) => (
            <span
              key={item.label}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                fontSize: '0.62rem',
                fontWeight: 600,
                color: 'var(--text-muted)',
                letterSpacing: '0.03em',
              }}
            >
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: item.color,
                  boxShadow: `0 0 0 3px ${withAlpha(item.color, 0.12)}`,
                }}
              />
              {item.label}
            </span>
          ))}
        </div>
      </div>

      <div ref={wrapRef} className="globe-canvas-wrap globe-stage" style={{ position: 'relative', height: webglAvailable ? 500 : 300 }}>
        {!webglAvailable ? (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8, color: 'var(--globe-stage-text)', padding: 24, textAlign: 'center' }}>
            <Globe2 size={30} style={{ color: 'var(--globe-stage-text-faint)' }} />
            <p style={{ fontSize: '0.84rem', fontWeight: 600, color: 'var(--globe-stage-text-strong)' }}>3D globe unavailable</p>
            <p style={{ fontSize: '0.76rem' }}>WebGL is disabled in this browser. IP origin data is still available in the scan detail and trace views.</p>
          </div>
        ) : size.w > 0 && size.h > 0 && (
          <Globe
            ref={globeRef}
            width={size.w}
            height={size.h}
            backgroundColor="rgba(0,0,0,0)"
            globeImageUrl={
              isDark
                ? 'https://unpkg.com/three-globe/example/img/earth-night.jpg'
                : 'https://unpkg.com/three-globe/example/img/earth-day.jpg'
            }
            bumpImageUrl="https://unpkg.com/three-globe/example/img/earth-topology.png"
            atmosphereColor={isDark ? '#60a5fa' : '#93c5fd'}
            atmosphereAltitude={0.12}
            showGraticules={false}
            onGlobeReady={handleReady}
            pointsData={points}
            pointLat="lat"
            pointLng="lng"
            pointColor={(p) => pointColor(p as IpGeoPoint)}
            pointAltitude={0.018}
            pointRadius={0.34}
            pointResolution={16}
            pointsTransitionDuration={reduceMotion ? 0 : 1300}
            pointLabel={(p) => pointLabel(p as IpGeoPoint)}
            onPointHover={(p) => setHovered((p as IpGeoPoint | null) ?? null)}
            labelsData={labels}
            labelLat="lat"
            labelLng="lng"
            labelText="text"
            labelSize={1.05}
            labelDotRadius={0.34}
            labelColor={() => (isDark ? '#e8eef8' : '#0f172a')}
            labelResolution={2}
            labelAltitude={0.012}
            labelsTransitionDuration={reduceMotion ? 0 : 1100}
            ringsData={reduceMotion ? [] : points}
            ringLat="lat"
            ringLng="lng"
            ringColor={(p: object) => (t: number) => withAlpha(pointColor(p as IpGeoPoint), 1 - t)}
            ringMaxRadius={4}
            ringPropagationSpeed={2.3}
            ringRepeatPeriod={2200}
          />
        )}

        {!loaded && (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 8,
              fontSize: '0.8rem',
              color: 'var(--globe-stage-text-muted)',
              pointerEvents: 'none',
            }}
          >
            <Loader2 size={16} style={{ animation: 'spin 1s linear infinite', color: 'var(--primary)' }} />
            Loading IP intelligence…
          </div>
        )}

        {loaded && points.length === 0 && (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '0.8rem',
              color: 'var(--globe-stage-text-muted)',
              pointerEvents: 'none',
              textAlign: 'center',
              padding: 24,
            }}
          >
            No geolocated IPs yet — run a scan with origin tracing to populate the globe.
          </div>
        )}
      </div>
    </section>
  );
}
