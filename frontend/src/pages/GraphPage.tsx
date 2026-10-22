import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, Share2, AlertCircle, X, ExternalLink, Download } from 'lucide-react';
import ForceGraph2d from 'react-force-graph-2d';
import { getGraph, getCampaigns, type GraphData, type GraphNode, type Campaign } from '../api/forensics';
import { useTheme } from '../lib/theme';

const TYPE_COLORS: Record<string, string> = {
  email: '#2563eb',
  domain: '#7c3aed',
  ip: '#d97706',
  hash: '#dc2626',
  brand: '#db2777',
  campaign: '#059669',
};

const LEGEND: Array<{ type: string; label: string }> = [
  { type: 'email', label: 'Email' },
  { type: 'domain', label: 'Domain' },
  { type: 'ip', label: 'IP' },
  { type: 'hash', label: 'Hash' },
  { type: 'brand', label: 'Brand' },
  { type: 'campaign', label: 'Campaign' },
];

export function GraphPage() {
  const navigate = useNavigate();
  const { isDark } = useTheme();
  const [data, setData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [minScore, setMinScore] = useState(0);
  const [campaignId, setCampaignId] = useState<number | undefined>(undefined);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 900, height: 560 });

  const load = useCallback(async (score: number, campaign?: number) => {
    setLoading(true);
    try {
      setError(null);
      setSelected(null);
      const g = await getGraph(score, 500, campaign);
      setData(g);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load graph');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    queueMicrotask(() => load(minScore, campaignId));
  }, [load, minScore, campaignId]);

  useEffect(() => {
    queueMicrotask(() => {
      getCampaigns()
        .then(setCampaigns)
        .catch(() => setCampaigns([])); // filter is best-effort
    });
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => setSize({ width: el.offsetWidth, height: Math.max(420, el.offsetHeight) });
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const graphData = useMemo(() => {
    if (!data) return { nodes: [], links: [] };
    return {
      nodes: data.nodes.map((n) => ({ ...n })),
      links: data.edges.map((e) => ({ source: e.source, target: e.target, relation: e.relation })),
    };
  }, [data]);

  const handleNodeClick = useCallback((node: { id: string; type: string; label?: string; risk?: number }) => {
    setSelected(node as GraphNode);
  }, []);

  // Edges touching the selected node (for the side panel, plan §6.3 FE-C4)
  const selectedEdges = useMemo(() => {
    if (!selected || !data) return [];
    return data.edges
      .filter((e) => e.source === selected.id || e.target === selected.id)
      .map((e) => {
        const otherId = e.source === selected.id ? e.target : e.source;
        const other = data.nodes.find((n) => n.id === otherId);
        return { relation: e.relation, otherId, otherLabel: other?.label ?? otherId };
      });
  }, [selected, data]);

  const openSelected = () => {
    if (!selected) return;
    if (selected.type === 'email') navigate(`/scans/${selected.id.split(':')[1]}`);
    else if (selected.type === 'campaign') navigate(`/campaigns/${selected.id.split(':')[1]}`);
  };

  return (
    <div className="dashboard-page" style={{ paddingTop: 22 }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Share2 size={18} style={{ color: 'var(--primary)' }} />
          <div>
            <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>Attribution Graph</h2>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {data ? `${data.nodes.length} nodes · ${data.edges.length} edges` : 'loading…'} — click a node for details
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            campaign
            <select
              value={campaignId ?? ''}
              onChange={(e) => setCampaignId(e.target.value ? Number(e.target.value) : undefined)}
              style={{ background: 'var(--input-bg)', border: '1px solid var(--border-default)', borderRadius: 8, color: 'var(--text-primary)', padding: '6px 10px', fontSize: '0.75rem', maxWidth: 230, boxShadow: 'var(--shadow-xs)' }}
            >
              <option value="">all campaigns</option>
              {campaigns.map((c) => (
                <option key={c.id} value={c.id}>#{c.id} {c.name}</option>
              ))}
            </select>
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            min score
            <input
              type="range"
              min={0}
              max={100}
              step={10}
              value={minScore}
              onChange={(e) => setMinScore(Number(e.target.value))}
              style={{ accentColor: 'var(--primary)', width: 120 }}
            />
            <span className="font-mono" style={{ color: 'var(--text-primary)', width: 24 }}>{minScore}</span>
          </label>
          <button className="btn-ghost" onClick={() => load(minScore, campaignId)} disabled={loading} style={{ fontSize: '0.75rem', padding: '5px 12px' }}>
            <RefreshCw size={12} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            Reload
          </button>
          <a
            className="btn-ghost"
            href={`/api/export/stix${campaignId ? `?campaign_id=${campaignId}` : ''}`}
            download
            title="Download this account's indicators as a STIX 2.1 bundle"
            style={{ fontSize: '0.75rem', padding: '5px 12px', textDecoration: 'none' }}
          >
            <Download size={12} /> STIX 2.1
          </a>
          <a
            className="btn-ghost"
            href={`/api/export/csv${campaignId ? `?campaign_id=${campaignId}` : ''}`}
            download
            title="Download this account's indicators as CSV"
            style={{ fontSize: '0.75rem', padding: '5px 12px', textDecoration: 'none' }}
          >
            <Download size={12} /> CSV
          </a>
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        {LEGEND.map(({ type, label }) => (
          <span key={type} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: TYPE_COLORS[type], display: 'inline-block' }} />
            {label}
          </span>
        ))}
      </div>

      {/* Canvas */}
      <div
        ref={containerRef}
        className="graph-canvas"
        style={{
          position: 'relative',
          height: 560,
          background: 'var(--bg-card)',
          border: '1px solid var(--border-default)',
          borderRadius: 14,
          overflow: 'hidden',
          boxShadow: 'var(--shadow-card)',
        }}
      >
        {error && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'center', justifyContent: 'center' }}>
            <AlertCircle size={28} style={{ color: 'var(--danger)' }} />
            <p style={{ fontSize: '0.85rem', color: 'var(--text-danger)' }}>{error}</p>
            <button className="btn-ghost" onClick={() => load(minScore)} style={{ fontSize: '0.75rem' }}>Retry</button>
          </div>
        )}

        {!error && !loading && graphData.nodes.length === 0 && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
            <Share2 size={28} style={{ color: 'var(--text-muted)' }} />
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>No nodes above score {minScore} — lower the filter or run more scans.</p>
          </div>
        )}

        {!error && graphData.nodes.length > 0 && (
          <ForceGraph2d
            graphData={graphData}
            width={size.width}
            height={size.height}
            backgroundColor={isDark ? '#0f1829' : '#ffffff'}
            nodeId="id"
            nodeColor={(n) => TYPE_COLORS[n.type] ?? '#64748b'}
            nodeVal={(n) => Math.max(2, (n.risk ?? 0) / 12)}
            nodeLabel={(n) => `${n.type}: ${n.label} · risk ${n.risk}`}
            nodeRelSize={3}
            linkColor={() => (isDark ? 'rgba(148,163,184,0.34)' : 'rgba(100,116,139,0.28)')}
            linkDirectionalArrowLength={3}
            linkDirectionalArrowRelPos={1}
            onNodeClick={handleNodeClick}
            warmupTicks={40}
            cooldownTime={3000}
          />
        )}

        {/* Node detail side panel (plan §6.3, FE-C4) */}
        {selected && (
          <div
            style={{
              position: 'absolute',
              top: 12,
              right: 12,
              width: 264,
              background: 'var(--popover-bg)',
              border: '1px solid var(--popover-border)',
              borderRadius: 8,
              padding: 14,
              zIndex: 5,
              boxShadow: 'var(--shadow-float)', backdropFilter: 'blur(20px)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
              <span style={{ fontSize: '0.65rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: TYPE_COLORS[selected.type] ?? '#64748b' }}>
                {selected.type}
              </span>
              <button
                onClick={() => setSelected(null)}
                aria-label="Close node panel"
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 2, display: 'flex' }}
              >
                <X size={14} />
              </button>
            </div>
            <p style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)', wordBreak: 'break-word', marginBottom: 6 }}>
              {selected.label}
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>risk</span>
              <div style={{ flex: 1, height: 5, background: 'var(--border-subtle)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${Math.min(100, Math.max(0, selected.risk ?? 0))}%`, height: '100%', background: TYPE_COLORS[selected.type] ?? '#64748b' }} />
              </div>
              <span className="font-mono" style={{ fontSize: '0.68rem', color: 'var(--text-primary)' }}>{selected.risk ?? 0}</span>
            </div>

            {selectedEdges.length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                  Links ({selectedEdges.length})
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3, maxHeight: 132, overflowY: 'auto' }}>
                  {selectedEdges.slice(0, 8).map((edge, i) => (
                    <div key={i} style={{ display: 'flex', gap: 6, fontSize: '0.68rem', alignItems: 'baseline' }}>
                      <span style={{ color: 'var(--text-muted)', minWidth: 78 }}>{edge.relation}</span>
                      <span style={{ color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{edge.otherLabel}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {(selected.type === 'email' || selected.type === 'campaign') ? (
              <button
                className="btn-ghost"
                onClick={openSelected}
                style={{ width: '100%', fontSize: '0.72rem', padding: '5px 10px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5 }}
              >
                Open {selected.type} <ExternalLink size={11} />
              </button>
            ) : (
              <p style={{ fontSize: '0.66rem', color: 'var(--text-muted)' }}>
                IoC node — open its email from the graph to inspect.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
