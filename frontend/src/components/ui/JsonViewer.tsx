import { useState } from 'react';
import { ChevronRight, ChevronDown, Copy, Check } from 'lucide-react';

interface JsonViewerProps {
  data: unknown;
  title?: string;
}

function JsonNode({ value, depth = 0 }: { value: unknown; depth?: number }) {
  const [collapsed, setCollapsed] = useState(depth > 2);

  if (value === null) return <span style={{ color: '#6B7280' }}>null</span>;
  if (value === undefined) return <span style={{ color: '#6B7280' }}>undefined</span>;
  if (typeof value === 'boolean')
    return <span style={{ color: '#10B981' }}>{String(value)}</span>;
  if (typeof value === 'number')
    return <span style={{ color: '#F59E0B', fontFamily: 'JetBrains Mono, monospace' }}>{value}</span>;
  if (typeof value === 'string')
    return <span style={{ color: '#93C5FD' }}>"{value}"</span>;

  if (Array.isArray(value)) {
    if (value.length === 0) return <span style={{ color: 'var(--text-muted)' }}>[]</span>;
    return (
      <span>
        <button
          onClick={() => setCollapsed((c) => !c)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '0 2px', verticalAlign: 'middle' }}
        >
          {collapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
        </button>
        <span style={{ color: 'var(--text-muted)' }}>[</span>
        {collapsed ? (
          <span style={{ color: 'var(--text-muted)' }}> {value.length} items ]</span>
        ) : (
          <>
            <div style={{ marginLeft: 16 }}>
              {value.map((item, i) => (
                <div key={i}>
                  <JsonNode value={item} depth={depth + 1} />
                  {i < value.length - 1 && <span style={{ color: 'var(--text-muted)' }}>,</span>}
                </div>
              ))}
            </div>
            <span style={{ color: 'var(--text-muted)' }}>]</span>
          </>
        )}
      </span>
    );
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return <span style={{ color: 'var(--text-muted)' }}>{'{}'}</span>;
    return (
      <span>
        <button
          onClick={() => setCollapsed((c) => !c)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '0 2px', verticalAlign: 'middle' }}
        >
          {collapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
        </button>
        <span style={{ color: 'var(--text-muted)' }}>{'{'}</span>
        {collapsed ? (
          <span style={{ color: 'var(--text-muted)' }}> {entries.length} keys {'}'}</span>
        ) : (
          <>
            <div style={{ marginLeft: 16 }}>
              {entries.map(([key, val], i) => (
                <div key={key}>
                  <span style={{ color: '#C084FC' }}>"{key}"</span>
                  <span style={{ color: 'var(--text-muted)' }}>: </span>
                  <JsonNode value={val} depth={depth + 1} />
                  {i < entries.length - 1 && <span style={{ color: 'var(--text-muted)' }}>,</span>}
                </div>
              ))}
            </div>
            <span style={{ color: 'var(--text-muted)' }}>{'}'}</span>
          </>
        )}
      </span>
    );
  }

  return <span>{String(value)}</span>;
}

export function JsonViewer({ data, title = 'Raw Breakdown' }: JsonViewerProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
      <button
        onClick={() => setIsOpen((o) => !o)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'var(--bg-input)',
          border: 'none',
          padding: '12px 16px',
          cursor: 'pointer',
          color: 'var(--text-secondary)',
          fontSize: '0.875rem',
          fontWeight: 600,
        }}
      >
        <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          {title}
        </span>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          {isOpen ? 'collapse' : 'expand'}
        </span>
      </button>
      {isOpen && (
        <div style={{ background: '#0D1117', padding: 16, position: 'relative' }}>
          <button
            onClick={handleCopy}
            style={{
              position: 'absolute',
              top: 12,
              right: 12,
              background: 'var(--bg-input)',
              border: '1px solid var(--border-default)',
              borderRadius: 4,
              padding: '4px 8px',
              cursor: 'pointer',
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              fontSize: '0.75rem',
            }}
          >
            {copied ? <Check size={12} style={{ color: 'var(--safe)' }} /> : <Copy size={12} />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <pre
            className="font-mono"
            style={{
              fontSize: '0.8rem',
              lineHeight: 1.6,
              color: 'var(--text-secondary)',
              overflow: 'auto',
              maxHeight: 400,
            }}
          >
            <JsonNode value={data} />
          </pre>
        </div>
      )}
    </div>
  );
}
