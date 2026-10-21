import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  approveIncidentAction,
  closeIncident,
  createIncident,
  executeIncidentAction,
  getIncident,
  listIncidents,
  rejectIncidentAction,
  requestIncidentAction,
  type Incident,
  type ResponseAction,
  type ResponseActionType,
} from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { can } from '../auth/permissions';
import {
  Check,
  CircleSlash,
  FileWarning,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

const STATUS_COLOR: Record<string, string> = {
  open: 'var(--warning)',
  pending_approval: 'var(--primary)',
  approved: 'var(--primary)',
  dry_run: 'var(--warning)',
  contained: 'var(--safe)',
  failed: 'var(--danger)',
  rejected: 'var(--text-muted)',
  closed: 'var(--text-muted)',
};

const ACTION_LABEL: Record<ResponseActionType, string> = {
  quarantine_email: 'Quarantine email',
  block_sender: 'Block sender',
  disable_account: 'Disable account',
  notify_user: 'Notify user',
};

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
      {label}
      {children}
    </label>
  );
}

function StatusPill({ status }: { status: string }) {
  return (
    <span
      style={{
        fontSize: '0.64rem',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        color: STATUS_COLOR[status] ?? 'var(--text-muted)',
        border: `1px solid ${STATUS_COLOR[status] ?? 'var(--border-default)'}`,
        borderRadius: 4,
        padding: '2px 7px',
      }}
    >
      {status.replaceAll('_', ' ')}
    </span>
  );
}

function ActionRow({
  action,
  canRespond,
  busy,
  onApprove,
  onReject,
  onExecute,
}: {
  action: ResponseAction;
  canRespond: boolean;
  busy: boolean;
  onApprove: () => void;
  onReject: () => void;
  onExecute: () => void;
}) {
  return (
    <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '10px 12px', background: 'var(--bg-input)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          {ACTION_LABEL[action.action_type] ?? action.action_type}
        </span>
        <StatusPill status={action.status} />
        <span className="font-mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{action.target}</span>
        <span style={{ marginLeft: 'auto', fontSize: '0.66rem', color: 'var(--text-muted)' }}>
          {action.created_at ? formatDistanceToNow(new Date(action.created_at), { addSuffix: true }) : ''}
        </span>
      </div>
      {action.reason && <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 5 }}>{action.reason}</p>}

      <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
        {action.status === 'pending_approval' && canRespond && (
          <>
            <button onClick={onApprove} disabled={busy} className="btn-ghost" style={{ fontSize: '0.7rem' }}>
              <Check size={12} /> Approve
            </button>
            <button onClick={onReject} disabled={busy} className="btn-ghost" style={{ fontSize: '0.7rem' }}>
              <X size={12} /> Reject
            </button>
          </>
        )}
        {action.status === 'approved' && canRespond && (
          <button onClick={onExecute} disabled={busy} className="btn-ghost" style={{ fontSize: '0.7rem', color: 'var(--warning)' }}>
            <Zap size={12} /> Execute (dry run)
          </button>
        )}
        {action.status === 'approved' && !canRespond && (
          <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Awaiting a responder with incidents.respond</span>
        )}
      </div>

      {(action.evidence_id || action.execution_audit_id) && (
        <p className="font-mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: 7 }}>
          {action.evidence_id ? `evidence #${action.evidence_id}` : ''}
          {action.execution_audit_id ? ` · execution audit #${action.execution_audit_id}` : ''}
          {action.approval_audit_id ? ` · approval audit #${action.approval_audit_id}` : ''}
        </p>
      )}
      {action.result && (
        <pre style={{ marginTop: 8, maxHeight: 140, overflow: 'auto', background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 4, padding: 8, fontSize: '0.62rem', color: 'var(--text-secondary)' }}>
          {JSON.stringify(action.result, null, 2)}
        </pre>
      )}
    </div>
  );
}

export function IncidentsPage() {
  const { user } = useAuth();
  const canRespond = can(user, 'incidents.respond');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<'low' | 'medium' | 'high' | 'critical'>('high');
  const [scanId, setScanId] = useState('');
  const [actionType, setActionType] = useState<ResponseActionType>('quarantine_email');
  const [target, setTarget] = useState('');
  const [reason, setReason] = useState('');

  const refresh = useCallback(async () => {
    const listing = await listIncidents();
    setIncidents(listing.incidents);
    if (selectedId != null) {
      setSelected(await getIncident(selectedId));
    }
  }, [selectedId]);

  useEffect(() => {
    refresh()
      .catch(() => setError('Failed to load incidents'))
      .finally(() => setLoading(false));
  }, [refresh]);

  const select = async (incident: Incident) => {
    setSelectedId(incident.id);
    try {
      setSelected(await getIncident(incident.id));
    } catch {
      setError('Failed to load incident');
    }
  };

  const create = async () => {
    if (!title.trim()) {
      setError('Title is required');
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const incident = await createIncident({
        title: title.trim(),
        description: description || undefined,
        severity,
        scan_id: scanId ? Number(scanId) : undefined,
      });
      setTitle('');
      setDescription('');
      setScanId('');
      setSelectedId(incident.id);
      setSelected(incident);
      setNotice(`Incident #${incident.id} created`);
      await refresh();
    } catch {
      setError('Failed to create incident (check scan ownership and fields)');
    } finally {
      setBusy(false);
    }
  };

  const addAction = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await requestIncidentAction(
        selected.id,
        { action_type: actionType, target: target.trim(), reason: reason || undefined },
        crypto.randomUUID(),
      );
      setTarget('');
      setReason('');
      setNotice('Action requested; approval is required before execution');
      await refresh();
    } catch {
      setError('Failed to request action');
    } finally {
      setBusy(false);
    }
  };

  const transition = async (
    action: ResponseAction,
    operation: 'approve' | 'reject' | 'execute',
  ) => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      if (operation === 'approve') {
        await approveIncidentAction(selected.id, action.id);
        setNotice('Action approved. Execution is still a separate explicit step.');
      } else if (operation === 'reject') {
        await rejectIncidentAction(selected.id, action.id, 'Rejected from incident UI');
        setNotice('Action rejected');
      } else {
        await executeIncidentAction(selected.id, action.id);
        setNotice('Execution recorded as dry run; no mailbox content was modified');
      }
      await refresh();
    } catch {
      setError(`Failed to ${operation} action`);
    } finally {
      setBusy(false);
    }
  };

  const close = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      await closeIncident(selected.id, 'Closed from incident UI');
      setNotice(`Incident #${selected.id} closed`);
      await refresh();
    } catch {
      setError('Failed to close incident');
    } finally {
      setBusy(false);
    }
  };

  const counts = useMemo(() => {
    const open = incidents.filter((item) => ['open', 'pending_approval'].includes(item.status)).length;
    const dry = incidents.filter((item) => item.status === 'dry_run').length;
    return { open, dry };
  }, [incidents]);

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 18, maxWidth: 1400 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <ShieldAlert size={20} style={{ color: 'var(--warning)' }} />
        <div>
          <h1 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)' }}>Incident Response</h1>
          <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: 2 }}>
            Containment is approval-gated. Every transition is audited; execution is an explicit dry run while Gmail remains read-only.
          </p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{counts.open} open · {counts.dry} dry run</span>
          <button onClick={() => refresh()} className="btn-ghost" style={{ fontSize: '0.72rem' }}><RefreshCw size={12} /> Refresh</button>
        </div>
      </div>

      {!canRespond && (
        <div style={{ border: '1px solid var(--border-default)', background: 'var(--bg-input)', borderRadius: 6, padding: '9px 12px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          You can create incidents and request actions, but approving or executing requires <span className="font-mono">incidents.respond</span>.
        </div>
      )}
      {(error || notice) && (
        <div style={{ border: `1px solid ${error ? 'var(--danger)' : 'var(--border-default)'}`, background: error ? 'var(--danger-subtle)' : 'var(--bg-input)', color: error ? 'var(--text-danger)' : 'var(--text-secondary)', borderRadius: 6, padding: '9px 12px', fontSize: '0.76rem', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ flex: 1 }}>{error ?? notice}</span>
          <button onClick={() => { setError(null); setNotice(null); }} style={{ background: 'none', border: 0, color: 'inherit', cursor: 'pointer' }}><X size={13} /></button>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 0.7fr) minmax(420px, 1.3fr)', gap: 18 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18 }}>
            <p style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>New incident</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <Field label="Title"><input value={title} onChange={(e) => setTitle(e.target.value)} className="dark-input" placeholder="Contain confirmed phishing" /></Field>
              <Field label="Description"><textarea value={description} onChange={(e) => setDescription(e.target.value)} className="dark-input" rows={3} /></Field>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <Field label="Severity">
                  <select value={severity} onChange={(e) => setSeverity(e.target.value as typeof severity)} className="dark-input">
                    <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option>
                  </select>
                </Field>
                <Field label="Scan ID (optional)"><input type="number" min={1} value={scanId} onChange={(e) => setScanId(e.target.value)} className="dark-input" /></Field>
              </div>
              <button onClick={create} disabled={busy} className="btn-primary" style={{ marginTop: 4, fontSize: '0.8rem', padding: '8px 12px' }}>
                <FileWarning size={14} /> Create incident
              </button>
            </div>
          </div>

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18 }}>
            <p style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 10 }}>Cases</p>
            {loading && <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>Loading…</p>}
            {!loading && incidents.length === 0 && <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>No incidents yet.</p>}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 380, overflowY: 'auto' }}>
              {incidents.map((incident) => (
                <button
                  key={incident.id}
                  onClick={() => select(incident)}
                  style={{ textAlign: 'left', background: selectedId === incident.id ? 'var(--primary-glow)' : 'var(--bg-input)', border: `1px solid ${selectedId === incident.id ? 'var(--primary)' : 'var(--border-subtle)'}`, borderRadius: 6, padding: '9px 10px', cursor: 'pointer' }}
                >
                  <div style={{ display: 'flex', gap: 7, alignItems: 'center' }}>
                    <span style={{ fontSize: '0.76rem', fontWeight: 700, color: 'var(--text-primary)' }}>#{incident.id} {incident.title}</span>
                    <StatusPill status={incident.status} />
                  </div>
                  <p style={{ fontSize: '0.67rem', color: 'var(--text-muted)', marginTop: 3 }}>
                    {incident.severity} · scan {incident.scan_id ?? '—'} · {incident.created_at ? formatDistanceToNow(new Date(incident.created_at), { addSuffix: true }) : ''}
                  </p>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18 }}>
          {!selected && <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Select a case to review its evidence and response actions.</p>}
          {selected && (
            <>
              <div style={{ display: 'flex', gap: 9, alignItems: 'center', flexWrap: 'wrap' }}>
                <ShieldCheck size={16} style={{ color: 'var(--primary)' }} />
                <p style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>#{selected.id} {selected.title}</p>
                <StatusPill status={selected.status} />
                {selected.scan_id && <span className="font-mono" style={{ fontSize: '0.67rem', color: 'var(--text-muted)' }}>scan {selected.scan_id}</span>}
                {selected.status !== 'closed' && canRespond && (
                  <button onClick={close} disabled={busy} className="btn-ghost" style={{ marginLeft: 'auto', fontSize: '0.7rem' }}><CircleSlash size={12} /> Close case</button>
                )}
              </div>
              {selected.description && <p style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: 8 }}>{selected.description}</p>}
              <p className="font-mono" style={{ fontSize: '0.62rem', color: 'var(--text-muted)', marginTop: 6 }}>
                created audit #{selected.created_audit_id ?? '—'}{selected.closed_audit_id ? ` · close audit #${selected.closed_audit_id}` : ''}
              </p>

              <div style={{ borderTop: '1px solid var(--border-subtle)', marginTop: 14, paddingTop: 14 }}>
                <p style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 9 }}>Response actions</p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {(selected.actions ?? []).map((action) => (
                    <ActionRow
                      key={action.id}
                      action={action}
                      canRespond={canRespond}
                      busy={busy}
                      onApprove={() => transition(action, 'approve')}
                      onReject={() => transition(action, 'reject')}
                      onExecute={() => transition(action, 'execute')}
                    />
                  ))}
                  {(selected.actions ?? []).length === 0 && <p style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>No actions requested.</p>}
                </div>

                {selected.status !== 'closed' && (
                  <div style={{ marginTop: 12, border: '1px solid var(--border-subtle)', borderRadius: 6, padding: 11, background: 'var(--bg-card)' }}>
                    <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>Request action</p>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.1fr', gap: 8 }}>
                      <Field label="Action">
                        <select value={actionType} onChange={(e) => setActionType(e.target.value as ResponseActionType)} className="dark-input">
                          {Object.entries(ACTION_LABEL).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                        </select>
                      </Field>
                      <Field label="Target (message id / address)"><input value={target} onChange={(e) => setTarget(e.target.value)} className="dark-input" placeholder="message-123 or sender@example" /></Field>
                    </div>
                    <div style={{ marginTop: 8 }}>
                      <Field label="Reason"><input value={reason} onChange={(e) => setReason(e.target.value)} className="dark-input" placeholder="Why this containment is needed" /></Field>
                    </div>
                    <button onClick={addAction} disabled={busy || !target.trim()} className="btn-primary" style={{ marginTop: 9, fontSize: '0.75rem', padding: '7px 11px' }}>
                      <ShieldAlert size={13} /> Request approval
                    </button>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
