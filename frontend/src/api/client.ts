import axios from 'axios';
import type {
  Email,
  EmailDetail,
  Scan,
  HealthStatus,
  FetchEmailsResponse,
  ScanTriggerResponse,
  Classification,
} from '../types';

// ─── Axios Instance ───────────────────────────────────────────────────────────

export const apiClient = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const resolveApiUrl = (path: string): string =>
  new URL(path, `${apiClient.defaults.baseURL}/`).toString();

export const resolveScreenshotUrl = (
  artifactPath?: string | null,
  storedPath?: string | null,
): string | null => {
  if (artifactPath) return resolveApiUrl(artifactPath);
  if (!storedPath) return null;
  const parts = storedPath.replaceAll('\\', '/').split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const scanId = parts.at(-2);
  const filename = parts.at(-1);
  return resolveApiUrl(`/artifacts/url-screenshots/${scanId}/${filename}`);
};

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
      return Promise.reject(new Error('BACKEND_OFFLINE'));
    }
    // 401 on any protected endpoint → back to the login page.
    // /auth/* 401s are handled by AuthContext / LoginPage themselves.
    if (error.response?.status === 401) {
      const url = String(error.config?.url ?? '');
      if (!url.includes('/auth/') && window.location.pathname !== '/login') {
        window.location.assign('/login');
      }
    }
    return Promise.reject(error);
  }
);

// ─── Health ───────────────────────────────────────────────────────────────────

export const getHealth = async (): Promise<HealthStatus> => {
  const { data } = await apiClient.get<HealthStatus>('/health');
  return data;
};

// ─── Emails ───────────────────────────────────────────────────────────────────

export const getEmails = async (skip = 0, limit = 50): Promise<Email[]> => {
  const { data } = await apiClient.get<{ total: number; emails: Email[] }>('/emails', {
    params: { skip, limit },
  });
  return data.emails ?? [];
};

export const getEmail = async (id: number): Promise<EmailDetail> => {
  const { data } = await apiClient.get<EmailDetail>(`/emails/${id}`);
  return data;
};

export const fetchEmails = async (limit = 20): Promise<FetchEmailsResponse> => {
  const { data } = await apiClient.post<FetchEmailsResponse>(
    `/emails/fetch?limit=${limit}`
  );
  return data;
};

// ─── Scans ────────────────────────────────────────────────────────────────────

export const getScans = async (skip = 0, limit = 50): Promise<Scan[]> => {
  const { data } = await apiClient.get<{ total: number; scans: Scan[] }>('/scans', {
    params: { skip, limit },
  });
  return data.scans ?? [];
};

export const getScan = async (id: number): Promise<Scan> => {
  const { data } = await apiClient.get<Scan>(`/scans/${id}`);
  return data;
};

export const runScan = async (emailId: number): Promise<ScanTriggerResponse> => {
  const { data } = await apiClient.post<ScanTriggerResponse>(`/scans/${emailId}`);
  return data;
};

// ─── Bulk Scan ────────────────────────────────────────────────────────────────

export interface BulkScanResponse {
  status: string;
  total_queued: number;
  scan_ids: number[];
}

export const bulkScan = async (emailIds: number[]): Promise<BulkScanResponse> => {
  const { data } = await apiClient.post<BulkScanResponse>('/emails/bulk-scan', {
    email_ids: emailIds,
  });
  return data;
};

// ─── AI Threat Summary ────────────────────────────────────────────────────────

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  tactic_id: string;
  url: string;
  confidence: 'high' | 'medium' | 'low';
  weight: number;
  evidence: string[];
  sources: string[];
}

export interface ThreatSummary {
  scan_id: number;
  classification: string;
  final_score: number;
  summary: string;
  key_findings: string[];
  risk_factors: { engine: string; severity: string; detail: string }[];
  techniques: AttackTechnique[];
}

export const getThreatSummary = async (scanId: number): Promise<ThreatSummary> => {
  const { data } = await apiClient.get<ThreatSummary>(`/scans/${scanId}/summary`);
  return data;
};

// ─── Extended findings + conversation (Phase 1) ──────────────────────────────

export interface FindingEvidence {
  kind: string;
  value: string;
  source: string | null;
  artifact_sha256: string | null;
  metadata: Record<string, unknown>;
}

export interface ScanFinding {
  id: number;
  scan_id: number;
  analyzer: string;
  analyzer_version: string;
  ruleset_version: string;
  category: string;
  code: string;
  title: string;
  severity: number;
  confidence: number;
  evidence_hash: string;
  evidence: FindingEvidence[];
  details: Record<string, unknown>;
  created_at: string | null;
}

export interface ConversationMetadata {
  shadow: boolean;
  status: string;
  score: number;
  finding_count: number;
  prior_messages: number;
  thread_key: string;
  normalized_subject: string;
  codes: string[];
}

export interface ScanFindingsResponse {
  scan_id: number;
  count: number;
  findings: ScanFinding[];
  conversation: ConversationMetadata | null;
}

export interface ThreadMessage {
  email_id: number;
  message_id: string;
  sender: string;
  subject: string;
  date: string | null;
  in_reply_to: string | null;
  has_attachments: boolean;
  is_current: boolean;
}

export interface ScanThreadResponse {
  scan_id: number;
  thread_key: string;
  normalized_subject: string;
  count: number;
  messages: ThreadMessage[];
  findings: ScanFinding[];
}

export const getScanFindings = async (
  scanId: number,
  category?: string,
): Promise<ScanFindingsResponse> => {
  const { data } = await apiClient.get<ScanFindingsResponse>(`/scans/${scanId}/findings`, {
    params: category ? { category } : {},
  });
  return data;
};

export const getScanThread = async (scanId: number): Promise<ScanThreadResponse> => {
  const { data } = await apiClient.get<ScanThreadResponse>(`/scans/${scanId}/thread`);
  return data;
};

// ─── Retroactive hunts (Phase 5) ─────────────────────────────────────────────

export interface HuntCreateInput {
  since?: string;
  until?: string;
  classification?: 'safe' | 'suspicious' | 'dangerous';
  sender_domain?: string;
  subject_contains?: string;
  analyzers: string[];
  max_scans: number;
  run_now: boolean;
}

export interface HuntJob {
  id: number;
  kind: string;
  status: string;
  progress: number;
  total: number;
  message: string | null;
  attempts: number;
  max_attempts: number;
  cancel_requested: boolean;
  error: string | null;
  result: HuntResult | null;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface HuntResultFinding {
  id: number;
  scan_id: number;
  analyzer: string;
  category: string;
  code: string;
  title: string;
  severity: number;
  confidence: number;
  evidence: FindingEvidence[];
}

export interface HuntResult {
  hunt: Record<string, unknown>;
  analyzers: string[];
  scans_matched: number;
  scans_scanned: number;
  scans_with_findings: number;
  new_finding_count: number;
  new_by_analyzer: Record<string, number>;
  new_by_code: Record<string, number>;
  scan_ids_with_findings: number[];
  top_findings: HuntResultFinding[];
  top_findings_truncated: boolean;
  completed_at: string;
}

export interface HuntListResponse {
  count: number;
  total: number;
  hunts: HuntJob[];
}

export const createHunt = async (
  input: HuntCreateInput,
  idempotencyKey?: string,
): Promise<{ hunt_id: number; status: string; progress: number; total: number }> => {
  const { data } = await apiClient.post('/hunts', input, {
    headers: idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {},
  });
  return data;
};

export const listHunts = async (): Promise<HuntListResponse> => {
  const { data } = await apiClient.get<HuntListResponse>('/hunts');
  return data;
};

export const getHunt = async (huntId: number): Promise<HuntJob> => {
  const { data } = await apiClient.get<HuntJob>(`/hunts/${huntId}`);
  return data;
};

export const getHuntResults = async (
  huntId: number,
): Promise<{ hunt_id: number; status: string; result: HuntResult | null; error: string | null }> => {
  const { data } = await apiClient.get(`/hunts/${huntId}/results`);
  return data;
};

export const cancelHunt = async (huntId: number): Promise<HuntJob> => {
  const { data } = await apiClient.post<HuntJob>(`/hunts/${huntId}/cancel`);
  return data;
};

export const runHunt = async (huntId: number): Promise<{ hunt_id: number; scheduled: boolean }> => {
  const { data } = await apiClient.post(`/hunts/${huntId}/run`);
  return data;
};

// ─── Incidents / approval-gated response (Phase 6) ───────────────────────────

export type IncidentStatus =
  | 'open'
  | 'pending_approval'
  | 'dry_run'
  | 'contained'
  | 'closed';

export type ResponseActionType =
  | 'quarantine_email'
  | 'block_sender'
  | 'disable_account'
  | 'notify_user';

export type ResponseActionStatus =
  | 'pending_approval'
  | 'approved'
  | 'rejected'
  | 'executing'
  | 'dry_run'
  | 'executed'
  | 'failed'
  | 'cancelled';

export interface ResponseAction {
  id: number;
  incident_id: number;
  user_id: number;
  action_type: ResponseActionType;
  target: string;
  reason: string | null;
  status: ResponseActionStatus;
  requested_by: number | null;
  approved_by: number | null;
  rejected_by: number | null;
  approved_at: string | null;
  rejected_at: string | null;
  executed_at: string | null;
  execution_mode: string | null;
  result: Record<string, unknown> | null;
  dedupe_key: string | null;
  created_at: string | null;
  request_audit_id: number | null;
  approval_audit_id: number | null;
  rejection_audit_id: number | null;
  execution_audit_id: number | null;
  evidence_id: number | null;
}

export interface Incident {
  id: number;
  user_id: number;
  scan_id: number | null;
  email_id: number | null;
  title: string;
  description: string | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: IncidentStatus;
  created_by: number | null;
  created_at: string | null;
  updated_at: string | null;
  closed_at: string | null;
  closed_by: number | null;
  created_audit_id: number | null;
  closed_audit_id: number | null;
  url: string;
  actions?: ResponseAction[];
}

export interface IncidentListResponse {
  count: number;
  total: number;
  incidents: Incident[];
}

export const createIncident = async (input: {
  title: string;
  description?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  scan_id?: number;
  email_id?: number;
}): Promise<Incident> => {
  const { data } = await apiClient.post<Incident>('/incidents', input);
  return data;
};

export const listIncidents = async (status?: string): Promise<IncidentListResponse> => {
  const { data } = await apiClient.get<IncidentListResponse>('/incidents', {
    params: status ? { status } : {},
  });
  return data;
};

export const getIncident = async (incidentId: number): Promise<Incident> => {
  const { data } = await apiClient.get<Incident>(`/incidents/${incidentId}`);
  return data;
};

export const requestIncidentAction = async (
  incidentId: number,
  input: { action_type: ResponseActionType; target: string; reason?: string },
  idempotencyKey?: string,
): Promise<ResponseAction> => {
  const { data } = await apiClient.post<ResponseAction>(
    `/incidents/${incidentId}/actions`,
    input,
    { headers: idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {} },
  );
  return data;
};

export const approveIncidentAction = async (
  incidentId: number,
  actionId: number,
): Promise<ResponseAction> => {
  const { data } = await apiClient.post<ResponseAction>(
    `/incidents/${incidentId}/actions/${actionId}/approve`,
  );
  return data;
};

export const rejectIncidentAction = async (
  incidentId: number,
  actionId: number,
  reason?: string,
): Promise<ResponseAction> => {
  const { data } = await apiClient.post<ResponseAction>(
    `/incidents/${incidentId}/actions/${actionId}/reject`,
    { reason },
  );
  return data;
};

export const executeIncidentAction = async (
  incidentId: number,
  actionId: number,
): Promise<ResponseAction> => {
  const { data } = await apiClient.post<ResponseAction>(
    `/incidents/${incidentId}/actions/${actionId}/execute`,
  );
  return data;
};

export const closeIncident = async (
  incidentId: number,
  reason?: string,
): Promise<Incident> => {
  const { data } = await apiClient.post<Incident>(`/incidents/${incidentId}/close`, {
    reason,
  });
  return data;
};

// ─── Detection coverage / global findings (Phase 7) ──────────────────────────

export interface DetectionFinding {
  id: number;
  scan_id: number;
  email_id: number;
  analyzer: string;
  analyzer_version: string;
  ruleset_version: string;
  category: string;
  code: string;
  title: string;
  severity: number;
  confidence: number;
  evidence_hash: string;
  evidence: Array<{ kind: string; value: string; [key: string]: unknown }>;
  details: Record<string, unknown>;
  subject: string;
  sender: string;
  url: string;
  created_at: string | null;
}

export interface DetectionSummary {
  window_days: number;
  generated_at: string;
  totals: {
    findings: number;
    scans_with_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  analyzers: Array<{ analyzer: string; findings: number; scans: number; max_severity: number }>;
  categories: Array<{ category: string; findings: number; max_severity: number }>;
  top_codes: Array<{ code: string; analyzer: string; findings: number; max_severity: number }>;
  recent_high: DetectionFinding[];
}

export interface FindingsResponse {
  count: number;
  total: number;
  offset: number;
  limit: number;
  findings: DetectionFinding[];
}

export const getFindings = async (params: {
  analyzer?: string;
  category?: string;
  code?: string;
  min_severity?: number;
  scan_id?: number;
  limit?: number;
  offset?: number;
}): Promise<FindingsResponse> => {
  const { data } = await apiClient.get<FindingsResponse>('/findings', { params });
  return data;
};

export const getDetectionSummary = async (days = 30): Promise<DetectionSummary> => {
  const { data } = await apiClient.get<DetectionSummary>('/detection/summary', {
    params: { days },
  });
  return data;
};

// ─── Attachments ──────────────────────────────────────────────────────────────

export interface AttachmentSummary {
  id: number;
  email_id: number;
  filename: string;
  content_type: string | null;
  size_bytes: number;
  sha256_hash: string | null;
  email_subject: string;
  email_sender: string;
  latest_scan_score: number | null;
  latest_classification: Classification | null;
}

export interface AttachmentDetail extends AttachmentSummary {
  storage_path: string | null;
  email_date: string | null;
  scan_results: Array<{
    scan_id: number;
    scan_status: string;
    final_score: number;
    classification: string;
    file_analysis: Record<string, unknown>;
  }>;
}

export const getAttachments = async (skip = 0, limit = 50): Promise<AttachmentSummary[]> => {
  const { data } = await apiClient.get<{ total: number; attachments: AttachmentSummary[] }>('/attachments', {
    params: { skip, limit },
  });
  return data.attachments ?? [];
};

export const getAttachmentDetail = async (id: number): Promise<AttachmentDetail> => {
  const { data } = await apiClient.get<AttachmentDetail>(`/attachments/${id}`);
  return data;
};

// ─── Export ───────────────────────────────────────────────────────────────────

export const exportScansCsv = async (classification?: string): Promise<void> => {
  const params = classification ? { classification } : {};
  const { data } = await apiClient.get('/scans/export/csv', {
    params,
    responseType: 'blob',
  });
  const url = window.URL.createObjectURL(new Blob([data]));
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', 'phishing_guard_scans.csv');
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
};

// ─── Backend status check ─────────────────────────────────────────────────────

export const checkBackendOnline = async (): Promise<boolean> => {
  try {
    await apiClient.get('/health', { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
};
