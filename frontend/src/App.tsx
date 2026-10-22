import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { Dashboard } from './pages/Dashboard';
import { EmailInbox } from './pages/EmailInbox';
import { ScanResults } from './pages/ScanResults';
import { ScanDetail } from './pages/ScanDetail';
import { HealthPage } from './pages/HealthPage';
import { ActiveScans } from './pages/ActiveScans';
import { UrlAnalysis } from './pages/UrlAnalysis';
import { AttachmentsPage } from './pages/AttachmentsPage';
import { SettingsPage } from './pages/SettingsPage';
import { TracePage } from './pages/TracePage';
import { ReportPage } from './pages/ReportPage';
import { GraphPage } from './pages/GraphPage';
import { CampaignsPage } from './pages/CampaignsPage';
import { AlertsPage } from './pages/AlertsPage';
import { LoginPage } from './pages/LoginPage';
import { UsersPage } from './pages/UsersPage';
import { CompliancePage } from './pages/CompliancePage';
import { HuntsPage } from './pages/HuntsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { DetectionPage } from './pages/DetectionPage';
import { SystemHealthProvider } from './hooks/useSystemHealth';
import { AuthProvider, useAuth } from './auth/AuthContext';
import { RequirePermission } from './auth/RequirePermission';
import { ShieldCheck } from 'lucide-react';

function ProtectedLayout() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          gap: 14,
          alignItems: 'center',
          justifyContent: 'center',
          background: 'var(--login-bg)',
        }}
      >
        <div
          style={{
            width: 52,
            height: 52,
            borderRadius: 15,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'var(--brand-tile-bg)',
            border: '1px solid var(--brand-tile-border)',
            boxShadow: 'var(--shadow-raised)',
          }}
        >
          <ShieldCheck size={26} style={{ color: 'var(--primary)' }} />
        </div>
        <span style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>
          Loading Phishing-Guard 2.0…
        </span>
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;
  return <Layout />;
}

export default function App() {
  return (
    <SystemHealthProvider>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/" element={<ProtectedLayout />}>
              <Route index element={<Dashboard />} />
              <Route path="emails" element={<EmailInbox />} />
              <Route path="active-scans" element={<ActiveScans />} />
              <Route path="scans" element={<ScanResults />} />
              <Route path="scans/:id" element={<ScanDetail />} />
              <Route path="scans/:id/report" element={<ReportPage />} />
              <Route path="emails/:id/trace" element={<TracePage />} />
              <Route path="graph" element={<GraphPage />} />
              <Route path="campaigns" element={<CampaignsPage />} />
              <Route path="campaigns/:id" element={<CampaignsPage />} />
              <Route path="alerts" element={<AlertsPage />} />
              <Route path="url-analysis" element={<UrlAnalysis />} />
              <Route path="attachments" element={<AttachmentsPage />} />
              <Route path="compliance" element={<CompliancePage />} />
              <Route path="hunts" element={<HuntsPage />} />
              <Route path="incidents" element={<IncidentsPage />} />
              <Route path="detection" element={<DetectionPage />} />
              <Route path="system-health" element={
                <RequirePermission permission="system.health"><HealthPage /></RequirePermission>
              } />
              <Route path="settings" element={
                <RequirePermission permission="system.settings"><SettingsPage /></RequirePermission>
              } />
              <Route path="users" element={
                <RequirePermission permission="users.manage"><UsersPage /></RequirePermission>
              } />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </SystemHealthProvider>
  );
}
