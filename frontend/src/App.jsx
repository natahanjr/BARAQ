import { lazy, Suspense, useEffect, useState, useCallback, memo, Component } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router";
import { ThemeProvider } from "./context/ThemeContext.jsx";
import { AuthProvider, useAuth } from "./context/AuthContext.jsx";
import { ToastProvider } from "./components/ui/Toast.jsx";
import Layout from "./components/layout/Layout.jsx";
import Login from "./pages/Login.jsx";

// Lazy-loaded pages
const Dashboard = lazy(() => import("./components/minimalist/AppleDashboard.jsx"));
const Alerts = lazy(() => import("./pages/Alerts.jsx"));
const AlertDetail = lazy(() => import("./pages/AlertDetail.jsx"));
const Investigation = lazy(() => import("./pages/Investigation.jsx"));
const Telemetry = lazy(() => import("./pages/Telemetry.jsx"));
const NetworkAnalyzer = lazy(() => import("./pages/NetworkAnalyzer.jsx"));
const Assistant = lazy(() => import("./pages/Assistant.jsx"));
const Reports = lazy(() => import("./pages/Reports.jsx"));
const Evaluation = lazy(() => import("./pages/Evaluation.jsx"));
const Incidents = lazy(() => import("./pages/Incidents.jsx"));
const Automation = lazy(() => import("./pages/Automation.jsx"));
const Dashboards = lazy(() => import("./pages/Dashboards.jsx"));
const Endpoints = lazy(() => import("./pages/Endpoints.jsx"));
const AgentSetup = lazy(() => import("./pages/AgentSetup.jsx"));
const Users = lazy(() => import("./pages/Users.jsx"));
const Settings = lazy(() => import("./pages/Settings.jsx"));

// New pages
const DetectionRules = lazy(() => import("./pages/DetectionRules.jsx"));
const MITREAttack = lazy(() => import("./pages/MITREAttack.jsx"));
const MLDetection = lazy(() => import("./pages/MLDetection.jsx"));
const ThreatIntelligence = lazy(() => import("./pages/ThreatIntelligence.jsx"));
const DataExport = lazy(() => import("./pages/DataExport.jsx"));

// V0.9-V1.4 new pages
const Bookmarks = lazy(() => import("./pages/Bookmarks.jsx"));
const ApprovalWorkflow = lazy(() => import("./pages/ApprovalWorkflow.jsx"));
const ComplianceGap = lazy(() => import("./pages/ComplianceGap.jsx"));
const AttackPath = lazy(() => import("./pages/AttackPath.jsx"));
const UEBA = lazy(() => import("./pages/UEBA.jsx"));
const InsiderThreat = lazy(() => import("./pages/InsiderThreat.jsx"));
const FleetConfig = lazy(() => import("./pages/FleetConfig.jsx"));
const MitreGapReport = lazy(() => import("./pages/MitreGapReport.jsx"));

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, info) {
    console.error("ErrorBoundary caught:", error, info);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-screen items-center justify-center bg-[var(--bg-primary)]">
          <div className="max-w-md rounded-lg border border-[var(--border-default)] bg-[var(--bg-secondary)] p-8 text-center">
            <h2 className="mb-2 text-lg font-semibold text-[var(--fg-primary)]">Something went wrong</h2>
            <p className="mb-4 text-sm text-[var(--fg-muted)]">{this.state.error?.message}</p>
            <button
              onClick={() => { this.setState({ hasError: false, error: null }); window.location.reload(); }}
              className="rounded bg-[var(--accent-cyan)] px-4 py-2 text-sm font-medium text-white hover:opacity-90"
            >Reload page</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function Loading() {
  return (
    <div className="flex h-[50vh] items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--border-default)] border-t-[var(--accent-cyan)]" />
        <span className="text-[12px] text-[var(--fg-muted)]">Loading...</span>
      </div>
    </div>
  );
}

function AppRoutes() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Login />;
  }

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Suspense fallback={<Loading />}><Dashboard /></Suspense>} />
        <Route path="alerts" element={<Suspense fallback={<Loading />}><Alerts /></Suspense>} />
        <Route path="alerts/:id" element={<Suspense fallback={<Loading />}><AlertDetail /></Suspense>} />
        <Route path="incidents" element={<Suspense fallback={<Loading />}><Incidents /></Suspense>} />
        <Route path="investigation" element={<Suspense fallback={<Loading />}><Investigation /></Suspense>} />
        <Route path="detection-rules" element={<Suspense fallback={<Loading />}><DetectionRules /></Suspense>} />
        <Route path="mitre" element={<Suspense fallback={<Loading />}><MITREAttack /></Suspense>} />
        <Route path="ml-detection" element={<Suspense fallback={<Loading />}><MLDetection /></Suspense>} />
        <Route path="evaluation" element={<Suspense fallback={<Loading />}><Evaluation /></Suspense>} />
        <Route path="network" element={<Suspense fallback={<Loading />}><NetworkAnalyzer /></Suspense>} />
        <Route path="threat-intel" element={<Suspense fallback={<Loading />}><ThreatIntelligence /></Suspense>} />
        <Route path="assistant" element={<Suspense fallback={<Loading />}><Assistant /></Suspense>} />
        <Route path="automation" element={<Suspense fallback={<Loading />}><Automation /></Suspense>} />
        <Route path="dashboards" element={<Suspense fallback={<Loading />}><Dashboards /></Suspense>} />
        <Route path="reports" element={<Suspense fallback={<Loading />}><Reports /></Suspense>} />
        <Route path="endpoints" element={<Suspense fallback={<Loading />}><Endpoints /></Suspense>} />
        <Route path="telemetry" element={<Suspense fallback={<Loading />}><Telemetry /></Suspense>} />
        <Route path="export" element={<Suspense fallback={<Loading />}><DataExport /></Suspense>} />
        <Route path="users" element={<Suspense fallback={<Loading />}><Users /></Suspense>} />
        <Route path="settings" element={<Suspense fallback={<Loading />}><Settings /></Suspense>} />
        <Route path="agent-setup" element={<Suspense fallback={<Loading />}><AgentSetup /></Suspense>} />
        <Route path="bookmarks" element={<Suspense fallback={<Loading />}><Bookmarks /></Suspense>} />
        <Route path="approval" element={<Suspense fallback={<Loading />}><ApprovalWorkflow /></Suspense>} />
        <Route path="compliance-gap" element={<Suspense fallback={<Loading />}><ComplianceGap /></Suspense>} />
        <Route path="attack-path" element={<Suspense fallback={<Loading />}><AttackPath /></Suspense>} />
        <Route path="ueba" element={<Suspense fallback={<Loading />}><UEBA /></Suspense>} />
        <Route path="insider-threat" element={<Suspense fallback={<Loading />}><InsiderThreat /></Suspense>} />
        <Route path="fleet-config" element={<Suspense fallback={<Loading />}><FleetConfig /></Suspense>} />
        <Route path="mitre-gap" element={<Suspense fallback={<Loading />}><MitreGapReport /></Suspense>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          <AppRoutes />
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default memo(App);