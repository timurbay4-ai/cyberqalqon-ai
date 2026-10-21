import { Component, lazy, Suspense, useCallback, useEffect, useState, type ErrorInfo, type ReactNode } from "react";

import { backendApi } from "./api/client";
import { ApiError } from "./api/client";
import type { BackendConnection } from "./components/backend-status-banner";
import { LoginPage } from "./components/login-page";
import { AppShell, type NavigationDetail, type PageId } from "./layouts/app-shell";
import type { BackendApi } from "./types/api";
import type { AnalystPrincipal, LoginCredentials } from "./types/auth";
import { DEFAULT_PREFERENCES, type AnalystPreferences } from "./types/preferences";
import type { WorkbenchTarget } from "./types/investigation-workbench";

const DashboardPage = lazy(() => import("./pages/dashboard-page").then((module) => ({ default: module.DashboardPage })));
const OperationsPage = lazy(() => import("./pages/operations-page").then((module) => ({ default: module.OperationsPage })));
const DiscoverPage = lazy(() => import("./pages/discover-page").then((module) => ({ default: module.DiscoverPage })));
const InvestigationWorkbenchPage = lazy(() => import("./pages/investigation-workbench-page").then((module) => ({ default: module.InvestigationWorkbenchPage })));
const ThreatHuntingPage = lazy(() => import("./pages/threat-hunting-page").then((module) => ({ default: module.ThreatHuntingPage })));
const AlertsPage = lazy(() => import("./pages/alerts-page").then((module) => ({ default: module.AlertsPage })));
const IncidentsPage = lazy(() => import("./pages/incidents-page").then((module) => ({ default: module.IncidentsPage })));
const CasesPage = lazy(() => import("./pages/cases-page").then((module) => ({ default: module.CasesPage })));
const HostsPage = lazy(() => import("./pages/hosts-page").then((module) => ({ default: module.HostsPage })));
const DetectionEngineeringPage = lazy(() => import("./pages/detection-engineering-page").then((module) => ({ default: module.DetectionEngineeringPage })));
const ThreatIntelligencePage = lazy(() => import("./pages/threat-intelligence-page").then((module) => ({ default: module.ThreatIntelligencePage })));
const ReportsPage = lazy(() => import("./pages/reports-page").then((module) => ({ default: module.ReportsPage })));
const AdministrationPage = lazy(() => import("./pages/administration-page").then((module) => ({ default: module.AdministrationPage })));

class PageErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(_error: Error, _info: ErrorInfo) {
    // Render a bounded recovery state. Detailed errors remain in local browser
    // diagnostics and are never copied into the analyst-facing page.
  }

  render() {
    if (this.state.failed) {
      return <section className="state-panel state-panel--error" role="alert"><h2>Workspace view unavailable</h2><p>The selected page could not be loaded. No data was changed.</p><button className="button button--secondary" type="button" onClick={() => window.location.reload()}>Reload workspace</button></section>;
    }
    return this.props.children;
  }
}

const PAGE_IDS: PageId[] = ["dashboard", "operations", "discover", "investigate", "hunting", "alerts", "incidents", "cases", "hosts", "rules", "intelligence", "reports", "administration"];

function locationState(): { page: PageId; alertId: string | null; incidentId: string | null; caseId: string | null; eventId: string | null; ruleId: string | null; workbench: WorkbenchTarget | null } {
  const parameters = new URLSearchParams(window.location.search);
  const candidate = parameters.get("view") as PageId | null;
  const page = candidate && PAGE_IDS.includes(candidate) ? candidate : "dashboard";
  const savedTarget = (window.history.state as { cyberqalqonWorkbench?: WorkbenchTarget } | null)?.cyberqalqonWorkbench;
  const eventId = parameters.get("event");
  return {
    page,
    alertId: parameters.get("alert"),
    incidentId: parameters.get("incident"),
    caseId: parameters.get("case"),
    eventId,
    ruleId: parameters.get("rule_id"),
    workbench: page === "investigate" ? (savedTarget ?? (eventId ? { target_type: "EVENT", target_id: eventId, relative_minutes: 10080, related_limit: 50, timeline_limit: 150, sort: "oldest" } : null)) : null,
  };
}

export function App({ api = backendApi }: { api?: BackendApi }) {
  const initialLocation = locationState();
  const [activePage, setActivePage] = useState<PageId>(initialLocation.page);
  const [connection, setConnection] = useState<BackendConnection>("checking");
  const [analyst, setAnalyst] = useState<AnalystPrincipal | null>(null);
  const [authChecking, setAuthChecking] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authRevision, setAuthRevision] = useState(0);
  const [loginBusy, setLoginBusy] = useState(false);
  const [logoutBusy, setLogoutBusy] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const [openAlertId, setOpenAlertId] = useState<string | null>(initialLocation.alertId);
  const [openIncidentId, setOpenIncidentId] = useState<string | null>(initialLocation.incidentId);
  const [openCaseId, setOpenCaseId] = useState<string | null>(initialLocation.caseId);
  const [openEventId, setOpenEventId] = useState<string | null>(initialLocation.eventId);
  const [openAlertRuleId, setOpenAlertRuleId] = useState<string | null>(initialLocation.ruleId);
  const [workbenchTarget, setWorkbenchTarget] = useState<WorkbenchTarget | null>(initialLocation.workbench);
  const [preferences, setPreferences] = useState<AnalystPreferences>(DEFAULT_PREFERENCES);

  const retryConnection = useCallback(() => setAuthRevision((revision) => revision + 1), []);

  useEffect(() => {
    return api.subscribeUnauthorized(() => {
      setAnalyst(null);
      setConnection("connected");
      setAuthChecking(false);
      setAuthError("Your analyst session expired. Sign in again.");
    });
  }, [api]);

  useEffect(() => {
    const restore = () => {
      const next = locationState();
      setActivePage(next.page);
      setOpenAlertId(next.alertId);
      setOpenIncidentId(next.incidentId);
      setOpenCaseId(next.caseId);
      setOpenEventId(next.eventId);
      setOpenAlertRuleId(next.ruleId);
      setWorkbenchTarget(next.workbench);
    };
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setConnection("checking");
    setAuthChecking(true);
    setAuthError(null);
    api.getSession(controller.signal)
      .then((session) => {
        if (!active) return;
        setAnalyst(session.analyst);
        setConnection("connected");
      })
      .catch((error: unknown) => {
        if (!active || (error instanceof DOMException && error.name === "AbortError")) return;
        setAnalyst(null);
        if (error instanceof ApiError && error.status === 401) {
          setConnection("connected");
        } else {
          setConnection("unavailable");
          setAuthError(error instanceof Error ? error.message : "Authentication service unavailable.");
        }
      })
      .finally(() => { if (active) setAuthChecking(false); });
    return () => { active = false; controller.abort(); };
  }, [api, authRevision]);

  useEffect(() => {
    if (!analyst) { setPreferences(DEFAULT_PREFERENCES); return; }
    const controller = new AbortController();
    api.getPreferences(controller.signal).then(setPreferences).catch(() => setPreferences(DEFAULT_PREFERENCES));
    return () => controller.abort();
  }, [api, analyst]);

  const login = async (credentials: LoginCredentials) => {
    setLoginBusy(true);
    setAuthError(null);
    try {
      const session = await api.login(credentials);
      setAnalyst(session.analyst);
      setConnection("connected");
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Sign in failed.");
    } finally {
      setLoginBusy(false);
    }
  };

  const logout = async () => {
    setLogoutBusy(true);
    setLogoutError(null);
    try {
      await api.logout();
      setAnalyst(null);
      setAuthError(null);
    } catch (error) {
      setLogoutError(error instanceof Error ? error.message : "Sign out failed.");
    } finally {
      setLogoutBusy(false);
    }
  };

  const navigate = useCallback((page: PageId, detail?: NavigationDetail) => {
    const url = new URL(window.location.href);
    url.search = "";
    if (page !== "dashboard") url.searchParams.set("view", page);
    if (detail?.alert) url.searchParams.set("alert", detail.alert);
    if (detail?.incident) url.searchParams.set("incident", detail.incident);
    if (detail?.case) url.searchParams.set("case", detail.case);
    const safeEventId = detail?.event ?? (detail?.workbench?.target_type === "EVENT" ? detail.workbench.target_id : undefined);
    if (safeEventId) url.searchParams.set("event", safeEventId);
    if (detail?.ruleId) url.searchParams.set("rule_id", detail.ruleId);
    const state = detail?.workbench ? { cyberqalqonWorkbench: detail.workbench } : {};
    window.history.pushState(state, "", url);
    setActivePage(page);
    setOpenAlertId(detail?.alert ?? null);
    setOpenIncidentId(detail?.incident ?? null);
    setOpenCaseId(detail?.case ?? null);
    setOpenEventId(detail?.event ?? null);
    setOpenAlertRuleId(detail?.ruleId ?? null);
    setWorkbenchTarget(detail?.workbench ?? null);
  }, []);

  if (!analyst) {
    return <LoginPage busy={loginBusy} checking={authChecking} error={authError} onLogin={login} onRetry={retryConnection} />;
  }

  let page;
  const openAlert = (alertId: string) => navigate("alerts", { alert: alertId });
  const openIncident = (incidentId: string) => navigate("incidents", { incident: incidentId });
  const openCase = (caseId: string) => navigate("cases", { case: caseId });
  const openEvent = (eventId: string) => navigate("discover", { event: eventId });
  const investigate = (target: WorkbenchTarget) => navigate("investigate", { workbench: target });
  if (activePage === "dashboard") page = <DashboardPage api={api} initialRange={preferences.dashboard_range} onOpenAlert={openAlert} onNavigate={navigate} />;
  else if (activePage === "operations") page = <OperationsPage api={api} onNavigate={navigate} />;
  else if (activePage === "discover") page = <DiscoverPage api={api} preferences={preferences} onPreferencesChange={setPreferences} openEventId={openEventId} onOpenAlert={openAlert} onOpenIncident={openIncident} onOpenCase={openCase} onInvestigate={(eventId) => investigate({ target_type: "EVENT", target_id: eventId, relative_minutes: 10080, related_limit: 50, timeline_limit: 150, sort: "oldest" })} />;
  else if (activePage === "investigate") page = <InvestigationWorkbenchPage api={api} target={workbenchTarget} canMutate={analyst.permissions.includes("incident:write")} onTargetChange={investigate} onOpenEvent={openEvent} onOpenAlert={openAlert} onOpenIncident={openIncident} onOpenCase={openCase} onOpenRule={(ruleId) => navigate("rules", { ruleId })} onReturn={() => window.history.back()} />;
  else if (activePage === "alerts") page = <AlertsPage api={api} initialPageSize={preferences.alert_page_size} initialSort={preferences.alert_default_sort} openAlertId={openAlertId} initialRuleId={openAlertRuleId} canMutate={analyst.permissions.includes("alert:write")} onOpenEvent={openEvent} />;
  else if (activePage === "incidents") page = <IncidentsPage api={api} initialPageSize={preferences.incident_page_size} openIncidentId={openIncidentId} onOpenAlert={openAlert} onOpenEvent={openEvent} canMutate={analyst.permissions.includes("incident:write")} />;
  else if (activePage === "cases") page = <CasesPage api={api} canMutate={analyst.permissions.includes("incident:write")} openCaseId={openCaseId} onOpenAlert={openAlert} onOpenIncident={openIncident} onOpenEvent={openEvent} />;
  else if (activePage === "hosts") page = <HostsPage api={api} />;
  else if (activePage === "hunting") page = <ThreatHuntingPage api={api} canMutate={analyst.permissions.includes("alert:write")} onOpenEvent={openEvent} onOpenAlert={openAlert} onOpenIncident={openIncident} />;
  else if (activePage === "rules") page = <DetectionEngineeringPage api={api} canMutate={analyst.permissions.includes("alert:write")} initialRuleId={openAlertRuleId} onOpenAlerts={(ruleId) => navigate("alerts", { ruleId })} onOpenEvent={openEvent} onInvestigateFinding={(ruleId, findingKey, startTime, endTime) => investigate({ target_type: "M11_FINDING", rule_id: ruleId, finding_key: findingKey, start_time: startTime, end_time: endTime, relative_minutes: null, related_limit: 50, timeline_limit: 150, sort: "oldest" })} />;
  else if (activePage === "intelligence") page = <ThreatIntelligencePage api={api} canMutate={analyst.permissions.includes("alert:write")} onOpenEvent={openEvent} />;
  else if (activePage === "reports") page = <ReportsPage api={api} />;
  else page = <AdministrationPage api={api} analyst={analyst} preferences={preferences} onPreferencesChange={setPreferences} />;

  return (
    <AppShell
      activePage={activePage}
      api={api}
      connection={connection}
      analyst={analyst}
      logoutBusy={logoutBusy}
      logoutError={logoutError}
      onNavigate={navigate}
      onRetryConnection={retryConnection}
      onLogout={() => { void logout(); }}
    >
      <PageErrorBoundary key={activePage}>
        <Suspense fallback={<section className="panel page-loading" role="status" aria-live="polite"><p>Loading workspace…</p></section>}>
          {page}
        </Suspense>
      </PageErrorBoundary>
    </AppShell>
  );
}
