import { useCallback, useEffect, useState } from "react";

import { backendApi } from "./api/client";
import { ApiError } from "./api/client";
import type { BackendConnection } from "./components/backend-status-banner";
import { LoginPage } from "./components/login-page";
import { AppShell, type PageId } from "./layouts/app-shell";
import { AlertsPage } from "./pages/alerts-page";
import { DashboardPage } from "./pages/dashboard-page";
import { IncidentsPage } from "./pages/incidents-page";
import type { BackendApi } from "./types/api";
import type { AnalystPrincipal, LoginCredentials } from "./types/auth";

export function App({ api = backendApi }: { api?: BackendApi }) {
  const [activePage, setActivePage] = useState<PageId>("dashboard");
  const [connection, setConnection] = useState<BackendConnection>("checking");
  const [analyst, setAnalyst] = useState<AnalystPrincipal | null>(null);
  const [authChecking, setAuthChecking] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authRevision, setAuthRevision] = useState(0);
  const [loginBusy, setLoginBusy] = useState(false);
  const [logoutBusy, setLogoutBusy] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);

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

  if (!analyst) {
    return <LoginPage busy={loginBusy} checking={authChecking} error={authError} onLogin={login} onRetry={retryConnection} />;
  }

  let page;
  if (activePage === "dashboard") page = <DashboardPage api={api} />;
  else if (activePage === "alerts") page = <AlertsPage api={api} />;
  else page = <IncidentsPage api={api} canMutate={analyst.permissions.includes("incident:write")} />;

  return (
    <AppShell
      activePage={activePage}
      connection={connection}
      analyst={analyst}
      logoutBusy={logoutBusy}
      logoutError={logoutError}
      onNavigate={setActivePage}
      onRetryConnection={retryConnection}
      onLogout={() => { void logout(); }}
    >
      {page}
    </AppShell>
  );
}
