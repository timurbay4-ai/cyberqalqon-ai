import type { ReactNode } from "react";

import { BackendStatusBanner, type BackendConnection } from "../components/backend-status-banner";
import { BrandMark } from "../components/brand-mark";
import type { AnalystPrincipal } from "../types/auth";

export type PageId = "dashboard" | "alerts" | "incidents";

const navigation: Array<{ id: PageId; label: string; icon: string }> = [
  { id: "dashboard", label: "Overview", icon: "⌁" },
  { id: "alerts", label: "Alerts", icon: "◇" },
  { id: "incidents", label: "Incidents", icon: "▱" },
];

interface AppShellProps {
  activePage: PageId;
  connection: BackendConnection;
  analyst: AnalystPrincipal;
  logoutBusy: boolean;
  logoutError: string | null;
  children: ReactNode;
  onNavigate(page: PageId): void;
  onRetryConnection(): void;
  onLogout(): void;
}

export function AppShell({ activePage, connection, analyst, logoutBusy, logoutError, children, onNavigate, onRetryConnection, onLogout }: AppShellProps) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <BrandMark />
          <div><strong>CyberQalqon</strong><span>Security Operations</span></div>
        </div>
        <nav className="primary-nav" aria-label="Primary navigation">
          <span className="nav-label">Workspace</span>
          {navigation.map((item) => (
            <button
              className={activePage === item.id ? "is-active" : undefined}
              type="button"
              aria-current={activePage === item.id ? "page" : undefined}
              onClick={() => onNavigate(item.id)}
              key={item.id}
            >
              <span className="nav-icon" aria-hidden="true">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar__footer">
          <div className={`connection-dot connection-dot--${connection}`} aria-hidden="true" />
          <div><span>Backend</span><strong>{connection}</strong></div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div><span className="eyebrow">SOC workspace</span><strong>Monitor · Triage · Investigate</strong></div>
          <div className="topbar__status">
            <div className="identity-block"><strong>{analyst.display_name}</strong><span>{analyst.username} · {analyst.role}</span></div>
            <span className="analyst-avatar" aria-label={`Authenticated analyst ${analyst.username}`}>{analyst.display_name.slice(0, 2).toUpperCase()}</span>
            <button className="button button--ghost" disabled={logoutBusy} type="button" onClick={onLogout}>{logoutBusy ? "Signing out…" : "Sign out"}</button>
          </div>
        </header>
        {logoutError && <div className="session-error" role="alert">{logoutError}</div>}
        <BackendStatusBanner status={connection} onRetry={onRetryConnection} />
        <main className="main-content">{children}</main>
      </div>
    </div>
  );
}
