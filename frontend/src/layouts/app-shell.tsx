import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

import { BackendStatusBanner, type BackendConnection } from "../components/backend-status-banner";
import { BrandMark } from "../components/brand-mark";
import type { AnalystPrincipal } from "../types/auth";
import type { BackendApi } from "../types/api";
import { NotificationCenter } from "../components/notification-center";

export type PageId = "dashboard" | "operations" | "discover" | "hunting" | "alerts" | "incidents" | "cases" | "hosts" | "rules" | "intelligence" | "reports" | "administration";

const navigation: Array<{ id: PageId; label: string; icon: string }> = [
  { id: "dashboard", label: "Overview", icon: "⌁" },
  { id: "operations", label: "Operations", icon: "◉" },
  { id: "discover", label: "Discover", icon: "⌕" },
  { id: "hunting", label: "Threat Hunting", icon: "◎" },
  { id: "alerts", label: "Alerts", icon: "◇" },
  { id: "incidents", label: "Incidents", icon: "▱" },
  { id: "cases", label: "Cases", icon: "▤" },
  { id: "hosts", label: "Hosts", icon: "▦" },
  { id: "rules", label: "Detection Rules", icon: "⌘" },
  { id: "intelligence", label: "Threat Intelligence", icon: "◈" },
  { id: "reports", label: "Reports", icon: "⇩" },
  { id: "administration", label: "Administration", icon: "⚙" },
];

interface AppShellProps {
  activePage: PageId;
  connection: BackendConnection;
  analyst: AnalystPrincipal;
  logoutBusy: boolean;
  logoutError: string | null;
  api: BackendApi;
  children: ReactNode;
  onNavigate(page: PageId, detail?: { alert?: string; incident?: string; case?: string; event?: string; ruleId?: string }): void;
  onRetryConnection(): void;
  onLogout(): void;
}

export function AppShell({ activePage, connection, analyst, logoutBusy, logoutError, api, children, onNavigate, onRetryConnection, onLogout }: AppShellProps) {
  const [showShortcuts, setShowShortcuts] = useState(false);
  const chordStarted = useRef(false);
  const chordTimeout = useRef<number | null>(null);
  const discoverFocusTimeout = useRef<number | null>(null);
  const previousFocus = useRef<HTMLElement | null>(null);
  const activeLabel = navigation.find((item) => item.id === activePage)?.label ?? activePage;
  const openShortcuts = useCallback(() => { previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setShowShortcuts(true); }, []);
  const closeShortcuts = useCallback(() => { setShowShortcuts(false); window.setTimeout(() => previousFocus.current?.focus(), 0); }, []);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      const target = event.target;
      const isTyping = target instanceof HTMLElement && Boolean(target.matches("input, textarea, select") || target.isContentEditable);
      if (event.key === "Escape") {
        if (showShortcuts) { event.preventDefault(); closeShortcuts(); return; }
        window.dispatchEvent(new CustomEvent("cyberqalqon:escape"));
        return;
      }
      if (isTyping || event.ctrlKey || event.metaKey || event.altKey) return;
      if (event.key === "?") { event.preventDefault(); openShortcuts(); return; }
      if (event.key === "/") {
        event.preventDefault();
        onNavigate("discover");
        let attempts = 0;
        const focusDiscoverSearch = () => {
          const search = document.getElementById("discover-search");
          if (search instanceof HTMLElement) {
            search.focus();
            discoverFocusTimeout.current = null;
            return;
          }
          attempts += 1;
          if (attempts < 40) discoverFocusTimeout.current = window.setTimeout(focusDiscoverSearch, 50);
        };
        if (discoverFocusTimeout.current) window.clearTimeout(discoverFocusTimeout.current);
        discoverFocusTimeout.current = window.setTimeout(focusDiscoverSearch, 0);
        return;
      }
      if (chordStarted.current) {
        const destination: Partial<Record<string, PageId>> = { d: "discover", a: "alerts", i: "incidents", c: "cases" };
        chordStarted.current = false;
        if (chordTimeout.current) window.clearTimeout(chordTimeout.current);
        const next = destination[event.key.toLowerCase()];
        if (next) { event.preventDefault(); onNavigate(next); }
        return;
      }
      if (event.key.toLowerCase() === "g") {
        chordStarted.current = true;
        if (chordTimeout.current) window.clearTimeout(chordTimeout.current);
        chordTimeout.current = window.setTimeout(() => { chordStarted.current = false; }, 1200);
      }
    };
    window.addEventListener("keydown", keydown);
    return () => {
      window.removeEventListener("keydown", keydown);
      if (chordTimeout.current) window.clearTimeout(chordTimeout.current);
      if (discoverFocusTimeout.current) window.clearTimeout(discoverFocusTimeout.current);
    };
  }, [closeShortcuts, onNavigate, openShortcuts, showShortcuts]);

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
            <NotificationCenter api={api} refreshKey={activePage} onNavigate={onNavigate} />
            <div className="identity-block"><strong>{analyst.display_name}</strong><span>{analyst.username} · {analyst.role}</span></div>
            <span className="analyst-avatar" aria-label={`Authenticated analyst ${analyst.username}`}>{analyst.display_name.slice(0, 2).toUpperCase()}</span>
            <button className="button button--ghost" disabled={logoutBusy} type="button" onClick={onLogout}>{logoutBusy ? "Signing out…" : "Sign out"}</button>
          </div>
        </header>
        {logoutError && <div className="session-error" role="alert">{logoutError}</div>}
        <BackendStatusBanner status={connection} onRetry={onRetryConnection} />
        <main className="main-content">
          <nav className="breadcrumbs" aria-label="Breadcrumb"><span>Workspace</span><span aria-hidden="true">/</span><strong aria-current="page">{activeLabel}</strong><button className="shortcut-trigger" type="button" aria-label="Show keyboard shortcuts" onClick={openShortcuts}>?</button></nav>
          {children}
        </main>
      </div>
      {showShortcuts && <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) closeShortcuts(); }}><section className="shortcut-dialog" role="dialog" aria-modal="true" aria-labelledby="shortcut-title"><header><div><span className="eyebrow">Keyboard navigation</span><h2 id="shortcut-title">Shortcuts</h2></div><button className="icon-button" autoFocus type="button" aria-label="Close keyboard shortcuts" onClick={closeShortcuts}>×</button></header><dl><div><dt><kbd>/</kbd></dt><dd>Open Discover and focus search</dd></div><div><dt><kbd>Esc</kbd></dt><dd>Close the active dialog</dd></div><div><dt><kbd>g</kbd> then <kbd>d</kbd></dt><dd>Go to Discover</dd></div><div><dt><kbd>g</kbd> then <kbd>a</kbd></dt><dd>Go to Alerts</dd></div><div><dt><kbd>g</kbd> then <kbd>i</kbd></dt><dd>Go to Incidents</dd></div><div><dt><kbd>g</kbd> then <kbd>c</kbd></dt><dd>Go to Cases</dd></div><div><dt><kbd>?</kbd></dt><dd>Show this help</dd></div></dl></section></div>}
    </div>
  );
}
