import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useHealth } from '@/hooks/useHealth';
import { formatRelativeTime } from '@/utils';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: '⬡', end: true },
  { to: '/incidents', label: 'Incidents', icon: '⚡', end: false },
  { to: '/alerts', label: 'Alert Explorer', icon: '🔍', end: false },
];

export function AppLayout() {
  const { health, refresh } = useHealth();
  const location = useLocation();

  const statusClass = `status-dot-${health.status}`;
  const statusLabel =
    health.status === 'online'
      ? 'Backend Online'
      : health.status === 'degraded'
      ? 'Backend Degraded'
      : health.status === 'offline'
      ? 'Backend Offline'
      : 'Checking…';

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <nav className="sidebar" aria-label="Main navigation">
        <NavLink to="/" className="sidebar-logo" aria-label="CyberQalqon AI — go to dashboard">
          <div className="sidebar-logo-icon" aria-hidden="true">🦅</div>
          <div className="sidebar-logo-text">
            <span className="sidebar-logo-name">CyberQalqon</span>
            <span className="sidebar-logo-tagline">SOC Platform</span>
          </div>
        </NavLink>

        <div className="sidebar-nav">
          <span className="nav-section-label">Navigation</span>
          {NAV_ITEMS.map(({ to, label, icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `nav-link${isActive ? ' active' : ''}`
              }
              aria-current={location.pathname === to ? 'page' : undefined}
            >
              <span className="nav-link-icon" aria-hidden="true">{icon}</span>
              <span>{label}</span>
            </NavLink>
          ))}
        </div>

        <div className="sidebar-footer">
          <button
            type="button"
            className="backend-status"
            onClick={refresh}
            title={`Backend status: ${statusLabel}. Last checked: ${formatRelativeTime(health.lastChecked?.toISOString())}. Click to refresh.`}
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
            aria-label={`Backend status: ${statusLabel}. Click to refresh.`}
          >
            <span className={`status-dot ${statusClass}`} aria-hidden="true" />
            <span className="text-muted" style={{ fontSize: 'var(--text-xs)' }}>
              {health.checking ? 'Checking…' : statusLabel}
            </span>
          </button>
        </div>
      </nav>

      {/* Main content */}
      <main className="main-content" id="main-content">
        <a href="#main-content" className="sr-only">Skip to main content</a>
        <Outlet />
      </main>
    </div>
  );
}
