import type { Severity } from '@/types';
import { severityLabel } from '@/utils';

interface SeverityBadgeProps {
  severity: Severity | string;
}

const SEVERITY_ICONS: Record<string, string> = {
  critical: '⛔',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
};

/**
 * SeverityBadge — communicates severity with color + icon + text.
 * Never relies on color alone (WCAG 1.4.1).
 */
export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const icon = SEVERITY_ICONS[severity] ?? '⚪';
  const label = severityLabel(severity);

  return (
    <span
      className={`badge badge-${severity}`}
      aria-label={`Severity: ${label}`}
      role="img"
    >
      <span className="badge-dot" aria-hidden="true" />
      <span aria-hidden="true">{icon}</span>
      {label}
    </span>
  );
}
