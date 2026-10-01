/**
 * CyberQalqon AI — Utility functions
 *
 * Date/time formatting, severity helpers, MITRE lookups.
 * All rendering uses text content — no innerHTML or dangerouslySetInnerHTML.
 */

import type { Severity, AIStatus, ReviewStatus, MitreTechnique } from '@/types';

// ---------------------------------------------------------------------------
// Date/time formatting
// ---------------------------------------------------------------------------

const DATE_FORMATTER = new Intl.DateTimeFormat('en-GB', {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  timeZoneName: 'short',
});

const DATE_ONLY_FORMATTER = new Intl.DateTimeFormat('en-GB', {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
});

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return DATE_FORMATTER.format(new Date(iso));
  } catch {
    return iso;
  }
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return DATE_ONLY_FORMATTER.format(new Date(iso));
  } catch {
    return iso;
  }
}

export function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    const diffMs = Date.now() - new Date(iso).getTime();
    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDay = Math.floor(diffHr / 24);
    return `${diffDay}d ago`;
  } catch {
    return '—';
  }
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

export function severityLabel(severity: Severity | string): string {
  const labels: Record<string, string> = {
    low: 'Low',
    medium: 'Medium',
    high: 'High',
    critical: 'Critical',
  };
  return labels[severity] ?? severity;
}

export function severityAriaLabel(severity: Severity | string): string {
  return `Severity: ${severityLabel(severity)}`;
}

/**
 * Maps Wazuh rule level (1-15) to display severity string.
 * Matches backend priority_engine.py thresholds.
 */
export function levelToSeverity(level: number | null): Severity {
  if (level == null) return 'low';
  if (level <= 3) return 'low';
  if (level <= 7) return 'medium';
  if (level <= 11) return 'high';
  return 'critical';
}

// ---------------------------------------------------------------------------
// AI status helpers
// ---------------------------------------------------------------------------

export function aiStatusLabel(status: AIStatus | string): string {
  const labels: Record<string, string> = {
    not_configured: 'Not configured',
    pending: 'Pending',
    success: 'Available',
    partial: 'Partial',
    failed: 'Failed',
    unavailable: 'Unavailable',
  };
  return labels[status] ?? status;
}

// ---------------------------------------------------------------------------
// Review status helpers
// ---------------------------------------------------------------------------

export function reviewStatusLabel(status: ReviewStatus | string): string {
  const labels: Record<string, string> = {
    needs_review: 'Needs review',
    confirmed: 'Confirmed',
    false_positive: 'False positive',
  };
  return labels[status] ?? status;
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK — static name lookup
// Limited set of common techniques; full reference at attack.mitre.org
// ---------------------------------------------------------------------------

const MITRE_NAMES: Record<string, string> = {
  T1110: 'Brute Force',
  'T1110.001': 'Password Guessing',
  'T1110.003': 'Password Spraying',
  'T1059.001': 'PowerShell',
  T1086: 'PowerShell (legacy ID)',
  'T1071.001': 'Web Protocols',
  T1021: 'Remote Services',
  T1078: 'Valid Accounts',
  T1003: 'OS Credential Dumping',
  T1055: 'Process Injection',
  T1027: 'Obfuscated Files',
  T1204: 'User Execution',
  T1566: 'Phishing',
  T1190: 'Exploit Public-Facing Application',
  T1133: 'External Remote Services',
  T1105: 'Ingress Tool Transfer',
  T1083: 'File and Directory Discovery',
  T1082: 'System Information Discovery',
  T1057: 'Process Discovery',
};

export function getMitreTechniqueInfo(id: string): MitreTechnique {
  return {
    id,
    name: MITRE_NAMES[id] ?? id,
    url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}`,
  };
}

// ---------------------------------------------------------------------------
// JSON safe serializer — used in JSON viewer (never eval'd)
// ---------------------------------------------------------------------------

export function safeJsonStringify(value: unknown, indent = 2): string {
  try {
    return JSON.stringify(value, null, indent);
  } catch {
    return '[Unable to serialize]';
  }
}

// ---------------------------------------------------------------------------
// String truncation
// ---------------------------------------------------------------------------

export function truncate(text: string | null | undefined, maxLength: number): string {
  if (!text) return '—';
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}…`;
}
