export interface AlertAgent {
  id: string;
  name: string;
  ip?: string | null;
}

export type WazuhSeverityLevel =
  | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8
  | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16;

export interface AlertRule {
  id: string;
  level: WazuhSeverityLevel;
  description: string;
  groups?: string[];
}

export interface MitreContext {
  ids: string[];
  tactics: string[];
  techniques: string[];
}

export interface NetworkEndpoint {
  ip?: string | null;
  port?: number | null;
}

/** Mirrors the backend NormalizedAlert schema. Every string is untrusted display data. */
export interface NormalizedAlert {
  alert_id: string;
  timestamp: string;
  agent: AlertAgent;
  rule: AlertRule;
  mitre: MitreContext;
  source?: NetworkEndpoint | null;
  destination?: NetworkEndpoint | null;
  user?: string | null;
  location?: string | null;
  decoder_name?: string | null;
}

export type SeverityBand = "critical" | "high" | "medium" | "low" | "informational";

export interface AlertQuery {
  ruleLevels?: WazuhSeverityLevel[];
  agent?: string;
  mitreMapped?: boolean;
  mitreId?: string;
  startTime?: string;
  endTime?: string;
  search?: string;
  limit?: number;
  cursor?: string;
}
