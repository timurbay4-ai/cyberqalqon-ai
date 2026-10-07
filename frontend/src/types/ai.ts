export const AI_AVAILABILITY = ["DISABLED", "AVAILABLE", "UNAVAILABLE", "MISCONFIGURED"] as const;
export type AIAvailability = (typeof AI_AVAILABILITY)[number];
export type AITargetType = "alert" | "incident";
export type AIAnalysisType = "ALERT_SUMMARY" | "INCIDENT_SUMMARY" | "ANALYST_QUESTION";

export interface AIStatus {
  state: AIAvailability;
  provider: "ollama";
  model: string | null;
  diagnostic: string | null;
  checked_at: string;
}

export interface AIMitreExplanation {
  technique_id: string;
  explanation: string;
  basis: "observed" | "inferred";
}

export interface AIAnalysisResult {
  summary: string;
  assessment: string;
  key_evidence: string[];
  mitre_context: AIMitreExplanation[];
  timeline_summary: string | null;
  hypotheses: string[];
  investigation_steps: string[];
  possible_false_positive_reasons: string[];
  recommended_actions: string[];
  containment_considerations: string[];
  uncertainties: string[];
}

export interface AIContextMetadata {
  context_bytes: number;
  truncated: boolean;
  alerts_included: number;
  alerts_available: number;
  notes_included: number;
  notes_available: number;
  history_included: number;
  history_available: number;
  raw_event_included: boolean;
  truncation_reasons: string[];
}

export interface AIAnalysisRecord {
  analysis_id: string;
  analysis_type: AIAnalysisType;
  target_type: AITargetType;
  target_id: string;
  requested_by: { analyst_id: string; display: string };
  requested_at: string;
  completed_at: string;
  provider: "ollama";
  model: string;
  model_digest: string | null;
  policy_version: "cyberqalqon-ai-policy-v1";
  schema_version: "ai-analysis-v1";
  context_fingerprint: string;
  context: AIContextMetadata;
  stale: boolean;
  result: AIAnalysisResult;
}

export interface AIAnalysisHistory {
  items: AIAnalysisRecord[];
  limit: number;
}

export interface AIAnalysisRequest {
  question?: string;
}
