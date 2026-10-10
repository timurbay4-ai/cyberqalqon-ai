export type EvidenceType = "EVENT" | "ALERT" | "INCIDENT_EVIDENCE";

export interface InvestigationAnalyst {
  analyst_id: string;
  username: string;
  display_name: string;
}

export interface ChecklistItem {
  checklist_item_id: string;
  incident_id: string;
  body: string;
  is_completed: boolean;
  assigned_to: InvestigationAnalyst | null;
  position: number;
  version: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  created_by_display: string;
  updated_by_display: string;
}

export interface EvidencePin {
  evidence_pin_id: string;
  incident_id: string;
  evidence_type: EvidenceType;
  evidence_id: string;
  annotation: string;
  source_timestamp: string;
  pinned_by_display: string;
  pinned_at: string;
  updated_at: string;
  version: number;
}

export interface InvestigationWorkspace {
  incident_id: string;
  checklist_items: ChecklistItem[];
  evidence_pins: EvidencePin[];
  checklist_completed: number;
  checklist_total: number;
}

export interface InvestigationActivity {
  activity_id: string;
  activity_type: string;
  entity_type: string;
  entity_id: string;
  actor_display: string;
  action_at: string;
  source_timestamp: string | null;
  details: Record<string, unknown>;
}

export interface InvestigationTimelinePage {
  items: InvestigationActivity[];
  limit: number;
  next_cursor: string | null;
  total: number;
}

export interface ChecklistCreate {
  body: string;
  assigned_to?: string | null;
}

export interface ChecklistUpdate {
  expected_version: number;
  body?: string;
  is_completed?: boolean;
  assigned_to?: string | null;
}

export interface ChecklistReorder {
  items: Array<{ checklist_item_id: string; expected_version: number }>;
}

export interface EvidencePinCreate {
  evidence_type: EvidenceType;
  evidence_id: string;
  annotation?: string;
}
