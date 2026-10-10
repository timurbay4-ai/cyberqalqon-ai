export const ANALYST_ROLES = ["ADMIN", "ANALYST", "VIEWER"] as const;
export type AnalystRole = (typeof ANALYST_ROLES)[number];

export const PERMISSIONS = ["soc:read", "alert:write", "incident:write", "analyst:manage"] as const;
export type Permission = (typeof PERMISSIONS)[number];

export interface AnalystPrincipal {
  analyst_id: string;
  username: string;
  display_name: string;
  role: AnalystRole;
  permissions: Permission[];
}

export interface SessionResponse {
  analyst: AnalystPrincipal;
  csrf_token: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AnalystPublic {
  analyst_id: string;
  username: string;
  display_name: string;
  role: AnalystRole;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface AnalystSessionStatus {
  active_sessions: number;
  current_expires_at: string;
}

export interface PasswordChange {
  current_password: string;
  new_password: string;
}

export interface SecurityAuditEvent {
  audit_id: string;
  action: string;
  actor_id: string | null;
  actor_display: string;
  target_type: string;
  target_id: string | null;
  outcome: "SUCCESS" | "DENIED" | "FAILURE";
  occurred_at: string;
  details: Record<string, unknown>;
}
