export const ANALYST_ROLES = ["ADMIN", "ANALYST", "VIEWER"] as const;
export type AnalystRole = (typeof ANALYST_ROLES)[number];

export const PERMISSIONS = ["soc:read", "incident:write", "analyst:manage"] as const;
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
