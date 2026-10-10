export type NotificationCategory = "CRITICAL_ALERT" | "HIGH_ALERT" | "ALERT_ASSIGNED" | "INCIDENT_ASSIGNED" | "OPERATIONAL_ISSUE" | "OPERATIONAL_RECOVERY" | "CASE_ASSIGNED" | "CASE_HANDOFF" | "CASE_SLA";

export interface AnalystNotification {
  notification_id: string;
  category: NotificationCategory;
  title: string;
  preview: string;
  target_type: "alert" | "incident" | "operational" | "case";
  target_id: string;
  created_at: string;
  read_at: string | null;
}

export interface NotificationListResponse {
  items: AnalystNotification[];
  unread_count: number;
  limit: number;
}

export interface NotificationReadAllResponse {
  updated_count: number;
  unread_count: 0;
}
