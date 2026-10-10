import type { AlertWorkflowSort } from "./alerts";

export const DISCOVER_COLUMNS = ["time", "source", "host", "identity", "rule", "event"] as const;
export type DiscoverColumn = (typeof DISCOVER_COLUMNS)[number];
export type DashboardRange = "24h" | "7d" | "30d";
export type TableDensity = "COMFORTABLE" | "COMPACT";
export type TimeDisplay = "LOCAL" | "UTC" | "RELATIVE";

export interface AnalystPreferences {
  dashboard_range: DashboardRange;
  discover_page_size: 25 | 50 | 100;
  alert_page_size: 25 | 50 | 100;
  incident_page_size: 25 | 50 | 100;
  table_density: TableDensity;
  time_display: TimeDisplay;
  alert_default_sort: AlertWorkflowSort;
  discover_columns: DiscoverColumn[];
  version: number;
}

export interface AnalystPreferencesUpdate extends Omit<AnalystPreferences, "version"> {
  expected_version: number;
}

export const DEFAULT_PREFERENCES: AnalystPreferences = {
  dashboard_range: "24h",
  discover_page_size: 25,
  alert_page_size: 25,
  incident_page_size: 25,
  table_density: "COMFORTABLE",
  time_display: "LOCAL",
  alert_default_sort: "time_desc",
  discover_columns: [...DISCOVER_COLUMNS],
  version: 1,
};
