import type { SeverityBand, WazuhSeverityLevel } from "../types/alerts";

export const SEVERITY_BANDS: SeverityBand[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

export function severityBand(level: number): SeverityBand {
  if (level >= 13) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  if (level >= 4) return "low";
  return "informational";
}

export function severityLabel(band: SeverityBand): string {
  return band === "informational" ? "Info" : `${band[0].toUpperCase()}${band.slice(1)}`;
}

export function severityRange(band: SeverityBand): string {
  return {
    critical: "13–16",
    high: "10–12",
    medium: "7–9",
    low: "4–6",
    informational: "0–3",
  }[band];
}

export function severityLevels(bands: SeverityBand[]): WazuhSeverityLevel[] {
  const levels: Record<SeverityBand, WazuhSeverityLevel[]> = {
    critical: [13, 14, 15, 16],
    high: [10, 11, 12],
    medium: [7, 8, 9],
    low: [4, 5, 6],
    informational: [0, 1, 2, 3],
  };
  return bands.flatMap((band) => levels[band]);
}
