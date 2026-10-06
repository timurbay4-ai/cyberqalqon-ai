import { severityBand, severityLabel } from "../utils/severity";

export function SeverityBadge({ level, compact = false }: { level: number; compact?: boolean }) {
  const band = severityBand(level);
  return (
    <span className={`badge severity severity--${band}`} title={`Wazuh rule level ${level}`}>
      <span className="badge__dot" aria-hidden="true" />
      {compact ? level : `${severityLabel(band)} · ${level}`}
    </span>
  );
}
