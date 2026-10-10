import { formatRelativeTimestamp, formatTimestamp } from "../utils/format";

export function TimeValue({ value, relative = false }: { value?: string | null; relative?: boolean }) {
  if (!value) return <span>—</span>;
  const absolute = formatTimestamp(value);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return <span title="Malformed timestamp">{absolute}</span>;
  return <time dateTime={parsed.toISOString()} title={absolute} aria-label={absolute}>{relative ? formatRelativeTimestamp(value) : absolute}</time>;
}
