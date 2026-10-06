import type { NetworkEndpoint } from "../types/alerts";

const dateFormatter = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

export function formatTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : dateFormatter.format(date);
}

export function formatEndpoint(endpoint?: NetworkEndpoint | null): string {
  if (!endpoint?.ip) return "—";
  if (!endpoint.port) return endpoint.ip;
  return endpoint.ip.includes(":") ? `[${endpoint.ip}]:${endpoint.port}` : `${endpoint.ip}:${endpoint.port}`;
}

export function toApiTimestamp(localValue: string): string | undefined {
  if (!localValue) return undefined;
  const parsed = new Date(localValue);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

export function humanize(value: string): string {
  return value.toLowerCase().replaceAll("_", " ").replace(/^./, (character) => character.toUpperCase());
}
