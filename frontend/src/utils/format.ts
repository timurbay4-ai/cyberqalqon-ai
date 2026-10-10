import type { NetworkEndpoint } from "../types/alerts";

const dateFormatter = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  timeZoneName: "short",
});

export function formatTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : dateFormatter.format(date);
}

export function formatRelativeTimestamp(value: string, now = Date.now()): string {
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) return value;
  const seconds = Math.round((timestamp - now) / 1000);
  const absoluteSeconds = Math.abs(seconds);
  if (absoluteSeconds < 45) return seconds > 5 ? "in a few seconds" : seconds < -5 ? "a few seconds ago" : "just now";
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["year", 31_536_000], ["month", 2_592_000], ["day", 86_400], ["hour", 3_600], ["minute", 60],
  ];
  const [unit, divisor] = units.find(([, size]) => absoluteSeconds >= size) ?? ["minute", 60];
  return new Intl.RelativeTimeFormat("en", { numeric: "auto" }).format(Math.round(seconds / divisor), unit);
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
  return value.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase().replaceAll("_", " ").replace(/^./, (character) => character.toUpperCase());
}
