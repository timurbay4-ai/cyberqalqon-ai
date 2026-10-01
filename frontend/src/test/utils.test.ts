/**
 * Tests for utility functions.
 *
 * All tests are isolated — no network calls, no browser APIs required.
 */
import { describe, it, expect } from 'vitest';
import {
  formatDateTime,
  formatDate,
  formatRelativeTime,
  severityLabel,
  aiStatusLabel,
  reviewStatusLabel,
  getMitreTechniqueInfo,
  safeJsonStringify,
  truncate,
  levelToSeverity,
} from '@/utils';

describe('formatDateTime', () => {
  it('returns em-dash for null input', () => {
    expect(formatDateTime(null)).toBe('—');
  });

  it('returns em-dash for undefined input', () => {
    expect(formatDateTime(undefined)).toBe('—');
  });

  it('formats a valid ISO string without throwing', () => {
    const result = formatDateTime('2026-09-30T21:00:00+05:00');
    expect(result).toBeTruthy();
    expect(result).not.toBe('—');
  });

  it('returns the raw value if unparseable', () => {
    const result = formatDateTime('not-a-date');
    // Should not crash, returns the raw string since Date("not-a-date") is Invalid Date
    expect(typeof result).toBe('string');
  });
});

describe('formatDate', () => {
  it('returns em-dash for null', () => {
    expect(formatDate(null)).toBe('—');
  });

  it('formats date portion only', () => {
    const result = formatDate('2026-09-30T21:00:00+05:00');
    expect(result).toBeTruthy();
    expect(result).not.toContain(':');
  });
});

describe('formatRelativeTime', () => {
  it('returns em-dash for null', () => {
    expect(formatRelativeTime(null)).toBe('—');
  });

  it('returns "s ago" for recent timestamps', () => {
    const result = formatRelativeTime(new Date().toISOString());
    expect(result).toMatch(/\ds ago/);
  });
});

describe('severityLabel', () => {
  it('maps known severities', () => {
    expect(severityLabel('critical')).toBe('Critical');
    expect(severityLabel('high')).toBe('High');
    expect(severityLabel('medium')).toBe('Medium');
    expect(severityLabel('low')).toBe('Low');
  });

  it('returns unknown values as-is', () => {
    expect(severityLabel('unknown-level')).toBe('unknown-level');
  });
});

describe('levelToSeverity', () => {
  it('maps null to low', () => {
    expect(levelToSeverity(null)).toBe('low');
  });

  it('maps level 1-3 to low', () => {
    expect(levelToSeverity(1)).toBe('low');
    expect(levelToSeverity(3)).toBe('low');
  });

  it('maps level 4-7 to medium', () => {
    expect(levelToSeverity(4)).toBe('medium');
    expect(levelToSeverity(7)).toBe('medium');
  });

  it('maps level 8-11 to high', () => {
    expect(levelToSeverity(8)).toBe('high');
    expect(levelToSeverity(11)).toBe('high');
  });

  it('maps level 12-15 to critical', () => {
    expect(levelToSeverity(12)).toBe('critical');
    expect(levelToSeverity(15)).toBe('critical');
  });
});

describe('aiStatusLabel', () => {
  it('maps not_configured correctly', () => {
    expect(aiStatusLabel('not_configured')).toBe('Not configured');
  });

  it('maps success correctly', () => {
    expect(aiStatusLabel('success')).toBe('Available');
  });
});

describe('reviewStatusLabel', () => {
  it('maps confirmed correctly', () => {
    expect(reviewStatusLabel('confirmed')).toBe('Confirmed');
  });

  it('maps false_positive correctly', () => {
    expect(reviewStatusLabel('false_positive')).toBe('False positive');
  });

  it('maps needs_review correctly', () => {
    expect(reviewStatusLabel('needs_review')).toBe('Needs review');
  });
});

describe('getMitreTechniqueInfo', () => {
  it('returns correct URL for known technique', () => {
    const info = getMitreTechniqueInfo('T1110');
    expect(info.id).toBe('T1110');
    expect(info.name).toBe('Brute Force');
    expect(info.url).toContain('attack.mitre.org');
  });

  it('returns the ID as name for unknown technique', () => {
    const info = getMitreTechniqueInfo('T9999');
    expect(info.name).toBe('T9999');
  });

  it('generates correct URL for sub-technique', () => {
    const info = getMitreTechniqueInfo('T1059.001');
    expect(info.url).toContain('T1059/001');
  });
});

describe('safeJsonStringify', () => {
  it('serializes plain objects', () => {
    const result = safeJsonStringify({ foo: 'bar' });
    expect(result).toContain('"foo"');
    expect(result).toContain('"bar"');
  });

  it('does not throw on circular references', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const circ: any = {};
    circ.self = circ;
    const result = safeJsonStringify(circ);
    expect(result).toBe('[Unable to serialize]');
  });
});

describe('truncate', () => {
  it('returns em-dash for null', () => {
    expect(truncate(null, 10)).toBe('—');
  });

  it('does not truncate short strings', () => {
    expect(truncate('hello', 10)).toBe('hello');
  });

  it('truncates long strings with ellipsis', () => {
    const result = truncate('hello world long text', 10);
    expect(result).toBe('hello worl…');
    expect(result.length).toBeLessThanOrEqual(12);
  });
});
