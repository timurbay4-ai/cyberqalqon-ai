/**
 * API Client tests.
 *
 * MOCKED TESTS — These test the API client's error handling, timeout behavior,
 * and response parsing WITHOUT any real backend connection.
 *
 * These tests do NOT verify live Wazuh integration.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { api, ApiRequestError, NetworkError } from '@/api/client';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function mockResponse(status: number, body: unknown, ok = status < 400) {
  return Promise.resolve({
    ok,
    status,
    json: () => Promise.resolve(body),
  } as Response);
}

describe('api.health', () => {
  beforeEach(() => mockFetch.mockClear());

  it('returns health response on success', async () => {
    mockFetch.mockReturnValueOnce(mockResponse(200, { status: 'ok', service: 'cyberqalqon-backend' }));
    const result = await api.health();
    expect(result.status).toBe('ok');
    expect(result.service).toBe('cyberqalqon-backend');
  });

  it('throws NetworkError when fetch rejects (no connectivity)', async () => {
    mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    await expect(api.health()).rejects.toBeInstanceOf(NetworkError);
  });

  it('throws ApiRequestError on 503', async () => {
    mockFetch.mockReturnValueOnce(
      mockResponse(503, { error: { code: 'DB_UNAVAILABLE', message: 'Database offline' } })
    );
    const err = await api.health().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiRequestError);
    if (err instanceof ApiRequestError) {
      expect(err.status).toBe(503);
      expect(err.code).toBe('DB_UNAVAILABLE');
    }
  });
});

describe('api.listIncidents', () => {
  beforeEach(() => mockFetch.mockClear());

  it('constructs correct URL with filters', async () => {
    mockFetch.mockReturnValueOnce(
      mockResponse(200, { total: 0, limit: 10, offset: 0, items: [] })
    );
    await api.listIncidents({ limit: 10, offset: 0, severity: 'high', agent: 'WIN-PC-01' });
    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain('limit=10');
    expect(calledUrl).toContain('severity=high');
    expect(calledUrl).toContain('agent=WIN-PC-01');
  });

  it('returns empty list correctly', async () => {
    mockFetch.mockReturnValueOnce(
      mockResponse(200, { total: 0, limit: 50, offset: 0, items: [] })
    );
    const result = await api.listIncidents();
    expect(result.total).toBe(0);
    expect(result.items).toHaveLength(0);
  });

  it('throws ApiRequestError on 422 (validation error)', async () => {
    mockFetch.mockReturnValueOnce(
      mockResponse(422, { detail: [{ msg: 'invalid severity' }] })
    );
    await expect(api.listIncidents({ severity: 'invalid' as never })).rejects.toBeInstanceOf(ApiRequestError);
  });
});

describe('api.getIncident', () => {
  beforeEach(() => mockFetch.mockClear());

  it('throws ApiRequestError with 404 status on unknown ID', async () => {
    mockFetch.mockReturnValueOnce(
      mockResponse(404, { error: { code: 'INCIDENT_NOT_FOUND', message: 'Incident not found' } })
    );
    const err = await api.getIncident('nonexistent').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiRequestError);
    if (err instanceof ApiRequestError) {
      expect(err.status).toBe(404);
      expect(err.code).toBe('INCIDENT_NOT_FOUND');
    }
  });

  it('encodes special characters in incident ID', async () => {
    mockFetch.mockReturnValueOnce(
      mockResponse(200, { id: 'test', items: [] })
    );
    await api.getIncident('id with spaces').catch(() => {});
    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain('id%20with%20spaces');
  });
});

describe('api.submitReview', () => {
  beforeEach(() => mockFetch.mockClear());

  it('sends POST with correct body', async () => {
    mockFetch.mockReturnValueOnce(mockResponse(201, { id: 'inc-1', reviews: [] }));
    await api.submitReview('inc-1', { status: 'confirmed', analyst: 'analyst-1' });
    const [, options] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(options.method).toBe('POST');
    const body = JSON.parse(options.body as string);
    expect(body.status).toBe('confirmed');
    expect(body.analyst).toBe('analyst-1');
  });

  it('throws on validation failure', async () => {
    mockFetch.mockReturnValueOnce(
      mockResponse(422, { detail: 'validation error' })
    );
    await expect(
      api.submitReview('inc-1', { status: 'confirmed', analyst: '' })
    ).rejects.toBeInstanceOf(ApiRequestError);
  });
});

describe('Timeout behavior', () => {
  afterEach(() => vi.useRealTimers());

  it('throws NetworkError on AbortError (timeout)', async () => {
    // Simulate request that gets aborted (DOMException with AbortError name)
    mockFetch.mockImplementationOnce(() => {
      const err = new DOMException('Aborted', 'AbortError');
      return Promise.reject(err);
    });
    await expect(api.health()).rejects.toBeInstanceOf(NetworkError);
  });
});
