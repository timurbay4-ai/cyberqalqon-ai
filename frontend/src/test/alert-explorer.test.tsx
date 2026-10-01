import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { AlertExplorerPage } from '@/pages/AlertExplorerPage';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

const summary = {
  id: 'incident-1',
  alert_id: 'alert-1',
  event_timestamp: '2026-09-30T16:00:00Z',
  created_at: '2026-09-30T16:00:01Z',
  agent_name: 'LAB-ENDPOINT',
  agent_ip: '192.0.2.10',
  rule_id: '5710',
  rule_level: 8,
  rule_description: 'Synthetic authentication failure',
  mitre_ids: ['T1110'],
  source_ip: '198.51.100.20',
  severity: 'high',
  priority_score: 40,
  ai_status: 'not_configured',
  review_status: 'needs_review',
};

function response(status: number, body: unknown) {
  return Promise.resolve({
    ok: status < 400,
    status,
    json: () => Promise.resolve(body),
  } as Response);
}

function summaryResponse() {
  return response(200, { total: 1, limit: 20, offset: 0, items: [summary] });
}

describe('AlertExplorerPage evidence loading', () => {
  beforeEach(() => mockFetch.mockReset());

  it('loads detail only on expansion and caches it across re-expansion', async () => {
    mockFetch
      .mockReturnValueOnce(summaryResponse())
      .mockReturnValueOnce(response(200, { ...summary, raw_event: { marker: 'synthetic evidence' } }));
    render(<MemoryRouter><AlertExplorerPage /></MemoryRouter>);

    const row = await screen.findByRole('button', { name: /synthetic authentication failure/i });
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockFetch.mock.calls[0][0]).toContain('/api/v1/incidents/summary');

    await userEvent.click(row);
    expect(await screen.findByText(/synthetic evidence/i)).toBeInTheDocument();
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockFetch.mock.calls[1][0]).toContain('/api/v1/incidents/incident-1');

    await userEvent.click(row);
    await userEvent.click(row);
    expect(await screen.findByText(/synthetic evidence/i)).toBeInTheDocument();
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('shows a detail error and retries without refetching the summary list', async () => {
    mockFetch
      .mockReturnValueOnce(summaryResponse())
      .mockReturnValueOnce(response(503, { error: { code: 'DATABASE_UNAVAILABLE', message: 'Evidence unavailable' } }))
      .mockReturnValueOnce(response(200, { ...summary, raw_event: { marker: 'recovered evidence' } }));
    render(<MemoryRouter><AlertExplorerPage /></MemoryRouter>);

    await userEvent.click(await screen.findByRole('button', { name: /synthetic authentication failure/i }));
    expect(await screen.findByText(/evidence unavailable/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByText(/recovered evidence/i)).toBeInTheDocument();
    await waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(3));
    expect(mockFetch.mock.calls.filter(([url]) => String(url).includes('/summary'))).toHaveLength(1);
  });
});
