import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';
import { api } from '@/api/client';
import { AIAnalysisPanel } from '@/components/AIAnalysisPanel';

const pending = { incident_id: 'inc-1', analysis_status: 'pending' as const, provider: 'ollama', model: 'test', result: null, failure_category: null, failure_message: null, analysis_version: '1', input_truncated: false, analysis_timestamp: null };

afterEach(() => vi.restoreAllMocks());

it('offers working analysis action for pending state', async () => {
  vi.spyOn(api, 'getAnalysis').mockResolvedValue(pending);
  vi.spyOn(api, 'runAnalysis').mockResolvedValue({ ...pending, analysis_status: 'failed', failure_category: 'timeout', failure_message: 'AI provider timed out' });
  render(<AIAnalysisPanel incidentId="inc-1" />);
  await userEvent.click(await screen.findByRole('button', { name: /analyze incident/i }));
  expect(api.runAnalysis).toHaveBeenCalledWith('inc-1', false);
  expect(await screen.findByText(/analysis failed: timeout/i)).toBeInTheDocument();
});

it('renders completed evidence and untrusted model text safely', async () => {
  vi.spyOn(api, 'getAnalysis').mockResolvedValue({ ...pending, analysis_status: 'completed', result: { summary: '<script>alert(1)</script>', observed_facts: ['Observed fact'], severity_explanation: 'Not proof of compromise', potential_mitre_techniques: [], investigation_steps: ['Review logs'], uncertainties: ['Limited context'] } });
  const { container } = render(<AIAnalysisPanel incidentId="inc-1" />);
  expect(await screen.findByText('<script>alert(1)</script>')).toBeInTheDocument();
  await waitFor(() => expect(container.querySelector('script')).toBeNull());
});

it('shows not-configured state without fictional output', async () => {
  vi.spyOn(api, 'getAnalysis').mockResolvedValue({ ...pending, analysis_status: 'not_configured', provider: 'noop', model: null });
  render(<AIAnalysisPanel incidentId="inc-1" />);
  expect(await screen.findByText(/AI Analysis Not Configured/i)).toBeInTheDocument();
});
