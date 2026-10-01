/**
 * Component rendering tests.
 *
 * Tests use JSDOM environment + @testing-library/react.
 * All API calls are mocked — these tests do NOT require a running backend.
 *
 * Clearly labeled: MOCKED TESTS — not live Wazuh integration tests.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ReviewStatusBadge } from '@/components/ReviewStatusBadge';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { LoadingState } from '@/components/LoadingState';
import { PriorityBar } from '@/components/PriorityBar';
import { MitreTagList } from '@/components/MitreTagList';
import { JsonViewer } from '@/components/JsonViewer';

// ---------------------------------------------------------------------------
// SeverityBadge
// ---------------------------------------------------------------------------
describe('SeverityBadge', () => {
  it('renders critical severity with accessible label', () => {
    render(<SeverityBadge severity="critical" />);
    const badge = screen.getByRole('img', { name: /severity: critical/i });
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveClass('badge-critical');
  });

  it('renders high severity', () => {
    render(<SeverityBadge severity="high" />);
    expect(screen.getByRole('img', { name: /severity: high/i })).toBeInTheDocument();
  });

  it('renders medium severity', () => {
    render(<SeverityBadge severity="medium" />);
    expect(screen.getByRole('img', { name: /severity: medium/i })).toBeInTheDocument();
  });

  it('renders low severity', () => {
    render(<SeverityBadge severity="low" />);
    expect(screen.getByRole('img', { name: /severity: low/i })).toBeInTheDocument();
  });

  it('contains severity text for non-color accessibility', () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// ReviewStatusBadge
// ---------------------------------------------------------------------------
describe('ReviewStatusBadge', () => {
  it('renders confirmed status', () => {
    render(<ReviewStatusBadge status="confirmed" />);
    // ReviewStatusBadge renders a <span> with aria-label — query by label text
    expect(screen.getByText('Confirmed')).toBeInTheDocument();
    const badge = screen.getByLabelText(/review status: confirmed/i);
    expect(badge).toBeInTheDocument();
  });

  it('renders false_positive status', () => {
    render(<ReviewStatusBadge status="false_positive" />);
    expect(screen.getByText('False positive')).toBeInTheDocument();
  });

  it('renders needs_review status', () => {
    render(<ReviewStatusBadge status="needs_review" />);
    expect(screen.getByText('Needs review')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// EmptyState
// ---------------------------------------------------------------------------
describe('EmptyState', () => {
  it('renders title and description', () => {
    render(
      <EmptyState
        title="No incidents found"
        description="Try adjusting filters"
        icon="📭"
      />
    );
    expect(screen.getByText('No incidents found')).toBeInTheDocument();
    expect(screen.getByText('Try adjusting filters')).toBeInTheDocument();
  });

  it('renders action slot', async () => {
    const onClear = vi.fn();
    render(
      <EmptyState
        title="Empty"
        action={<button onClick={onClear}>Clear filters</button>}
      />
    );
    await userEvent.click(screen.getByRole('button', { name: /clear filters/i }));
    expect(onClear).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// ErrorState
// ---------------------------------------------------------------------------
describe('ErrorState', () => {
  it('renders error message', () => {
    render(<ErrorState message="Something went wrong" />);
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });

  it('shows network-specific title for network errors', () => {
    render(<ErrorState message="Connection refused" isNetwork />);
    expect(screen.getByText('Backend Unavailable')).toBeInTheDocument();
  });

  it('calls onRetry when retry button clicked', async () => {
    const onRetry = vi.fn();
    render(<ErrorState message="Failed" onRetry={onRetry} />);
    await userEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('does not show retry button when onRetry not provided', () => {
    render(<ErrorState message="Not found" />);
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// LoadingState
// ---------------------------------------------------------------------------
describe('LoadingState', () => {
  it('renders with default message', () => {
    render(<LoadingState />);
    expect(screen.getByRole('status')).toBeInTheDocument();
    expect(screen.getByText('Loading…')).toBeInTheDocument();
  });

  it('renders with custom message', () => {
    render(<LoadingState message="Fetching incidents…" />);
    expect(screen.getByText('Fetching incidents…')).toBeInTheDocument();
  });

  it('has aria-live attribute for screen readers', () => {
    render(<LoadingState />);
    const status = screen.getByRole('status');
    expect(status).toHaveAttribute('aria-live', 'polite');
  });
});

// ---------------------------------------------------------------------------
// PriorityBar
// ---------------------------------------------------------------------------
describe('PriorityBar', () => {
  it('renders with accessible label', () => {
    render(<PriorityBar score={75} severity="high" />);
    const bar = screen.getByLabelText(/priority score: 75/i);
    expect(bar).toBeInTheDocument();
  });

  it('displays the numeric score', () => {
    render(<PriorityBar score={42} severity="medium" />);
    expect(screen.getByText('42')).toBeInTheDocument();
  });

  it('clamps scores above 100', () => {
    render(<PriorityBar score={150} severity="critical" />);
    expect(screen.getByText('100')).toBeInTheDocument();
  });

  it('clamps scores below 0', () => {
    render(<PriorityBar score={-10} severity="low" />);
    expect(screen.getByText('0')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// MitreTagList
// ---------------------------------------------------------------------------
describe('MitreTagList', () => {
  it('renders empty state when no IDs', () => {
    render(<MitreTagList ids={[]} />);
    expect(screen.getByText(/no mitre identifiers/i)).toBeInTheDocument();
  });

  it('renders MITRE tags as links', () => {
    render(<MitreTagList ids={['T1110', 'T1059.001']} />);
    const t1110Link = screen.getByRole('link', { name: /T1110/i });
    expect(t1110Link).toBeInTheDocument();
    expect(t1110Link).toHaveAttribute('href', expect.stringContaining('attack.mitre.org'));
  });

  it('links open in new tab', () => {
    render(<MitreTagList ids={['T1110']} />);
    const link = screen.getByRole('link', { name: /T1110/i });
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', expect.stringContaining('noreferrer'));
  });
});

// ---------------------------------------------------------------------------
// JsonViewer
// ---------------------------------------------------------------------------
describe('JsonViewer', () => {
  beforeEach(() => {
    // Mock clipboard API
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  it('renders in collapsed state by default', () => {
    render(<JsonViewer data={{ key: 'value' }} />);
    // Content should not be visible when collapsed
    const expandButton = screen.getByRole('button', { name: /expand json/i });
    expect(expandButton).toBeInTheDocument();
  });

  it('expands when expand button clicked', async () => {
    render(<JsonViewer data={{ foo: 'bar' }} />);
    await userEvent.click(screen.getByRole('button', { name: /expand json/i }));
    expect(screen.getByRole('region', { name: /json content/i })).toBeInTheDocument();
  });

  it('renders with initiallyExpanded=true', () => {
    render(<JsonViewer data={{ test: 42 }} initiallyExpanded />);
    expect(screen.getByRole('region', { name: /json content/i })).toBeInTheDocument();
  });

  it('renders copy button', () => {
    render(<JsonViewer data={{ x: 1 }} initiallyExpanded />);
    expect(screen.getByRole('button', { name: /copy json/i })).toBeInTheDocument();
  });

  it('displays custom label', () => {
    render(<JsonViewer data={{}} label="Raw Event" />);
    expect(screen.getByText('Raw Event')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// App routing test
// ---------------------------------------------------------------------------
describe('App routing', () => {
  it('renders 404 page for unknown route via MemoryRouter', async () => {
    const { NotFoundPage } = await import('@/pages/NotFoundPage');
    render(
      <MemoryRouter initialEntries={['/unknown']}>
        <NotFoundPage />
      </MemoryRouter>
    );
    expect(screen.getByText('404')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /go to dashboard/i })).toBeInTheDocument();
  });
});
