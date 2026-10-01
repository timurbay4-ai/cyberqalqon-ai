import type { ReviewStatus } from '@/types';
import { reviewStatusLabel } from '@/utils';

interface ReviewStatusBadgeProps {
  status: ReviewStatus | string;
}

const STATUS_ICONS: Record<string, string> = {
  confirmed: '✓',
  false_positive: '✕',
  needs_review: '◉',
};

const STATUS_CLASSES: Record<string, string> = {
  confirmed: 'badge-confirmed',
  false_positive: 'badge-false-positive',
  needs_review: 'badge-needs-review',
};

export function ReviewStatusBadge({ status }: ReviewStatusBadgeProps) {
  const cls = STATUS_CLASSES[status] ?? 'badge-needs-review';
  const icon = STATUS_ICONS[status] ?? '?';
  const label = reviewStatusLabel(status);
  return (
    <span className={`badge ${cls}`} aria-label={`Review status: ${label}`}>
      <span aria-hidden="true">{icon}</span>
      {label}
    </span>
  );
}
