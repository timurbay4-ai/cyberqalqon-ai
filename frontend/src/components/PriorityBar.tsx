import type { Severity } from '@/types';

interface PriorityBarProps {
  score: number;
  severity: Severity | string;
}

export function PriorityBar({ score, severity }: PriorityBarProps) {
  const clamped = Math.max(0, Math.min(100, score));
  return (
    <div className="priority-bar-wrap" aria-label={`Priority score: ${clamped} out of 100`}>
      <div className="priority-bar" aria-hidden="true">
        <div
          className={`priority-bar-fill ${severity}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
      <span className="priority-score-label">{clamped}</span>
    </div>
  );
}
