interface LoadingStateProps {
  message?: string;
}

export function LoadingState({ message = 'Loading…' }: LoadingStateProps) {
  return (
    <div className="loading-state" role="status" aria-live="polite" aria-label={message}>
      <div className="loading-spinner" aria-hidden="true">
        <div className="spinner spinner-lg" />
      </div>
      <span>{message}</span>
    </div>
  );
}
