interface ErrorStateProps {
  title?: string;
  message: string;
  isNetwork?: boolean;
  onRetry?: () => void;
}

export function ErrorState({ title, message, isNetwork, onRetry }: ErrorStateProps) {
  return (
    <div className="error-state" role="alert" aria-live="assertive">
      <div className="error-state-icon" aria-hidden="true">
        {isNetwork ? '🔌' : '⚠️'}
      </div>
      <div>
        <h3>{title ?? (isNetwork ? 'Backend Unavailable' : 'Request Failed')}</h3>
        <p className="text-secondary text-sm mt-4" style={{ marginTop: 8 }}>{message}</p>
        {isNetwork && (
          <p className="text-muted text-xs" style={{ marginTop: 8 }}>
            Verify the backend is running: <code>uvicorn app.main:app --port 8000</code>
          </p>
        )}
      </div>
      {onRetry && (
        <button type="button" className="btn btn-secondary" onClick={onRetry}>
          ↺ Retry
        </button>
      )}
    </div>
  );
}
