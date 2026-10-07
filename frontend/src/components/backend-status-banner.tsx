export type BackendConnection = "checking" | "connected" | "unavailable";

export function BackendStatusBanner({ status, onRetry }: { status: BackendConnection; onRetry(): void }) {
  if (status === "connected") {
    return (
      <div className="source-banner source-banner--connected" role="status">
        <span className="source-banner__dot" aria-hidden="true" />
        <strong>Live backend</strong>
        <span>Displaying real CyberQalqon API data.</span>
      </div>
    );
  }
  return (
    <div className={`source-banner source-banner--${status}`} role="status">
      <span className="source-banner__dot" aria-hidden="true" />
      <strong>{status === "checking" ? "Connecting" : "Backend unavailable"}</strong>
      <span>{status === "checking" ? "Checking the configured API origin…" : "No demo data has been substituted."}</span>
      {status === "unavailable" && <button type="button" onClick={onRetry}>Retry</button>}
    </div>
  );
}
