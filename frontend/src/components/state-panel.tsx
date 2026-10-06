interface StatePanelProps {
  kind: "loading" | "error" | "empty" | "unavailable";
  title: string;
  message: string;
  actionLabel?: string;
  onAction?(): void;
}

export function StatePanel({ kind, title, message, actionLabel, onAction }: StatePanelProps) {
  return (
    <div className={`state-panel state-panel--${kind}`} role={kind === "error" || kind === "unavailable" ? "alert" : "status"}>
      {kind === "loading" ? <span className="spinner" aria-hidden="true" /> : <span className="state-panel__icon" aria-hidden="true">{kind === "empty" ? "∅" : "!"}</span>}
      <div>
        <h3>{title}</h3>
        <p>{message}</p>
        {actionLabel && onAction && <button className="button button--secondary" type="button" onClick={onAction}>{actionLabel}</button>}
      </div>
    </div>
  );
}
