import { useEffect, useRef, useState } from "react";

import { ApiError } from "../api/client";
import type { AIAnalysisRecord, AIStatus, AITargetType } from "../types/ai";
import type { BackendApi } from "../types/api";
import { formatTimestamp } from "../utils/format";

function errorMessage(reason: unknown): string {
  if (reason instanceof ApiError) {
    const messages: Record<string, string> = {
      ai_disabled: "AI Analyst is disabled by the operator.",
      ai_misconfigured: "AI Analyst configuration needs operator attention.",
      ai_unavailable: "Local AI is unavailable. Core SOC features remain available.",
      ai_model_unavailable: "The configured local model is not installed or available.",
      ai_timeout: "Local AI did not respond before the timeout.",
      ai_busy: "Local AI is busy. Retry after the current analysis finishes.",
      ai_rate_limited: "Please wait briefly before requesting another analysis.",
      ai_invalid_response: "The model returned an invalid structured response.",
      ai_response_too_large: "The model response exceeded the safe output limit.",
    };
    return messages[reason.code] ?? reason.message;
  }
  return reason instanceof Error ? reason.message : "AI analysis failed.";
}

function ListSection({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return <section className="ai-result__section"><h4>{title}</h4><ul>{items.map((item, index) => <li key={`${title}-${index}`}>{item}</li>)}</ul></section>;
}

function AnalysisResult({ analysis }: { analysis: AIAnalysisRecord }) {
  const result = analysis.result;
  return (
    <article className="ai-result" aria-label="AI advisory analysis">
      <header className="ai-result__meta">
        <div><span className="ai-label">AI-generated advisory analysis</span><strong>{analysis.model}</strong></div>
        <time>{formatTimestamp(analysis.completed_at)}</time>
      </header>
      <p className="trust-note">Verify against source evidence before taking action. Recommendations are not executed automatically.</p>
      {analysis.stale && <p className="ai-notice ai-notice--warning" role="status">This analysis may be stale because the target evidence changed.</p>}
      {analysis.context.truncated && <p className="ai-notice" role="status">The model received bounded, truncated context ({analysis.context.context_bytes.toLocaleString()} bytes).</p>}
      <section className="ai-result__section"><h4>Summary</h4><p>{result.summary}</p></section>
      <section className="ai-result__section"><h4>Assessment</h4><p>{result.assessment}</p></section>
      <ListSection title="Key evidence" items={result.key_evidence} />
      {result.mitre_context.length > 0 && <section className="ai-result__section"><h4>MITRE context</h4><ul>{result.mitre_context.map((item, index) => <li key={`${item.technique_id}-${index}`}><strong>{item.technique_id}</strong> <span className="ai-basis">{item.basis}</span><p>{item.explanation}</p></li>)}</ul></section>}
      {result.timeline_summary && <section className="ai-result__section"><h4>Timeline interpretation</h4><p>{result.timeline_summary}</p></section>}
      <ListSection title="Hypotheses" items={result.hypotheses} />
      <ListSection title="Investigation steps" items={result.investigation_steps} />
      <ListSection title="Possible false-positive explanations" items={result.possible_false_positive_reasons} />
      <ListSection title="Recommended actions" items={result.recommended_actions} />
      <ListSection title="Containment considerations" items={result.containment_considerations} />
      <ListSection title="Uncertainties" items={result.uncertainties} />
      <footer className="ai-result__provenance">
        <span>Requested by {analysis.requested_by.display}</span>
        <span>Policy {analysis.policy_version}</span>
        <span>Schema {analysis.schema_version}</span>
      </footer>
    </article>
  );
}

function statusText(status: AIStatus | null, loading: boolean): string {
  if (loading) return "Checking local AI availability…";
  if (!status) return "AI status could not be loaded.";
  if (status.state === "AVAILABLE") return `Local AI available${status.model ? ` · ${status.model}` : ""}`;
  if (status.state === "DISABLED") return "AI Analyst is disabled by the operator.";
  if (status.state === "MISCONFIGURED") return "AI Analyst configuration needs operator attention.";
  return "Local AI is unavailable. Core SOC features remain available.";
}

export function AIAnalysisPanel({ api, targetType, targetId }: { api: BackendApi; targetType: AITargetType; targetId: string }) {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [history, setHistory] = useState<AIAnalysisRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AIAnalysisRecord | null>(null);
  const [question, setQuestion] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const generationController = useRef<AbortController | null>(null);
  const targetKey = `${targetType}:${targetId}`;
  const currentTarget = useRef(targetKey);
  currentTarget.current = targetKey;

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setStatusLoading(true);
    setStatus(null);
    setHistory([]);
    setHistoryLoading(true);
    setSelected(null);
    setError(null);
    setHistoryError(null);
    setQuestion("");
    setPending(false);
    api.getAIStatus(controller.signal)
      .then((value) => { if (active) setStatus(value); })
      .catch((reason: unknown) => { if (active && !(reason instanceof DOMException && reason.name === "AbortError")) setError(errorMessage(reason)); })
      .finally(() => { if (active) setStatusLoading(false); });
    const historyRequest = targetType === "alert"
      ? api.listAlertAnalyses(targetId, controller.signal)
      : api.listIncidentAnalyses(targetId, controller.signal);
    historyRequest
      .then((value) => { if (active) { setHistory(value.items); setSelected(value.items[0] ?? null); } })
      .catch((reason: unknown) => { if (active && !(reason instanceof DOMException && reason.name === "AbortError")) setHistoryError(errorMessage(reason)); })
      .finally(() => { if (active) setHistoryLoading(false); });
    return () => {
      active = false;
      controller.abort();
      generationController.current?.abort();
    };
  }, [api, revision, targetId, targetType]);

  const generate = async () => {
    generationController.current?.abort();
    const controller = new AbortController();
    generationController.current = controller;
    const requestedTarget = targetKey;
    setPending(true);
    setError(null);
    try {
      const payload = question.trim() ? { question: question.trim() } : {};
      const analysis = targetType === "alert"
        ? await api.analyzeAlert(targetId, payload, controller.signal)
        : await api.analyzeIncident(targetId, payload, controller.signal);
      if (controller.signal.aborted || currentTarget.current !== requestedTarget) return;
      setSelected(analysis);
      setHistory((items) => [analysis, ...items.filter((item) => item.analysis_id !== analysis.analysis_id)]);
    } catch (reason) {
      if (!controller.signal.aborted && currentTarget.current === requestedTarget) setError(errorMessage(reason));
    } finally {
      if (!controller.signal.aborted && currentTarget.current === requestedTarget) setPending(false);
    }
  };

  const available = status?.state === "AVAILABLE";
  return (
    <section className="detail-section ai-panel" aria-label="AI Analyst">
      <div className="ai-panel__heading"><div><span className="eyebrow">Local advisory</span><h3>AI Analyst</h3></div><span className={`ai-status ai-status--${status?.state.toLowerCase() ?? "checking"}`}>{statusText(status, statusLoading)}</span></div>
      {!available && !statusLoading && <button className="button button--ghost" type="button" onClick={() => setRevision((value) => value + 1)}>Retry AI status</button>}
      <label className="field"><span>Optional analyst question</span><textarea maxLength={500} rows={2} value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="What evidence should I verify next?" /></label>
      <button className="button button--primary" type="button" disabled={!available || historyLoading || pending} onClick={() => { void generate(); }}>{pending ? "Analyzing…" : targetType === "alert" ? "Analyze alert with AI" : "Analyze incident with AI"}</button>
      {error && <p className="form-message form-message--error" role="alert">{error}</p>}
      {pending && <p className="muted" role="status">Local model analysis is in progress…</p>}
      {historyLoading && <p className="muted" role="status">Loading previous AI analyses…</p>}
      {historyError && <p className="form-message form-message--error">Previous analyses could not be loaded: {historyError}</p>}
      {history.length > 0 && <div className="ai-history"><h4>Previous analyses</h4><div className="ai-history__items">{history.map((item) => <button className={selected?.analysis_id === item.analysis_id ? "is-active" : undefined} type="button" key={item.analysis_id} onClick={() => setSelected(item)}><span>{formatTimestamp(item.completed_at)}</span><small>{item.model}{item.stale ? " · stale" : ""}</small></button>)}</div></div>}
      {!historyLoading && !historyError && !pending && !selected && <p className="muted">No AI analysis has been generated for this {targetType}.</p>}
      {selected && <AnalysisResult analysis={selected} />}
    </section>
  );
}
