import { useCallback, useEffect, useState } from 'react';
import { api, ApiRequestError } from '@/api/client';
import type { AIAnalysisResponse } from '@/types';
import { MitreTagList } from './MitreTagList';

export function AIAnalysisPanel({ incidentId }: { incidentId: string }) {
  const [analysis, setAnalysis] = useState<AIAnalysisResponse | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => { setLoading(true); setError(''); try { setAnalysis(await api.getAnalysis(incidentId)); } catch (e) { setError(e instanceof Error ? e.message : 'Unable to load AI analysis'); } finally { setLoading(false); } }, [incidentId]);
  const run = async (retry: boolean) => { setLoading(true); setError(''); try { setAnalysis(await api.runAnalysis(incidentId, retry)); } catch (e) { setError(e instanceof ApiRequestError ? e.message : 'Backend or AI provider unavailable'); } finally { setLoading(false); } };
  useEffect(() => { void load(); }, [load]);
  if (loading) return <div className="info-message" role="status"><span className="spinner" /> Processing AI request…</div>;
  if (error) return <div className="error-message" role="alert">{error} <button className="btn" onClick={() => void load()}>Retry load</button></div>;
  if (!analysis) return null;
  if (analysis.analysis_status === 'not_configured') return <div className="info-message"><div><strong>AI Analysis Not Configured</strong><p>Configure a server-side provider to enable real inference. No synthetic result is shown.</p></div></div>;
  if (analysis.analysis_status === 'pending') return <div className="info-message"><div><p>No analysis has run yet.</p><button className="btn btn-primary" onClick={() => void run(false)}>Analyze incident</button></div></div>;
  if (analysis.analysis_status === 'failed') return <div className="error-message"><div><strong>Analysis failed: {analysis.failure_category}</strong><p>{analysis.failure_message}</p><button className="btn" onClick={() => void run(true)}>Retry analysis</button></div></div>;
  if (!analysis.result) return <div className="info-message">Analysis is {analysis.analysis_status}. Refresh shortly.</div>;
  const result = analysis.result;
  return <div className="flex flex-col gap-6">
    {analysis.input_truncated && <div className="warning-message">Input was bounded; some raw evidence was omitted.</div>}
    <section><h3>Summary</h3><p>{result.summary}</p></section>
    <section><h3>Observed evidence</h3><ul>{result.observed_facts.map((x, i) => <li key={i}>{x}</li>)}</ul></section>
    <section><h3>Severity context</h3><p>{result.severity_explanation}</p></section>
    <section><h3>Potential MITRE ATT&CK techniques</h3>{result.potential_mitre_techniques.length === 0 ? <p>None supported by available evidence.</p> : result.potential_mitre_techniques.map((m) => <div key={m.technique_id}><MitreTagList ids={[m.technique_id]} /><span className="text-xs">{m.source === 'source_event' ? 'Source mapping' : 'AI suggestion'} — {m.reasoning}</span></div>)}</section>
    <section><h3>Recommended investigation</h3><ol>{result.investigation_steps.map((x, i) => <li key={i}>{x}</li>)}</ol></section>
    <section><h3>Uncertainty</h3><ul>{result.uncertainties.map((x, i) => <li key={i}>{x}</li>)}</ul></section>
    <div className="text-xs text-muted">Provider: {analysis.provider} · Model: {analysis.model ?? 'unknown'} · Output is advisory and untrusted.</div>
    <button className="btn" onClick={() => void run(true)}>Run again</button>
  </div>;
}
