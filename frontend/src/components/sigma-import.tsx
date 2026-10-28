import {useEffect,useRef,useState} from 'react';
import type {BackendApi} from '../types/api';
import type {SigmaPreview} from '../api/sigma-contract';

export function SigmaImport({api,canMutate,onUseRule}:{api:BackendApi;canMutate:boolean;onUseRule:(rule:SigmaPreview['rules'][number])=>void}) {
  const [source,setSource]=useState(''),[result,setResult]=useState<SigmaPreview|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  const active=useRef<AbortController|null>(null);
  useEffect(()=>()=>active.current?.abort(),[]);
  function change(value:string){active.current?.abort();active.current=null;setBusy(false);setSource(value);setResult(null);setError('');}
  async function preview(){
    const controller=new AbortController();active.current?.abort();active.current=controller;setBusy(true);setResult(null);setError('');
    try{const value=await api.previewSigma(source,controller.signal);if(!controller.signal.aborted)setResult(value);}
    catch(reason){if(!controller.signal.aborted)setError(reason instanceof Error?reason.message:'Sigma conversion unavailable');}
    finally{if(active.current===controller){active.current=null;setBusy(false);}}
  }
  return <section className="panel" aria-label="Restricted Sigma import">
    <header className="panel__header"><div><span className="eyebrow">Rule interoperability</span><h2>Sigma preview — SHADOW ONLY</h2></div></header>
    <p>Explicit profile CQ_ENDPOINT_SHADOW_V1: endpoint namespaces, bounded counts and windows. Wildcards, regex, account grouping and unsupported features are rejected. No rule is activated or saved by preview.</p>
    <label className="filter-field"><span>Sigma YAML</span><textarea aria-label="Sigma YAML" rows={16} maxLength={32768} value={source} readOnly={!canMutate} onChange={event=>change(event.target.value)}/></label>
    <p>Up to 8 documents / 32 KiB UTF-8; canonical UUID and explicit ISO date required. No external rule or feed is fetched.</p>
    {!canMutate&&<p>Read-only: ANALYST or ADMIN permission and CSRF protection are required.</p>}
    <button className="button button--secondary" type="button" disabled={!canMutate||busy||!source.trim()} onClick={()=>void preview()}>Preview Sigma conversion</button>
    {busy&&<p role="status">Validating bounded Sigma semantics…</p>}
    {error&&<p role="alert">{error}</p>}
    {result&&<><p>Converted {result.rules.length} definition(s). Source SHA-256 <span className="mono wrap-anywhere">{result.source_sha256}</span>. Production active: NO.</p>
      <ul>{result.warnings.map(value=><li key={value}>{value}</li>)}</ul>
      {result.rules.map(row=><article className="detail-section" key={row.rule_version}><h3>{row.definition.title}</h3><p>External ID {row.external_id}; local {row.definition.rule_id}; {row.definition.correlation_mode}; window {row.definition.window_seconds}s.</p>
        <details><summary>Review exact converted definition</summary><pre className="mono wrap-anywhere">{JSON.stringify(row.definition,null,2)}</pre></details>
        <button className="button button--secondary" type="button" disabled={!canMutate} onClick={()=>onUseRule(row)}>Use in existing durable shadow evaluator</button>
      </article>)}
    </>}
  </section>;
}
