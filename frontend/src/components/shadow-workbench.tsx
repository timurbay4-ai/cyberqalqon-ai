import {useEffect,useRef,useState} from "react";
import type {BackendApi} from "../types/api";
import type {ShadowCatalog,ShadowRule,ShadowSimulationResult} from "../types/shadow-detection";
import {TimeValue} from "./time-value";

export function ShadowWorkbench({api,canMutate,onOpenEvent}:{api:BackendApi;canMutate:boolean;onOpenEvent:(id:string)=>void}) {
    const [catalog,setCatalog]=useState<ShadowCatalog|null>(null),[editor,setEditor]=useState("");
    const [result,setResult]=useState<ShadowSimulationResult|null>(null),[message,setMessage]=useState("");
    const [busy,setBusy]=useState(false),[error,setError]=useState("");
    const [start,setStart]=useState(()=>new Date(Date.now()-3600000).toISOString());
    const [end,setEnd]=useState(()=>new Date().toISOString());
    const operation=useRef<AbortController|null>(null);
    function invalidate() {
        operation.current?.abort();operation.current=null;
        setBusy(false);setResult(null);setMessage("");setError("");
    }
    useEffect(()=>{
        const controller=new AbortController();
        void api.getShadowCatalog(controller.signal).then(value=>{
            if(controller.signal.aborted)return;
            setCatalog(value); if(value.rules[0])setEditor(JSON.stringify(value.rules[0].definition,null,2));
        }).catch(reason=>{if(!controller.signal.aborted)setError(reason instanceof Error?reason.message:"Catalog unavailable");});
        return ()=>{controller.abort();operation.current?.abort();};
    },[api]);
    async function run(simulate:boolean) {
        const controller=new AbortController(); operation.current?.abort(); operation.current=controller;
        setBusy(true);setError("");setMessage("");setResult(null);
        try {
            const rule=JSON.parse(editor) as ShadowRule;
            if(simulate) {
                const value=await api.simulateShadowRule({rule,start_time:start,end_time:end,evaluation_time:new Date().toISOString()},controller.signal);
                if(!controller.signal.aborted)setResult(value);
            } else {
                const value=await api.validateShadowRule(rule,controller.signal);
                if(!controller.signal.aborted)setMessage(`Validated immutable definition ${value.rule_version}. Not deployed.`);
            }
        }catch(reason) {if(!controller.signal.aborted)setError(reason instanceof SyntaxError?"Invalid JSON definition":reason instanceof Error?reason.message:"Shadow operation failed");}
        finally {if(operation.current===controller){setBusy(false);operation.current=null;}}
    }
    return <section className="panel" aria-label="Shadow simulation workbench">
        <h2>CDRC v2 — SHADOW ONLY</h2>
        <p>NOT PRODUCTION ACTIVE. Disposable simulations only. Historical continuity and window completeness: UNPROVEN.</p>
        {!catalog&&!error&&<p role="status">Loading shadow catalog…</p>}
        {error&&<p role="alert">{error}</p>}
        {catalog&&<>
            <p>{catalog.simulation_enabled?"Explicit disposable simulation gate open.":"Simulation gate closed. Normal production application cannot activate this feature from the UI."}</p>
            <label className="field">Rule template<select aria-label="Shadow rule template" onChange={event=>{
                const selected=catalog.rules.find(value=>value.definition.rule_id===event.target.value);
                if(selected){invalidate();setEditor(JSON.stringify(selected.definition,null,2));}
            }}>{catalog.rules.map(value=><option key={value.rule_version} value={value.definition.rule_id}>{value.definition.title}</option>)}</select></label>
            <label className="field">Versioned JSON definition<textarea aria-label="Shadow rule JSON" rows={14} maxLength={24000} value={editor} onChange={event=>{invalidate();setEditor(event.target.value);}}/></label>
            <label className="field">Start time (explicit UTC offset)<input aria-label="Shadow start time" maxLength={40} value={start} onChange={event=>{invalidate();setStart(event.target.value);}}/></label>
            <label className="field">End time (explicit UTC offset)<input aria-label="Shadow end time" maxLength={40} value={end} onChange={event=>{invalidate();setEnd(event.target.value);}}/></label>
            <button type="button" disabled={!canMutate||busy||!editor} onClick={()=>void run(false)}>Validate definition</button>
            <button type="button" disabled={!canMutate||busy||!catalog.simulation_enabled||!editor} onClick={()=>void run(true)}>Run disposable simulation</button>
            {busy&&<button type="button" onClick={()=>{operation.current?.abort();setBusy(false);setMessage("Evaluation cancelled; no incident created.");}}>Cancel evaluation</button>}
            {!canMutate&&<p>Permission denied: an ANALYST or ADMIN is required for validation/simulation.</p>}
        </>}
        {message&&<p role="status">{message}</p>}
        {result&&<>
            <h3>Simulation result: {result.outcome}</h3>
            <p>{result.findings.length} findings in this run only. Coverage: {result.coverage}; elapsed {result.execution_ms} ms. Evidence is not pinned.</p>
            <pre>{JSON.stringify(result.diagnostics,null,2)}</pre>
            {result.findings.length===0&&<p>No findings. Unsupported/invalid telemetry is reported in diagnostics, not interpreted as benign activity.</p>}
            {result.findings.map(finding=><article key={finding.finding_id}>
                <h4>{finding.rule_snapshot.title} — SHADOW ONLY</h4>
                <p>{finding.explanation}</p><p>Confidence score (not probability): {finding.confidence}; identity: {finding.identity_confidence}.</p>
                <p>Rule version: {finding.rule_version}; completeness: {finding.completeness}.</p>
                <ul>{finding.uncertainty.map(note=><li key={note}>{note}</li>)}</ul>
                <p>MITRE rule tags (not confirmed attacks): {finding.mitre.map(value=>`${value.technique_id} ${value.name}`).join(", ")||"None"}</p>
                <table><caption>Observed evidence timeline — temporal order is not causation</caption>
                    <thead><tr><th>Event time</th><th>Source</th><th>Host / user</th><th>Process</th><th>Evidence</th></tr></thead>
                    <tbody>{finding.evidence.map(item=><tr key={item.event_id}><td><TimeValue value={item.event_time}/></td><td>{item.source_family}</td>
                        <td>{item.host} / {item.user||"Unknown"}</td><td>{item.process||"Unknown"}</td><td><button type="button" onClick={()=>onOpenEvent(item.event_id)}>Open event {item.event_id}</button> — {item.provenance}</td></tr>)}</tbody>
                </table>
            </article>)}
            <details><summary>Bounded relationship graph (accessible table)</summary><table><thead><tr><th>Source</th><th>Relationship</th><th>Target</th></tr></thead>
                <tbody>{result.graph_edges.map((edge,index)=><tr key={index}><td>{edge.source}</td><td>{edge.relationship} — no causal claim</td><td>{edge.target}</td></tr>)}</tbody></table></details>
        </>}
    </section>;
}
