import {act,fireEvent,render,screen,waitFor} from "@testing-library/react";
import {describe,it,expect,vi} from "vitest";
import {ShadowWorkbench} from "./shadow-workbench";
import {M30_API_CONTRACT} from "../test/m30-api-contract";
import {createMockApi} from "../test/fixtures";
import {parseShadowCatalog,parseShadowResult,parseShadowValidation,ShadowContractError} from "../api/shadow-contracts";

const clone=<T,>(value:T):T=>JSON.parse(JSON.stringify(value));
describe("CDRC shadow API/analyst integration",()=>{
    it("consumes a captured real disposable backend contract",()=>{
        expect(parseShadowCatalog(M30_API_CONTRACT.catalog).production_active).toBe(false);
        expect(parseShadowValidation(M30_API_CONTRACT.validation).valid).toBe(true);
        const result=parseShadowResult(M30_API_CONTRACT.result);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].evidence).toHaveLength(4);
        expect(result.historical_continuity).toBe("UNPROVEN");
    });
    it.each(["live","verified","confidence","causal","unknown-edge","duplicate-evidence","version","truncation"])("rejects forged %s state",kind=>{
        const payload:Record<string,any>=clone(M30_API_CONTRACT.result);
        if(kind==="live")payload.scope="LIVE_SHADOW_RESULTS";
        if(kind==="verified")payload.findings[0].evidence[0].provenance="VERIFIED";
        if(kind==="confidence")payload.findings[0].confidence=100;
        if(kind==="causal")payload.graph_edges[0].causal_claim=true;
        if(kind==="unknown-edge")payload.graph_edges[0].target="nonexistent";
        if(kind==="duplicate-evidence")payload.findings[0].evidence.push(payload.findings[0].evidence[0]);
        if(kind==="version")payload.findings[0].rule_version="f".repeat(64);
        if(kind==="truncation")payload.candidate_truncated=true;
        expect(()=>parseShadowResult(payload)).toThrow(ShadowContractError);
    });
    it("renders actual finding uncertainty and drills into existing event workflow",async()=>{
        const api=createMockApi({getShadowCatalog:vi.fn().mockResolvedValue(parseShadowCatalog(M30_API_CONTRACT.catalog)),
            simulateShadowRule:vi.fn().mockResolvedValue(parseShadowResult(M30_API_CONTRACT.result))});
        const open=vi.fn();render(<ShadowWorkbench api={api} canMutate onOpenEvent={open}/>);
        const run=await screen.findByRole("button",{name:"Run disposable simulation"});
        fireEvent.click(run);
        expect(await screen.findByText("Simulation result: MATCH")).toBeInTheDocument();
        expect(screen.getByText(/Confidence score \(not probability\)/)).toBeInTheDocument();
        expect(screen.getByText(/No global source watermark/)).toBeInTheDocument();
        fireEvent.click(screen.getAllByRole("button",{name:/Open event EVT-/})[0]);
        expect(open).toHaveBeenCalledWith(M30_API_CONTRACT.result.findings[0].evidence[0].event_id);
        expect(api.simulateShadowRule).toHaveBeenCalledTimes(1);
    });
    it("keeps viewer and closed server gate non-mutating",async()=>{
        const api=createMockApi({getShadowCatalog:vi.fn().mockResolvedValue({...parseShadowCatalog(M30_API_CONTRACT.catalog),simulation_enabled:false})});
        render(<ShadowWorkbench api={api} canMutate={false} onOpenEvent={()=>undefined}/>);
        expect(await screen.findByRole("button",{name:"Run disposable simulation"})).toBeDisabled();
        expect(screen.getByRole("button",{name:"Validate definition"})).toBeDisabled();
        expect(screen.getByText(/Simulation gate closed/)).toBeInTheDocument();
        expect(api.simulateShadowRule).not.toHaveBeenCalled();
    });
    it("propagates cancellation and does not render stale results",async()=>{
        const api=createMockApi({getShadowCatalog:vi.fn().mockResolvedValue(parseShadowCatalog(M30_API_CONTRACT.catalog)),
            simulateShadowRule:vi.fn().mockImplementation((_payload,signal:AbortSignal)=>new Promise((_resolve,reject)=>{
                signal.addEventListener("abort",()=>reject(new DOMException("cancelled","AbortError")));
            }))});
        render(<ShadowWorkbench api={api} canMutate onOpenEvent={()=>undefined}/>);
        fireEvent.click(await screen.findByRole("button",{name:"Run disposable simulation"}));
        fireEvent.click(await screen.findByRole("button",{name:"Cancel evaluation"}));
        expect(await screen.findByText(/Evaluation cancelled/)).toBeInTheDocument();
        await waitFor(()=>expect(screen.queryByText("Simulation result: MATCH")).not.toBeInTheDocument());
    });
    it("renders hostile source strings as text, never HTML",async()=>{
        const result=clone(parseShadowResult(M30_API_CONTRACT.result));
        result.findings[0].evidence[0].user='<img src=x onerror="alert(1)">';
        const api=createMockApi({getShadowCatalog:vi.fn().mockResolvedValue(parseShadowCatalog(M30_API_CONTRACT.catalog)),
            simulateShadowRule:vi.fn().mockResolvedValue(result)});
        const view=render(<ShadowWorkbench api={api} canMutate onOpenEvent={()=>undefined}/>);
        fireEvent.click(await screen.findByRole("button",{name:"Run disposable simulation"}));
        await screen.findByText(/onerror=/);
        expect(view.container.querySelector("img")).toBeNull();
    });
    it("invalidates in-flight evidence when the analyst edits the rule or interval",async()=>{
        let finish:((value:unknown)=>void)|undefined;
        let signal:AbortSignal|undefined;
        const api=createMockApi({getShadowCatalog:vi.fn().mockResolvedValue(parseShadowCatalog(M30_API_CONTRACT.catalog)),
            simulateShadowRule:vi.fn().mockImplementation((_payload,requestSignal)=>{
                signal=requestSignal;return new Promise(resolve=>{finish=resolve;});
            })});
        render(<ShadowWorkbench api={api} canMutate onOpenEvent={()=>undefined}/>);
        fireEvent.click(await screen.findByRole("button",{name:"Run disposable simulation"}));
        fireEvent.change(screen.getByLabelText("Shadow end time"),{target:{value:"2026-10-24T00:00:00Z"}});
        expect(signal?.aborted).toBe(true);
        await act(async()=>{finish?.(parseShadowResult(M30_API_CONTRACT.result));});
        expect(screen.queryByText("Simulation result: MATCH")).not.toBeInTheDocument();
        expect(screen.getByRole("button",{name:"Run disposable simulation"})).toBeEnabled();
    });
});
