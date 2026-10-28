import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import {M31_API_CONTRACT as captured} from '../test/m31-api-contract';
import {M30_API_CONTRACT} from '../test/m30-api-contract';
import {createMockApi} from '../test/fixtures';
import {ShadowHistory} from './shadow-history';
import {parseDurableStatus,parseDurableRun,parseFindingPage,parseFindingDetail} from '../api/shadow-history-contracts';
import {parseShadowCatalog} from '../api/shadow-contracts';
import {ApiError} from '../api/client';

function api(){return createMockApi({getDurableShadowStatus:vi.fn().mockResolvedValue(parseDurableStatus(captured.history_status)),
    getShadowCatalog:vi.fn().mockResolvedValue(parseShadowCatalog(M30_API_CONTRACT.catalog)),
    listDurableShadowFindings:vi.fn().mockResolvedValue(parseFindingPage(captured.history_page)),
    getDurableShadowFinding:vi.fn().mockResolvedValue(parseFindingDetail(captured.history_detail)),
    createDurableShadowRun:vi.fn().mockResolvedValue(parseDurableRun(captured.durable_run))});}

describe('durable shadow history actual API contracts',()=>{
    it('validates the captured actual backend response',()=>{
        expect(parseDurableStatus(captured.history_status).enabled).toBe(true);
        expect(parseDurableRun(captured.durable_run).status).toBe('COMPLETED');
        expect(parseFindingPage(captured.history_page).items).toHaveLength(1);
        expect(parseFindingDetail(captured.history_detail).history).toHaveLength(1);
    });
    it.each(['live','missing-authority','tampered-evidence','invalid-state'])('rejects %s contract',kind=>{
        const value:Record<string,any>=JSON.parse(JSON.stringify(captured.history_detail));
        if(kind==='live')value.production_active=true;
        if(kind==='missing-authority')value.identity.entities[0].status='VERIFIED';
        if(kind==='tampered-evidence')value.evidence_references[0].envelope_sha='f'.repeat(64);
        if(kind==='invalid-state')value.state='PRODUCTION_INCIDENT';
        expect(()=>parseFindingDetail(value)).toThrow();
    });
    it('renders real history, uncertainty and opens retained event',async()=>{
        const mock=api(),open=vi.fn();render(<ShadowHistory api={mock} canMutate onOpenEvent={open}/>);
        fireEvent.click(await screen.findByRole('button',{name:captured.history_page.items[0].finding_id}));
        expect(await screen.findByRole('table',{name:'Resolved entities and uncertainty'})).toBeInTheDocument();
        expect(screen.getByText(/No automatic incident or evidence pin/)).toBeInTheDocument();
        fireEvent.click(screen.getAllByRole('button',{name:/Open retained event/})[0]);
        expect(open).toHaveBeenCalledWith(captured.history_detail.matching_evidence.evidence[0].event_id);
    });
    it('keeps default gate closed without writing or loading findings',async()=>{
        const mock=createMockApi();render(<ShadowHistory api={mock} canMutate onOpenEvent={()=>undefined}/>);
        expect(await screen.findByText(/Durable history gate closed/)).toBeInTheDocument();
        expect(mock.listDurableShadowFindings).not.toHaveBeenCalled();expect(mock.createDurableShadowRun).not.toHaveBeenCalled();
    });
    it('restricts viewer mutations',async()=>{
        render(<ShadowHistory api={api()} canMutate={false} onOpenEvent={()=>undefined}/>);
        expect(await screen.findByRole('button',{name:'Evaluate and save bounded findings'})).toBeDisabled();
    });
    it('shows retained metadata with missing evidence, never enables false confirmation',async()=>{
        const value=JSON.parse(JSON.stringify(captured.history_detail));
        for(const id of Object.keys(value.current_evidence_availability))value.current_evidence_availability[id]='MISSING';
        const mock=api();vi.mocked(mock.getDurableShadowFinding).mockResolvedValue(parseFindingDetail(value));
        render(<ShadowHistory api={mock} canMutate onOpenEvent={()=>undefined}/>);
        fireEvent.click(await screen.findByRole('button',{name:value.finding_id}));
        expect(await screen.findByText(/Evidence is missing/)).toBeInTheDocument();
        expect(screen.getByRole('button',{name:'Review matched pattern — not compromise'})).toBeDisabled();
    });
    it('uses actual durable API and exposes per-run counts only',async()=>{
        const mock=api();render(<ShadowHistory api={mock} canMutate onOpenEvent={()=>undefined}/>);
        await screen.findByRole('button',{name:captured.history_page.items[0].finding_id});
        fireEvent.click(screen.getByRole('button',{name:'Evaluate and save bounded findings'}));
        expect(await screen.findByText(/Not a global detection count/)).toBeInTheDocument();
        expect(mock.createDurableShadowRun).toHaveBeenCalledTimes(1);
    });
    it('invalidates pending output when the required identity policy changes',async()=>{
        const mock=api();let finish:((value:any)=>void)|undefined;let signal:AbortSignal|undefined;
        vi.mocked(mock.createDurableShadowRun).mockImplementation((_body,requestSignal)=>{signal=requestSignal;return new Promise(resolve=>{finish=resolve;});});
        render(<ShadowHistory api={mock} canMutate onOpenEvent={()=>undefined}/>);
        await screen.findByRole('button',{name:captured.history_page.items[0].finding_id});
        fireEvent.click(screen.getByRole('button',{name:'Evaluate and save bounded findings'}));
        fireEvent.change(screen.getByLabelText('Required identity strength'),{target:{value:'VERIFIED'}});
        await act(async()=>{finish?.(parseDurableRun(captured.durable_run));});
        expect(signal?.aborted).toBe(true);expect(screen.queryByText(/Not a global detection count/)).not.toBeInTheDocument();
    });
    it('loads failure checkpoint without automatically retrying a durable operation',async()=>{
        const mock=api();const failed={...parseDurableRun(captured.durable_run),status:'FAILED' as const,
            result:null,error_code:'SHADOW_WORKER_EXCEPTION',recovery_state:'EXPLICIT_RESUME_REQUIRED' as const};
        vi.mocked(mock.createDurableShadowRun).mockRejectedValue(new ApiError('Bounded write rejected',503,'SHADOW_WORKER_EXCEPTION',undefined,failed.run_id));
        vi.mocked(mock.getDurableShadowRun).mockResolvedValue(failed);
        render(<ShadowHistory api={mock} canMutate onOpenEvent={()=>undefined}/>);
        await screen.findByRole('button',{name:captured.history_page.items[0].finding_id});
        fireEvent.click(screen.getByRole('button',{name:'Evaluate and save bounded findings'}));
        expect(await screen.findByRole('button',{name:'Resume sealed evaluation'})).toBeInTheDocument();
        expect(mock.resumeDurableShadowRun).not.toHaveBeenCalled();
    });
    it('escapes stored lifecycle actor strings',async()=>{
        const value=JSON.parse(JSON.stringify(captured.history_detail));value.history[0].actor='<img src=x onerror="fake()">';
        const mock=api();vi.mocked(mock.getDurableShadowFinding).mockResolvedValue(parseFindingDetail(value));
        const view=render(<ShadowHistory api={mock} canMutate onOpenEvent={()=>undefined}/>);
        fireEvent.click(await screen.findByRole('button',{name:value.finding_id}));
        expect(await screen.findByText(/onerror=/)).toBeInTheDocument();expect(view.container.querySelector('img')).toBeNull();
    });
});
