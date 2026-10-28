import {fireEvent, render, screen} from '@testing-library/react';
import {describe, expect, it, vi} from 'vitest';
import captured from '../test/m33-api-contract.json';
import {parseInvestigationWorkbench, parseOperationalOverview} from '../api/contracts';
import {parseFindingDetail} from '../api/shadow-history-contracts';
import {M31_API_CONTRACT} from '../test/m31-api-contract';
import {M30_API_CONTRACT} from '../test/m30-api-contract';
import {parseDurableStatus, parseFindingPage} from '../api/shadow-history-contracts';
import {parseShadowCatalog} from '../api/shadow-contracts';
import {createMockApi} from '../test/fixtures';
import {ShadowHistory} from './shadow-history';
import {InvestigationWorkbenchPage} from '../pages/investigation-workbench-page';

const actual = captured.contract;
const target = {target_type:'DURABLE_SHADOW_FINDING' as const,target_id:actual.finding.finding_id,shadow_revision:1};

describe('M33 actual isolated full-application contract',()=>{
    it('accepts the exact durable finding revision and MITRE evidence',()=>{
        const result=parseInvestigationWorkbench(actual.workbench);
        expect(result.durable_shadow_context?.finding_id).toBe(actual.finding.finding_id);
        expect(result.durable_shadow_context?.revision).toBe(1);
        expect(result.durable_shadow_context?.matching_evidence.evidence).toHaveLength(4);
        expect(result.durable_shadow_context?.matching_evidence.mitre.length).toBeGreaterThan(0);
        const operations=parseOperationalOverview(actual.operations);
        expect(operations.archive_backlog.state).toBe('UNAVAILABLE');
        expect(operations.archive_backlog.current_lag_bytes).toBeNull();
        expect(operations.storage_retention.max_records).toBe(100000);
    });
    it.each(['missing-context','wrong-target','foreign-primary','missing-evidence','production'])('rejects %s',kind=>{
        const value:Record<string,any>=structuredClone(actual.workbench);
        if(kind==='missing-context')delete value.durable_shadow_context;
        if(kind==='wrong-target')value.target_type='EVENT';
        if(kind==='foreign-primary')value.primary_event.event_id='EVT-FFFFFFFFFFFFFFFFFFFFFFFF';
        if(kind==='missing-evidence')for(const id of Object.keys(value.durable_shadow_context.current_evidence_availability))value.durable_shadow_context.current_evidence_availability[id]='MISSING';
        if(kind==='production')value.durable_shadow_context.production_active=true;
        expect(()=>parseInvestigationWorkbench(value)).toThrow();
    });
    it('opens workbench using durable identity and viewed revision, including viewer reads',async()=>{
        const onInvestigate=vi.fn();
        const api=createMockApi({getDurableShadowStatus:vi.fn().mockResolvedValue(parseDurableStatus(M31_API_CONTRACT.history_status)),
            listDurableShadowFindings:vi.fn().mockResolvedValue(parseFindingPage({...M31_API_CONTRACT.history_page,items:[actual.finding]})),
            getShadowCatalog:vi.fn().mockResolvedValue(parseShadowCatalog(M30_API_CONTRACT.catalog)),
            getDurableShadowFinding:vi.fn().mockResolvedValue(parseFindingDetail(actual.finding))});
        render(<ShadowHistory api={api} canMutate={false} onOpenEvent={()=>undefined} onInvestigate={onInvestigate}/>);
        fireEvent.click(await screen.findByRole('button',{name:actual.finding.finding_id}));
        fireEvent.click(await screen.findByRole('button',{name:'Investigate durable finding revision 1'}));
        expect(onInvestigate).toHaveBeenCalledWith(expect.objectContaining(target));
        expect(api.createDurableShadowRun).not.toHaveBeenCalled();
    });
    it('renders retained durable context in the existing investigation page',async()=>{
        const api=createMockApi({getInvestigationWorkbench:vi.fn().mockResolvedValue(parseInvestigationWorkbench(actual.workbench))});
        const onOpenEvent=vi.fn();
        render(<InvestigationWorkbenchPage api={api} target={target} canMutate={false}
            onTargetChange={()=>undefined} onOpenEvent={onOpenEvent} onOpenAlert={()=>undefined}
            onOpenIncident={()=>undefined} onOpenCase={()=>undefined} onOpenRule={()=>undefined} onReturn={()=>undefined}/>);
        expect(await screen.findByRole('heading',{name:'Durable finding revision 1'})).toBeInTheDocument();
        expect(screen.getByText(/Historical continuity UNPROVEN/)).toBeInTheDocument();
        fireEvent.click(screen.getAllByRole('button',{name:/Open finding evidence/})[0]);
        expect(onOpenEvent).toHaveBeenCalledWith(actual.finding.matching_evidence.evidence[0].event_id);
        expect(api.createCase).not.toHaveBeenCalled();
    });
});
