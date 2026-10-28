import {fireEvent,render,screen} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import {M32_RECONCILIATION} from '../test/m32-reconciliation-contract';
import {M31_API_CONTRACT} from '../test/m31-api-contract';
import {M30_API_CONTRACT} from '../test/m30-api-contract';
import {parseReconciliationPage} from '../api/evidence-consistency-contract';
import {parseDurableStatus,parseFindingPage} from '../api/shadow-history-contracts';
import {parseShadowCatalog} from '../api/shadow-contracts';
import {createMockApi} from '../test/fixtures';
import {ShadowHistory} from './shadow-history';

describe('read-only evidence consistency actual API contract',()=>{
    it('validates actual backend capture and page counts',()=>{
        const page=parseReconciliationPage(M32_RECONCILIATION);expect(page.counts.AVAILABLE).toBe(4);expect(page.cross_database_atomic).toBe(false);
    });
    it.each(['atomic','pins','count','state','oversize'])('rejects forged %s',kind=>{
        const value:Record<string,any>=JSON.parse(JSON.stringify(M32_RECONCILIATION));
        if(kind==='atomic')value.cross_database_atomic=true;
        if(kind==='pins')value.automatic_evidence_pins=true;
        if(kind==='count')value.counts.AVAILABLE=999;
        if(kind==='state')value.revisions[0].availability[Object.keys(value.revisions[0].availability)[0]]='VERIFIED';
        if(kind==='oversize')value.revisions=Array(51).fill(value.revisions[0]);
        expect(()=>parseReconciliationPage(value)).toThrow();
    });
    it('allows a viewer to inspect, never mutates or automatically audits',async()=>{
        const api=createMockApi({getDurableShadowStatus:vi.fn().mockResolvedValue(parseDurableStatus(M31_API_CONTRACT.history_status)),
            getShadowCatalog:vi.fn().mockResolvedValue(parseShadowCatalog(M30_API_CONTRACT.catalog)),
            listDurableShadowFindings:vi.fn().mockResolvedValue(parseFindingPage(M31_API_CONTRACT.history_page)),
            reconcileShadowEvidence:vi.fn().mockResolvedValue(parseReconciliationPage(M32_RECONCILIATION))});
        render(<ShadowHistory api={api} canMutate={false} onOpenEvent={()=>undefined}/>);
        fireEvent.click(await screen.findByRole('button',{name:'Reconcile retained evidence'}));
        expect(await screen.findByRole('complementary',{name:'Evidence reconciliation audit'})).toBeInTheDocument();
        expect(screen.getByText('AVAILABLE: 4')).toBeInTheDocument();
        expect(screen.getByText(/Each page is a separate snapshot/)).toBeInTheDocument();
        expect(api.reconcileShadowEvidence).toHaveBeenCalledTimes(1);expect(api.transitionDurableShadowFinding).not.toHaveBeenCalled();expect(api.createDurableShadowRun).not.toHaveBeenCalled();
    });
});
