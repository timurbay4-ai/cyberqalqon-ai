import type {ReconciliationPage,EvidenceAvailability} from '../types/evidence-consistency';
import {ShadowContractError} from './shadow-contracts';
export function parseReconciliationPage(value:unknown):ReconciliationPage {
    const fail=()=>{throw new ShadowContractError();};
    if(!value||typeof value!=='object'||Array.isArray(value))return fail();
    const row=value as Record<string,any>;
    if(row.version!=='m32-reconciliation-v1'||row.scope!=='READ_ONLY_POINT_IN_TIME_PER_PAGE'||
        row.history_modified!==false||row.automatic_evidence_pins!==false||row.cross_database_atomic!==false||
        row.historical_continuity!=='UNPROVEN'||typeof row.store_id!=='string'||!/^[a-f0-9]{32}$/.test(row.store_id)||
        typeof row.source_binding!=='string'||!/^[a-f0-9]{64}$/.test(row.source_binding)||
        typeof row.observed_at!=='string'||row.observed_at.length>40||!Number.isFinite(Date.parse(row.observed_at)))return fail();
    if(!Array.isArray(row.revisions)||row.revisions.length>50||!row.counts||typeof row.counts!=='object'||Array.isArray(row.counts))return fail();
    if(row.next_cursor!==null&&(typeof row.next_cursor!=='string'||row.next_cursor.length>512))return fail();
    const counts:Partial<Record<EvidenceAvailability,number>>={},seen=new Set<string>();
    for(const revision of row.revisions){
        if(!revision||typeof revision.finding_id!=='string'||!/^DSF-[a-f0-9]{64}$/.test(revision.finding_id)||!Number.isInteger(revision.revision)||revision.revision<1||revision.revision>8192||
            typeof revision.reference_sha256!=='string'||!/^[a-f0-9]{64}$/.test(revision.reference_sha256)||!revision.availability||typeof revision.availability!=='object'||Array.isArray(revision.availability))return fail();
        const id=revision.finding_id+':'+revision.revision;if(seen.has(id))return fail();seen.add(id);
        if(Object.keys(revision.availability).length>32)return fail();
        for(const [event,status] of Object.entries(revision.availability)){
            if(!event||event.length>128||typeof status!=='string'||!['AVAILABLE','MISSING','CHANGED','UNKNOWN'].includes(status))return fail();
            const key=status as EvidenceAvailability;counts[key]=(counts[key]??0)+1;
        }
    }
    for(const [key,count] of Object.entries(row.counts))if(!['AVAILABLE','MISSING','CHANGED','UNKNOWN'].includes(key)||!Number.isInteger(count)||Number(count)<0||Number(count)>1600)return fail();
    for(const key of ['AVAILABLE','MISSING','CHANGED','UNKNOWN'])if((row.counts[key]??0)!==(counts[key as EvidenceAvailability]??0))return fail();
    return row as unknown as ReconciliationPage;
}
