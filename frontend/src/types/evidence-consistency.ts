export type EvidenceAvailability='AVAILABLE'|'MISSING'|'CHANGED'|'UNKNOWN';
export interface ReconciliationPage {
    version:'m32-reconciliation-v1';scope:'READ_ONLY_POINT_IN_TIME_PER_PAGE';
    source_binding:string;store_id:string;observed_at:string;
    revisions:{finding_id:string;revision:number;availability:Record<string,EvidenceAvailability>;reference_sha256:string}[];
    counts:Partial<Record<EvidenceAvailability,number>>;next_cursor:string|null;
    history_modified:false;automatic_evidence_pins:false;cross_database_atomic:false;historical_continuity:'UNPROVEN';
}
