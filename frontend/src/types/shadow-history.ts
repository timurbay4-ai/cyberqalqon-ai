import type {ShadowFinding,ShadowSimulationRequest} from './shadow-detection';
export type FindingState='SHADOW_CANDIDATE'|'SHADOW_CONFIRMED_MATCH'|'INCOMPLETE_EVIDENCE'|'SUPERSEDED'|'EXPIRED'|'INVALIDATED';
export interface DurableStatus {enabled:boolean;scope:'DISPOSABLE_DURABLE_SHADOW';production_active:false;schema_version:1|null;resource_state:Record<string,number>|null;recovery_runs?:{run_id:string;status:string;attempts:number;error_code:string|null;created_at:string;sealed:number}[]}
export interface DurableRequest {simulation:ShadowSimulationRequest;identity_policy:{minimum:'PARTIAL'|'STRONGLY_CORRELATED'|'VERIFIED'}}
export interface FindingHeader {finding_id:string;matching_id:string;rule_version:string;policy_sha:string;current_revision:number;state:FindingState;created_at:string;last_observed_at:string}
export interface FindingPage {items:FindingHeader[];next_cursor:string|null;scope:'DISPOSABLE_DURABLE_SHADOW';production_active:false}
export interface RecoveryIntent {version:'m35-bounded-snapshot-intent-v1';manifest_sha256:string;candidate_rows:number;candidate_truncated:boolean;scope:'BOUNDED_CANDIDATES_NOT_GLOBAL_COMPLETENESS';verification:'RECHECK_REQUIRED'|'SEALED'}
export interface DurableRun {run_id:string;status:'RUNNING'|'COMPLETED'|'FAILED'|'CANCELLED';recovery_state?:'NOT_REQUIRED'|'IN_PROGRESS'|'EXPLICIT_RESUME_REQUIRED'|'UNSEALED_BLOCKED'|'UNSEALED_VERIFICATION_REQUIRED'|'ATTEMPTS_EXHAUSTED';recovery_intent?:RecoveryIntent|null;attempts:number;error_code:string|null;checkpoint:'SEALED'|'UNSEALED';snapshot_sha256:string|null;production_active:false;scope:'DISPOSABLE_DURABLE_SHADOW';historical_continuity:'UNPROVEN';result:null|{finding_ids:string[];diagnostics:Record<string,number>;coverage:'PARTIAL'|'BOUNDED_CANDIDATE_SLICE';identity_rejected:number;candidate_count:number;historical_continuity:'UNPROVEN';window_completeness:'UNPROVEN';evaluation_version:'m31-shadow-v1';graph_edges:{source:string;target:string;relationship:string;causal_claim:false}[]}}
export interface FindingDetail extends FindingHeader {
    revision:number;matching_evidence:ShadowFinding;first_observed_at:string;
    identity:{version:'m31-identity-v1';policy:{version:'identity-policy-v1';minimum:'PARTIAL'|'STRONGLY_CORRELATED'|'VERIFIED'};satisfied:boolean;historical_continuity:'UNPROVEN';causal_claim:false;required_kinds:string[];entities:{kind:string;status:'VERIFIED'|'STRONGLY_CORRELATED'|'PARTIAL'|'AMBIGUOUS'|'UNVERIFIED'|'CONFLICTING';entity_id:string|null;scope_sha256:string;reason:string;evidence_ids:string[];authority_sha256:string|null}[]};
    authority_documents:unknown[];evidence_references:{event_id:string;envelope_sha:string;row_sha:string}[];
    history:{sequence:number;finding_id:string;revision:number;previous_state:FindingState|null;target_state:FindingState;reason:string;actor:string;occurred_at:string;superseded_by:string|null}[];
    history_truncated:boolean;historical_continuity:'UNPROVEN';production_active:false;scope:'DISPOSABLE_DURABLE_SHADOW';
    evidence_retention:'REFERENCES_NOT_AUTOMATIC_PINS';current_evidence_availability:Record<string,'AVAILABLE'|'MISSING'|'CHANGED'|'UNKNOWN'>;
    identity_context:'AT_ORIGINAL_EVALUATION_NOT_CURRENT_SOURCE_ATTESTATION';
}
export interface FindingTransition {expected_revision:number;expected_state:FindingState;target:FindingState;reason:'ANALYST_PATTERN_REVIEW'|'EVIDENCE_UNAVAILABLE'|'RULE_SUPERSEDED'|'PROVENANCE_CONFLICT'|'REVIEW_EXPIRED';superseded_by?:string}
