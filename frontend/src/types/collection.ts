import type {CUSEMetadata} from './events';

export interface SourceFamilyCoverage {
  family:CUSEMetadata['source_family'];parser_available:boolean;observed:boolean;
  sample_event_count:number;sample_normalized_count:number;
  last_event_time:string|null;last_ingestion_time:string|null;latest_event_id:string|null;
  freshness:'UNKNOWN'|'OBSERVED'|'STALE';search_fields_available:boolean;
  connected:'UNKNOWN';detection_eligible:'UNKNOWN';queue_backlog:null;
}
export interface RegisteredSourceCoverage {
  source_id:string;source_type:'ZEEK_JSON'|'SURICATA_EVE';host:string;collector_id:string;
  source_generation:string;configured:true;connected:'UNKNOWN';
  delivery_state:'UNKNOWN'|'OBSERVED_COMMIT';last_committed_delivery_at:string|null;
  last_acknowledged_delivery:null;queue_backlog:null;retry_count:null;dead_letter_count:null;
  sample_event_count:number;last_event_time:string|null;last_ingestion_time:string|null;
  process_counters:Record<string,number>;counter_scope:'SINCE_APPLICATION_START';
  configuration_authority:'EXPLICIT_DISPOSABLE_CONSTRUCTOR';family:'ZEEK'|'SURICATA';
}
export interface ContinuousWorkerObservation {
  rule_id:string;rule_version:string;state:string;reason:string|null;ticks_committed:number;
  pending_evaluation:boolean;late_observed:number;late_outside_overlap:number;
  last_finding_ids:string[];historical_continuity:'UNPROVEN';production_active:false;
  progress?:{contract:'cq-shadow-progress-v1';stage:'CREATED'|'PENDING'|'RECOVERY_REQUIRED'|'FINDINGS_COMMITTED'|'CHECKPOINT_COMMITTED'|'BLOCKED';
    observed_gap:'UNPROVEN'|'PARTIAL'|'SOURCE_GAP'|'RETENTION_GAP';pending_run_id:string|null;run_status:'RUNNING'|'FAILED'|'CANCELLED'|'COMPLETED'|null;
    snapshot_state:'SEALED'|'UNSEALED'|null;unsealed_intent_present:boolean;last_completed_evaluation:string|null;
    transition_count:number;audit_scope:'M35_ONLY_LEGACY_NOT_BACKFILLED';transition_tail:{tick:number;stage:'PENDING_COMMITTED'|'CHECKPOINT_COMMITTED';run_id:string|null}[];window_completeness:'UNPROVEN'};
}
export interface SourceCoverageReport {
  contract:'cq-source-coverage-v1';observed_at:string;scope:'SYNTHETIC_TEST'|'UNKNOWN';
  coverage:'PARTIAL_SAMPLE'|'RETAINED_SAMPLE';sample_limit:1000;sample_count:number;truncated:boolean;
  historical_continuity:'UNPROVEN';production_active:false;
  families:SourceFamilyCoverage[];registered_sources:RegisteredSourceCoverage[];
  detection_workers:ContinuousWorkerObservation[];
  continuous_worker_state:'OBSERVED_ISOLATED_WORKERS'|'UNKNOWN_NOT_ACTIVATED';
}
