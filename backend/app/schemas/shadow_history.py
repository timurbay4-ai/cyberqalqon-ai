"""M31 contracts are separate from immutable M30 CDRC definitions/versions."""
from datetime import datetime
from typing import Annotated,Literal
from pydantic import Field,StrictInt,model_validator
from app.schemas.shadow_detection import FrozenModel,ShadowSimulationRequest,ShadowRule,ShadowFinding,ChainEdge

EntityKind=Literal['HOST','ACCOUNT','PROCESS','NETWORK_ENDPOINT','SESSION','AGENT','COLLECTOR']
ResolutionStatus=Literal['VERIFIED','STRONGLY_CORRELATED','PARTIAL','AMBIGUOUS','UNVERIFIED','CONFLICTING']
FindingState=Literal['SHADOW_CANDIDATE','SHADOW_CONFIRMED_MATCH','INCOMPLETE_EVIDENCE','SUPERSEDED','EXPIRED','INVALIDATED']


class IdentityPolicy(FrozenModel):
    version:Literal['identity-policy-v1']='identity-policy-v1'
    minimum:Literal['PARTIAL','STRONGLY_CORRELATED','VERIFIED']='PARTIAL'


class DurableEvaluationRequest(FrozenModel):
    simulation:ShadowSimulationRequest
    identity_policy:IdentityPolicy=Field(default_factory=IdentityPolicy)


class EntityResolution(FrozenModel):
    kind:EntityKind
    status:ResolutionStatus
    entity_id:str|None
    scope_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    reason:str=Field(max_length=128)
    evidence_ids:tuple[str,...]=Field(max_length=32)
    authority_sha256:str|None=None


class IdentityAssessment(FrozenModel):
    version:Literal['m31-identity-v1']='m31-identity-v1'
    policy:IdentityPolicy
    satisfied:bool
    entities:tuple[EntityResolution,...]=Field(max_length=7)
    required_kinds:tuple[EntityKind,...]=Field(min_length=1,max_length=7)
    historical_continuity:Literal['UNPROVEN']='UNPROVEN'
    causal_claim:Literal[False]=False

    @model_validator(mode='after')
    def consistent(self):
        ranks={'UNVERIFIED':0,'PARTIAL':1,'STRONGLY_CORRELATED':2,'VERIFIED':3}
        entities={entity.kind:entity for entity in self.entities}
        if len(entities)!=len(self.entities) or not set(self.required_kinds)<=entities.keys():raise ValueError('invalid identity set')
        expected=all(ranks.get(entities[kind].status,-1)>=ranks[self.policy.minimum] for kind in self.required_kinds)
        if self.satisfied!=expected:raise ValueError('identity strength mismatch')
        if any(entity.status=='VERIFIED' and not entity.authority_sha256 for entity in self.entities):raise ValueError('missing independent authority')
        return self


class FindingTransition(FrozenModel):
    expected_revision:StrictInt=Field(ge=1,le=8192)
    expected_state:FindingState
    target:FindingState
    reason:Literal['ANALYST_PATTERN_REVIEW','EVIDENCE_UNAVAILABLE','RULE_SUPERSEDED','PROVENANCE_CONFLICT','REVIEW_EXPIRED']
    superseded_by:str|None=Field(default=None,pattern=r'^DSF-[a-f0-9]{64}$')

    @model_validator(mode='after')
    def reason_matches(self):
        targets={'ANALYST_PATTERN_REVIEW':'SHADOW_CONFIRMED_MATCH','EVIDENCE_UNAVAILABLE':'INCOMPLETE_EVIDENCE',
            'RULE_SUPERSEDED':'SUPERSEDED','PROVENANCE_CONFLICT':'INVALIDATED','REVIEW_EXPIRED':'EXPIRED'}
        if targets[self.reason]!=self.target:raise ValueError('transition reason mismatch')
        if (self.superseded_by is not None)!=(self.target=='SUPERSEDED'):raise ValueError('supersession target required')
        return self


class AuthorityEntry(FrozenModel):
    kind:EntityKind
    scope:tuple[Annotated[str,Field(min_length=1,max_length=255)],Annotated[str,Field(min_length=1,max_length=255)],Annotated[str,Field(min_length=1,max_length=255)]]
    native_key:str=Field(min_length=1,max_length=512)
    entity_id:str=Field(min_length=1,max_length=128,pattern=r'^[A-Za-z0-9_.:-]+$')
    evidence_fingerprints:tuple[Annotated[str,Field(pattern=r'^[a-f0-9]{64}$')],...]=Field(min_length=1,max_length=32)


class AuthorityInventory(FrozenModel):
    version:Literal['m31-authority-v1']='m31-authority-v1'
    issuer:str=Field(min_length=1,max_length=64)
    key_id:str=Field(min_length=1,max_length=64)
    evidence_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    issued_at:datetime
    expires_at:datetime
    entries:tuple[AuthorityEntry,...]=Field(max_length=128)

    @model_validator(mode='after')
    def interval(self):
        for value in (self.issued_at,self.expires_at):ShadowRule.aware(value)
        if self.expires_at<=self.issued_at:raise ValueError('invalid inventory interval')
        keys=[(value.kind,value.scope,value.native_key) for value in self.entries]
        if len(keys)!=len(set(keys)):raise ValueError('duplicate authority subject')
        return self


class FindingHeader(FrozenModel):
    finding_id:str=Field(pattern=r'^DSF-[a-f0-9]{64}$')
    matching_id:str=Field(pattern=r'^SF-[a-f0-9]{64}$')
    rule_version:str=Field(pattern=r'^[a-f0-9]{64}$')
    policy_sha:str=Field(pattern=r'^[a-f0-9]{64}$')
    current_revision:int=Field(ge=1,le=8192)
    state:FindingState
    created_at:datetime
    last_observed_at:datetime


class FindingPage(FrozenModel):
    items:tuple[FindingHeader,...]=Field(max_length=50)
    next_cursor:str|None=Field(max_length=512)
    scope:Literal['DISPOSABLE_DURABLE_SHADOW']='DISPOSABLE_DURABLE_SHADOW'
    production_active:Literal[False]=False


class EvaluationSummary(FrozenModel):
    finding_ids:tuple[str,...]=Field(max_length=100)
    diagnostics:dict[str,int]
    coverage:Literal['PARTIAL','BOUNDED_CANDIDATE_SLICE']
    identity_rejected:int=Field(ge=0,le=100)
    candidate_count:int=Field(ge=0,le=100)
    historical_continuity:Literal['UNPROVEN']='UNPROVEN'
    window_completeness:Literal['UNPROVEN']='UNPROVEN'
    evaluation_version:Literal['m31-shadow-v1']='m31-shadow-v1'
    graph_edges:tuple[ChainEdge,...]=Field(max_length=256)


class RecoveryIntentView(FrozenModel):
    version:Literal['m35-bounded-snapshot-intent-v1']
    manifest_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    candidate_rows:int=Field(ge=0,le=1000)
    candidate_truncated:bool
    scope:Literal['BOUNDED_CANDIDATES_NOT_GLOBAL_COMPLETENESS']
    verification:Literal['RECHECK_REQUIRED','SEALED']


class DurableRun(FrozenModel):
    run_id:str=Field(pattern=r'^RUN-[a-f0-9]{32}$')
    status:Literal['RUNNING','COMPLETED','FAILED','CANCELLED']
    attempts:int=Field(ge=1,le=3)
    error_code:str|None=Field(max_length=128)
    checkpoint:Literal['SEALED','UNSEALED']
    snapshot_sha256:str|None
    result:EvaluationSummary|None
    recovery_state:Literal['NOT_REQUIRED','IN_PROGRESS','EXPLICIT_RESUME_REQUIRED','UNSEALED_BLOCKED','UNSEALED_VERIFICATION_REQUIRED','ATTEMPTS_EXHAUSTED']
    recovery_intent:RecoveryIntentView|None=None
    production_active:Literal[False]=False
    scope:Literal['DISPOSABLE_DURABLE_SHADOW']='DISPOSABLE_DURABLE_SHADOW'
    historical_continuity:Literal['UNPROVEN']='UNPROVEN'


class EvidenceReference(FrozenModel):
    event_id:str=Field(pattern=r'^EVT-[A-F0-9]{24}$')
    envelope_sha:str=Field(pattern=r'^[a-f0-9]{64}$')
    row_sha:str=Field(pattern=r'^[a-f0-9]{64}$')


class TransitionRecord(FrozenModel):
    sequence:int=Field(ge=1)
    finding_id:str
    revision:int=Field(ge=1,le=8192)
    previous_state:FindingState|None
    target_state:FindingState
    reason:str=Field(max_length=64)
    actor:str=Field(max_length=128)
    occurred_at:datetime
    superseded_by:str|None


class FindingDetail(FindingHeader):
    revision:int=Field(ge=1,le=8192)
    matching_evidence:ShadowFinding
    identity:IdentityAssessment
    authority_documents:tuple[dict,...]=Field(max_length=1)
    first_observed_at:datetime
    evidence_references:tuple[EvidenceReference,...]=Field(max_length=32)
    history:tuple[TransitionRecord,...]=Field(max_length=50)
    history_truncated:bool
    historical_continuity:Literal['UNPROVEN']='UNPROVEN'
    production_active:Literal[False]=False
    scope:Literal['DISPOSABLE_DURABLE_SHADOW']='DISPOSABLE_DURABLE_SHADOW'
    evidence_retention:Literal['REFERENCES_NOT_AUTOMATIC_PINS']='REFERENCES_NOT_AUTOMATIC_PINS'
    current_evidence_availability:dict[str,Literal['AVAILABLE','MISSING','CHANGED','UNKNOWN']]
    identity_context:Literal['AT_ORIGINAL_EVALUATION_NOT_CURRENT_SOURCE_ATTESTATION']='AT_ORIGINAL_EVALUATION_NOT_CURRENT_SOURCE_ATTESTATION'
