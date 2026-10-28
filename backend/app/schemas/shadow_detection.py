"""CDRC v2: immutable JSON definitions, no executable extensions or ACTIVE state."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator, model_serializer
from app.services.cqql import FIELD_CATALOG, CQQLQueryError, compile_cqql


EXTENSION_FIELDS = {'process.guid', 'process.parent.guid'}
IdentityField = Literal['host.name','user.name','source.ip','process.guid']
SourceFamily = Literal['WINDOWS_EVENTCHANNEL','SYSMON','LINUX_AUTH','SYSLOG','JOURNALD','WAZUH_GENERIC','ZEEK','SURICATA']


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)


class SelectionStep(FrozenModel):
    query: str = Field(min_length=1,max_length=2000)
    threshold: Annotated[StrictInt,Field(ge=1,le=10)] = 1
    process_basename_equals: str | None = Field(default=None,max_length=128,pattern=r'^[A-Za-z0-9_.-]+$')
    parent_basename_equals: str | None = Field(default=None,max_length=128,pattern=r'^[A-Za-z0-9_.-]+$')

    @field_validator('query')
    @classmethod
    def safe_cqql(cls,value: str) -> str:
        try: compiled = compile_cqql(value)
        except CQQLQueryError as exc: raise ValueError('invalid CQQL selection: '+exc.code) from exc
        if compiled.uses_fts: raise ValueError('FTS selection is unsupported in bounded shadow evaluation')
        return value


class ShadowRule(FrozenModel):
    contract: Literal['cdrc-v2','cdrc-v3'] = 'cdrc-v2'
    correlation_mode: Literal['ORDERED','UNORDERED'] = 'ORDERED'
    predicate_semantics: Literal['CQQL_SQL_3VL','SIGMA_2VL'] = 'CQQL_SQL_3VL'
    external_rule_ids: tuple[Annotated[str,Field(min_length=1,max_length=128)],...] = Field(default=(),max_length=8)
    external_metadata_json: str | None = Field(default=None,max_length=8192)
    rule_id: str = Field(pattern=r'^SHADOW-[A-Z0-9-]{1,48}$')
    title: str = Field(min_length=1,max_length=128)
    description: str = Field(min_length=1,max_length=1024)
    author: str = Field(min_length=1,max_length=128)
    status: Literal['DRAFT','VALIDATED','SHADOW_ONLY','DISABLED_BY_POLICY','INVALID','DEPRECATED'] = 'SHADOW_ONLY'
    severity: Annotated[StrictInt,Field(ge=0,le=16)] = 8
    confidence: Annotated[StrictInt,Field(ge=0,le=100)] = 40
    minimum_confidence: Annotated[StrictInt,Field(ge=0,le=100)] = 0
    source_families: tuple[SourceFamily,...] = Field(min_length=1,max_length=8)
    required_fields: tuple[str,...] = Field(min_length=1,max_length=16)
    steps: tuple[SelectionStep,...] = Field(min_length=1,max_length=3)
    group_by: tuple[IdentityField,...] = Field(min_length=1,max_length=4)
    window_seconds: Annotated[StrictInt,Field(ge=1,le=1800)] = 600
    allowed_lateness: Annotated[StrictInt,Field(ge=0,le=300)] = 60
    suppression_policy: Literal['EVIDENCE_IDENTITY_ONLY'] = 'EVIDENCE_IDENTITY_ONLY'
    account_identity_policy: Literal['SID_WHEN_PRESENT_NO_DOWNGRADE'] = 'SID_WHEN_PRESENT_NO_DOWNGRADE'
    source_duplicate_policy: Literal['SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY'] = 'SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY'
    mitre_ids: tuple[str,...] = Field(default=(),max_length=8)
    tags: tuple[Annotated[str,Field(max_length=64)],...] = Field(default=(),max_length=12)
    references: tuple[Annotated[str,Field(max_length=256)],...] = Field(default=(),max_length=5)
    created_at: datetime
    updated_at: datetime

    @field_validator('created_at','updated_at')
    @classmethod
    def aware(cls,value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None: raise ValueError('UTC offset required')
        return value.astimezone(timezone.utc)

    @model_validator(mode='after')
    def semantic(self) -> 'ShadowRule':
        if self.contract == 'cdrc-v2' and (self.correlation_mode != 'ORDERED' or self.predicate_semantics != 'CQQL_SQL_3VL'
                or self.external_rule_ids or self.external_metadata_json is not None):
            raise ValueError('New evaluation semantics require explicit cdrc-v3')
        if self.external_metadata_json is not None:
            try:
                metadata = json.loads(self.external_metadata_json)
            except (ValueError, RecursionError):
                raise ValueError('Invalid bounded external metadata') from None
            if not isinstance(metadata,dict):
                raise ValueError('External metadata must be a bounded JSON object')
            stack, count = [(metadata, 0)], 0
            while stack:
                value, depth = stack.pop();count += 1
                if count > 512 or depth > 8:
                    raise ValueError('External metadata complexity exceeded')
                if isinstance(value,dict):stack.extend((item,depth+1) for item in value.values())
                elif isinstance(value,list):stack.extend((item,depth+1) for item in value)
        if self.updated_at < self.created_at: raise ValueError('invalid version timestamps')
        if self.allowed_lateness > self.window_seconds: raise ValueError('lateness exceeds window')
        for values in (self.required_fields,self.group_by,self.source_families,self.mitre_ids):
            if len(values) != len(set(values)): raise ValueError('duplicate definition members')
        if any(field not in FIELD_CATALOG and field not in EXTENSION_FIELDS for field in self.required_fields):
            raise ValueError('unsupported required field')
        if 'text' in self.required_fields: raise ValueError('FTS required field unsupported')
        if any(field not in self.required_fields for field in self.group_by): raise ValueError('group fields must be required')
        if sum(compile_cqql(step.query).clause_count for step in self.steps) > 32:
            raise ValueError('rule predicate budget exceeded')
        if sum(len(step.query) for step in self.steps) > 4000: raise ValueError('rule query budget exceeded')
        for step in self.steps:
            if step.process_basename_equals and 'process.name' not in self.required_fields:
                raise ValueError('process basename predicate requires process.name')
            if step.parent_basename_equals and 'process.parent.name' not in self.required_fields:
                raise ValueError('parent basename predicate requires process.parent.name')
        if any(urlsplit(value).scheme != 'https' or not urlsplit(value).netloc for value in self.references):
            raise ValueError('references require HTTPS; references are never fetched')
        return self

    @model_serializer(mode='wrap')
    def compatible_definition(self, handler):
        document = handler(self)
        if self.contract == 'cdrc-v2':
            # Original definitions, snapshots and hashes remain byte-equivalent.
            for key in ('correlation_mode','predicate_semantics','external_rule_ids','external_metadata_json'):
                document.pop(key, None)
        return document

    @property
    def rule_version(self) -> str:
        # Version IS the definition hash, not a mutable display revision number.
        encoded = json.dumps(self.model_dump(mode='json'),sort_keys=True,separators=(',',':'),ensure_ascii=False)
        return hashlib.sha256(encoded.encode()).hexdigest()


class ShadowSimulationRequest(FrozenModel):
    rule: ShadowRule
    start_time: datetime
    end_time: datetime
    evaluation_time: datetime

    @field_validator('start_time','end_time','evaluation_time')
    @classmethod
    def aware(cls,value: datetime) -> datetime:
        return ShadowRule.aware(value)

    @model_validator(mode='after')
    def bounded_range(self) -> 'ShadowSimulationRequest':
        if not self.start_time <= self.end_time <= self.evaluation_time:
            raise ValueError('start <= end <= evaluation_time required')
        if self.end_time-self.start_time > timedelta(days=31): raise ValueError('range exceeds 31 days')
        return self


class FindingEvidence(FrozenModel):
    event_id: str
    event_time: datetime
    ingestion_time: datetime
    source_family: SourceFamily
    host: str
    user: str | None
    user_sid: str | None = None
    process: str | None
    event_code: str | None = None
    process_guid: str | None = None
    stored_envelope_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    source_identity_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    source_record_key_sha256: str | None = None
    provenance: Literal['PARTIAL'] = 'PARTIAL'


class MitreContext(FrozenModel):
    technique_id: str
    name: str
    tactic: str
    evidence_strength: Literal['RULE_TAGGED_TECHNIQUE'] = 'RULE_TAGGED_TECHNIQUE'


class ShadowFinding(FrozenModel):
    finding_id: str = Field(pattern=r'^SF-[a-f0-9]{64}$')
    rule_id: str
    rule_version: str = Field(pattern=r'^[a-f0-9]{64}$')
    evidence_manifest_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    rule_snapshot: ShadowRule
    evaluation_version: Literal['m30-shadow-v1','m34-shadow-v1'] = 'm30-shadow-v1'
    status: Literal['SHADOW_ONLY'] = 'SHADOW_ONLY'
    severity: int = Field(ge=0,le=16)
    confidence: int = Field(ge=0,le=40)
    identity_confidence: Literal['CLAIMED_ENDPOINT_SCOPED'] = 'CLAIMED_ENDPOINT_SCOPED'
    window_start: datetime
    window_end: datetime
    completeness: Literal['UNPROVEN'] = 'UNPROVEN'
    group: dict[str,str]
    explanation: str
    uncertainty: tuple[str,...]
    evidence: tuple[FindingEvidence,...] = Field(min_length=1,max_length=32)
    mitre: tuple[MitreContext,...] = Field(max_length=8)


class ChainEdge(FrozenModel):
    source: str
    target: str
    relationship: Literal['FINDING_SUPPORTED_BY_EVENT','OBSERVED_BEFORE','OBSERVED_SHARED_PROCESS_GUID']
    causal_claim: Literal[False] = False


class ShadowSimulationResult(FrozenModel):
    version: Literal['cdrc-v2'] = 'cdrc-v2'
    scope: Literal['DISPOSABLE_SIMULATION'] = 'DISPOSABLE_SIMULATION'
    status: Literal['COMPLETE','RULE_DISABLED']
    outcome: Literal['MATCH','NO_MATCH','RULE_DISABLED','UNSUPPORTED_FIELDS','INVALID_EVENT']
    rule_version: str
    findings: tuple[ShadowFinding,...] = Field(max_length=100)
    graph_edges: tuple[ChainEdge,...] = Field(max_length=256)
    diagnostics: dict[str,int]
    candidate_truncated: bool
    coverage: Literal['BOUNDED_CANDIDATE_SLICE','PARTIAL']
    historical_continuity: Literal['UNPROVEN'] = 'UNPROVEN'
    window_completeness: Literal['UNPROVEN'] = 'UNPROVEN'
    evidence_retention: Literal['NOT_PINNED_RECHECK_ON_DRILLDOWN'] = 'NOT_PINNED_RECHECK_ON_DRILLDOWN'
    persistence: Literal['STATELESS_CONTENT_ADDRESSED_OUTPUT'] = 'STATELESS_CONTENT_ADDRESSED_OUTPUT'
    side_effects: Literal[False] = False
    execution_ms: float = Field(ge=0)
