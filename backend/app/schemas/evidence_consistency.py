"""Read-only reconciliation audit; never a cross-database atomicity claim."""
from datetime import datetime
from typing import Literal
from pydantic import Field
from app.schemas.shadow_detection import FrozenModel


class ReconciledRevision(FrozenModel):
    finding_id:str=Field(pattern=r'^DSF-[a-f0-9]{64}$')
    revision:int=Field(ge=1,le=8192)
    availability:dict[str,Literal['AVAILABLE','MISSING','CHANGED','UNKNOWN']]=Field(max_length=32)
    reference_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')


class ReconciliationPage(FrozenModel):
    version:Literal['m32-reconciliation-v1']='m32-reconciliation-v1'
    scope:Literal['READ_ONLY_POINT_IN_TIME_PER_PAGE']='READ_ONLY_POINT_IN_TIME_PER_PAGE'
    source_binding:str=Field(pattern=r'^[a-f0-9]{64}$')
    store_id:str=Field(pattern=r'^[a-f0-9]{32}$')
    observed_at:datetime
    revisions:tuple[ReconciledRevision,...]=Field(max_length=50)
    counts:dict[str,int]
    next_cursor:str|None
    history_modified:Literal[False]=False
    automatic_evidence_pins:Literal[False]=False
    cross_database_atomic:Literal[False]=False
    historical_continuity:Literal['UNPROVEN']='UNPROVEN'

