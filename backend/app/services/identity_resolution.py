"""Independent conservative resolver. No authority is accepted from event/API data."""
import hashlib
import hmac
import json
from datetime import datetime,timezone
from app.schemas.shadow_history import AuthorityInventory,IdentityPolicy,IdentityAssessment,EntityResolution
from app.services.wazuh_normalizer import canonical_json

KINDS=('HOST','ACCOUNT','PROCESS','NETWORK_ENDPOINT','SESSION','AGENT','COLLECTOR')
RANK={'UNVERIFIED':0,'PARTIAL':1,'STRONGLY_CORRELATED':2,'VERIFIED':3}


def digest(value):return hashlib.sha256(canonical_json(value).encode()).hexdigest()


class IdentityResolver:
    def __init__(self):
        self._inventory=None
        self._authority_sha=None
        self._signature=None

    @classmethod
    def from_signed_inventory(cls,inventory:dict,signature:str,trusted_keys:dict[str,bytes]):
        model=AuthorityInventory.model_validate(inventory)
        key=trusted_keys.get(model.key_id)
        if key is None or len(key)<32:raise ValueError('untrusted inventory authority')
        body=canonical_json(model.model_dump(mode='json')).encode()
        if len(body)>262144:raise ValueError('inventory exceeds budget')
        expected=hmac.new(key,body,hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,signature):raise ValueError('inventory signature mismatch')
        value=cls();value._inventory=model;value._authority_sha=hashlib.sha256(body).hexdigest();value._signature=signature
        return value

    @property
    def authority_sha256(self):return self._authority_sha

    def authority_document(self):
        return {'inventory':self._inventory.model_dump(mode='json'),'signature':self._signature} if self._inventory else None

    def _authority(self,kind,scope,key,at,fingerprint):
        model=self._inventory
        if model is None or not model.issued_at<=at<=model.expires_at:return None
        found=[entry.entity_id for entry in model.entries if entry.kind==kind and entry.scope==scope
            and entry.native_key==key and fingerprint in entry.evidence_fingerprints]
        return found[0] if len(found)==1 else None

    def assess(self,records,rule,policy:IdentityPolicy,*,at=None):
        if not 1<=len(records)<=32:raise ValueError('identity evidence count exceeded')
        at=at or datetime.now(timezone.utc)
        claims=[]
        for record in records:
            values=record['values'];scope=record['scope'];raw=record.get('raw',{})
            data=raw.get('data',{}) if isinstance(raw,dict) else {}
            data=data if isinstance(data,dict) else {}
            win=data.get('win',{})
            win=win.get('eventdata',{}) if isinstance(win,dict) else {}
            win=win if isinstance(win,dict) else {}
            # journald _UID identifies the emitting process, not necessarily the
            # account named in an SSH/sudo message. Never equate those subjects.
            uid=data.get('uid') if record['family'] in {'LINUX_AUTH','JOURNALD'} else None
            uid=str(uid) if isinstance(uid,(str,int)) and not isinstance(uid,bool) and str(uid).isdigit() else None
            user=values.get('user.name')
            sid=values.get('user.sid')
            account=('SID:'+sid if sid else 'UID:'+uid if uid is not None else 'NAME:'+str(user)) if user else None
            session=win.get('targetLogonId') if record['family']=='WINDOWS_EVENTCHANNEL' else data.get('session_id')
            session=str(session)[:128] if isinstance(session,(str,int)) else None
            ip=values.get('source.ip');port=values.get('source.port')
            protocol=win.get('protocol') if record['family']=='SYSMON' else None
            protocol=protocol.lower() if isinstance(protocol,str) else None
            endpoint=[protocol,ip,port] if protocol in {'tcp','udp'} and ip and port else None
            claims.append((record,{'HOST':scope[2],'AGENT':scope[1],'COLLECTOR':scope[0],
                'ACCOUNT':account,'PROCESS':values.get('process.guid'),
                'NETWORK_ENDPOINT':canonical_json(endpoint) if endpoint else None,'SESSION':session}))
        entities=[]
        for kind in KINDS:
            entries=[(record,keys[kind]) for record,keys in claims]
            scopes={record['scope'] for record,key in entries}
            keys={key for record,key in entries if key is not None}
            status='UNVERIFIED';reason='MISSING_IDENTITY';entity_id=None;authority=None
            required=kind=='HOST' or kind=='ACCOUNT' and 'user.name' in rule.group_by or kind=='PROCESS' and 'process.guid' in rule.group_by
            if len(keys)>1:
                status='CONFLICTING';reason='CONFLICTING_NATIVE_IDENTITIES'
            elif len(keys)==1 and all(key is not None for record,key in entries):
                key=next(iter(keys))
                verified=[self._authority(kind,record['scope'],key,at,record['sha']) if self._inventory is not None and
                    self._inventory.issued_at<=record['time']<=self._inventory.expires_at else None for record,_ in entries]
                if all(verified) and len(set(verified))==1:
                    status='VERIFIED';reason='SIGNED_OPERATOR_INVENTORY';authority=self._authority_sha
                    entity_id='ENTITY-'+digest([kind,verified[0],authority])
                elif len(scopes)>1:
                    status='AMBIGUOUS';reason='UNRELATED_SOURCE_SCOPES'
                else:
                    status='STRONGLY_CORRELATED' if kind=='PROCESS' or kind=='ACCOUNT' and key.startswith(('SID:','UID:')) else 'PARTIAL'
                    reason='SOURCE_SCOPED_NATIVE_IDENTIFIER' if status=='STRONGLY_CORRELATED' else 'CLAIMED_SOURCE_SCOPE_ONLY'
                    entity_id='ENTITY-'+digest([kind,next(iter(scopes)),key])
            elif keys:status='AMBIGUOUS';reason='MISSING_IDENTITY_NO_DOWNGRADE'
            scope_hash=digest(sorted(scopes))
            entities.append(EntityResolution(kind=kind,status=status,entity_id=entity_id,scope_sha256=scope_hash,
                reason=reason,evidence_ids=tuple(record['id'] for record,key in entries),authority_sha256=authority))
        needed={'HOST'}|({'ACCOUNT'} if 'user.name' in rule.group_by else set())|({'PROCESS'} if 'process.guid' in rule.group_by else set())
        satisfied=all(RANK.get(entity.status,-1)>=RANK[policy.minimum] for entity in entities if entity.kind in needed)
        return IdentityAssessment(policy=policy,satisfied=satisfied,entities=tuple(entities),required_kinds=tuple(kind for kind in KINDS if kind in needed))
