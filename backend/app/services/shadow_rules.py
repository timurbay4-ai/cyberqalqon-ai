"""Versioned declarative extension of the existing AdvancedDetectionEngine catalog."""
from datetime import datetime, timezone
from app.schemas.shadow_detection import ShadowRule
from app.services.advanced_detection import MITRE_TECHNIQUES, RULES


def validate_mitre(rule: ShadowRule) -> None:
    if any(value not in MITRE_TECHNIQUES for value in rule.mitre_ids):
        raise ValueError('MITRE mapping is not in the existing reviewed project catalog')


def catalog() -> list[ShadowRule]:
    at = datetime(2026,10,24,tzinfo=timezone.utc)
    common = dict(author='CyberQalqon M30',created_at=at,updated_at=at,
                  required_fields=('host.name','user.name','source.ip'),group_by=('user.name','source.ip'))
    return [
        ShadowRule(**common,rule_id='SHADOW-WINDOWS-AUTH',title='Potential suspicious Windows authentication sequence',
            description='Three failures followed by a success in the same claimed endpoint/account/source scope; requires analyst validation.',
            source_families=('WINDOWS_EVENTCHANNEL',),mitre_ids=('T1110.001','T1078'),tags=('related:DET-002',),
            steps=({'query':'event.code = "4625" AND event.outcome = "failure"','threshold':3},
                   {'query':'event.code = "4624" AND event.outcome = "success"'})),
        ShadowRule(**common,rule_id='SHADOW-SSH-AUTH',title='Potential suspicious SSH authentication sequence',
            description='Three SSH failures followed by success; NAT and legitimate retries remain alternative explanations.',
            source_families=('LINUX_AUTH',),mitre_ids=('T1110.001','T1078'),tags=('related:DET-007',),
            steps=({'query':'event.category = "linux_ssh" AND event.outcome = "failure"','threshold':3},
                   {'query':'event.category = "linux_ssh" AND event.outcome = "success"'})),
        ShadowRule(rule_id='SHADOW-OFFICE-SCRIPT',title='Office parent with script interpreter',
            author='CyberQalqon M30',created_at=at,updated_at=at,
            description='Recorded parent/child executable names, not proof of malicious payload or verified process ancestry.',
            source_families=('SYSMON',),required_fields=('host.name','process.name','process.parent.name'),
            group_by=('host.name',),mitre_ids=('T1059.001',),
            steps=({'query':'event.code = "1"','process_basename_equals':'powershell.exe','parent_basename_equals':'WINWORD.EXE'},)),
        ShadowRule(rule_id='SHADOW-PROCESS-NETWORK',title='Observed process/network sequence',
            author='CyberQalqon M30',created_at=at,updated_at=at,
            description='Process creation then connection sharing a real source ProcessGuid, scoped to one claimed endpoint. Not exfiltration evidence.',
            source_families=('SYSMON',),required_fields=('host.name','process.guid'),group_by=('process.guid',),
            steps=({'query':'event.code = "1"'},{'query':'event.code = "3"'})),
        ShadowRule(rule_id='SHADOW-ACCOUNT-PRIVILEGE',title='Account creation followed by privilege context',
            author='CyberQalqon M30',created_at=at,updated_at=at,
            description='Same scoped account name and host, not a proven privilege transition or globally verified SID identity.',
            source_families=('WINDOWS_EVENTCHANNEL',),required_fields=('host.name','user.name'),group_by=('user.name',),
            steps=({'query':'event.code = "4720"'},{'query':'event.code = "4672"'}),mitre_ids=('T1136',)),
        ShadowRule(rule_id='SHADOW-HOST-CONTEXT',title='Cross-source logon/process context hypothesis',
            author='CyberQalqon M30',created_at=at,updated_at=at,confidence=20,
            description='Two source families in the same claimed endpoint/account-name scope. Temporal context only: no verified SID/logon-ID or causal process ownership claim.',
            source_families=('WINDOWS_EVENTCHANNEL','SYSMON'),required_fields=('host.name','user.name'),group_by=('user.name',),
            steps=({'query':'event.code = "4624"'},{'query':'event.code = "1"'}))
    ]


def legacy_compatibility() -> list[dict]:
    return [{'rule_id':spec.rule_id,'required_fields':list(spec.required_fields),'source_types':list(spec.source_types),
        'window_seconds':spec.window_seconds,'mitre_ids':list(spec.mitre_ids),'enabled':False,
        'runtime_activation_state':'DISABLED_BY_POLICY','deployment_eligibility':'SHADOW_ONLY',
        'semantics':'UNCHANGED_EXISTING_M11_EVALUATOR'} for spec in RULES]
