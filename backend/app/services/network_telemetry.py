"""Registered Zeek/EVE normalization into existing schema-17 CUSE evidence."""
from __future__ import annotations

import hashlib
import ipaddress
import math
from datetime import datetime, timezone
from typing import Any

from app.schemas.collection import CollectionEnvelope, SourceBinding
from app.schemas.cuse import CUSEMetadata
from app.schemas.events import NormalizedSecurityEvent
from app.services.event_normalizer import (
    EventNormalizationError, _normalize_legacy_wazuh_event, redact_sensitive_payload,
)
from app.services.source_adapters import CONTROL, validate_bounds
from app.services.wazuh_normalizer import canonical_json

MAX_DURATION_SECONDS = 31_536_000
NETWORK_FIELDS = {
    'network.protocol': 'network_protocol',
    'network.duration_ms': 'network_duration_ms',
    'network.sensor.id': 'sensor_id',
    'network.connection.uid': 'connection_uid',
    'dns.question.name': 'dns_question_name',
    'dns.response.code': 'dns_response_code',
    'http.host': 'http_host',
    'url.path': 'url_path',
    'tls.server.name': 'tls_server_name',
}


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode('utf-8')).hexdigest()


def source_record_identity(raw: dict) -> str:
    """Domain-separated record identity; deliberately excludes payload/delivery ID."""
    return 'EVT-' + digest(['cq-source-record-v1', raw['agent']['id'],
                           raw['manager']['name'], raw['data']['source_generation'], raw['id']])[:24].upper()


def _string(value: Any, field: str, maximum: int = 1024) -> str | None:
    if value is None or value == '-':
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or CONTROL.search(value):
        raise EventNormalizationError('Invalid bounded network text', field=field)
    return value


def _integer(value: Any, field: str, maximum: int) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= maximum:
        raise EventNormalizationError('Invalid bounded network integer', field=field)
    return value


def _time(value: Any, *, epoch=False) -> datetime:
    try:
        if epoch:
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError('Invalid epoch')
            return datetime.fromtimestamp(value, timezone.utc)
        if not isinstance(value, str):
            raise ValueError('Invalid timestamp')
        result = datetime.fromisoformat(value)
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError('Offset required')
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError) as exc:
        raise EventNormalizationError('Invalid network timestamp', code='INVALID_TIMESTAMP') from exc


def normalize_network(envelope: CollectionEnvelope, binding: SourceBinding) -> NormalizedSecurityEvent:
    if (envelope.source_id, envelope.source_type, envelope.collector_id, envelope.source_generation) != (
            binding.source_id, binding.source_type, binding.collector_id, binding.source_generation):
        raise EventNormalizationError('Registered source identity mismatch', code='INVALID_SOURCE_IDENTITY')
    payload = envelope.payload
    validate_bounds(payload)
    if digest(payload) != envelope.integrity_fingerprint:
        raise EventNormalizationError('Payload fingerprint mismatch', code='INVALID_FINGERPRINT')
    zeek = binding.source_type == 'ZEEK_JSON'
    supported = {'conn', 'dns', 'http', 'ssl'} if zeek else {'alert', 'dns', 'http', 'tls', 'flow'}
    if envelope.stream not in supported or (not zeek and payload.get('event_type') != envelope.stream):
        raise EventNormalizationError('Unsupported or conflicting network stream', code='UNSUPPORTED_SOURCE')
    occurred = _time(payload.get('ts') if zeek else payload.get('timestamp'), epoch=zeek)
    if occurred != envelope.event_timestamp:
        raise EventNormalizationError('Conflicting network timestamps', code='INVALID_TIMESTAMP')
    attrs: dict[str, str | int] = {'sensor_id': binding.source_id,
                                  'collector_version': envelope.collector_version,
                                  'collector_checkpoint_identity': envelope.checkpoint_identity}
    patch: dict[str, Any] = {}
    for field, key in (('source_ip', 'id.orig_h' if zeek else 'src_ip'),
                       ('destination_ip', 'id.resp_h' if zeek else 'dest_ip')):
        value = payload.get(key)
        if value is not None:
            try:
                if not isinstance(value, str):
                    raise ValueError('IP must be text')
                patch[field] = str(ipaddress.ip_address(value))
            except ValueError as exc:
                raise EventNormalizationError('Invalid network address', field=field) from exc
    for field, key in (('source_port', 'id.orig_p' if zeek else 'src_port'),
                       ('destination_port', 'id.resp_p' if zeek else 'dest_port')):
        value = _integer(payload.get(key), field, 65535)
        if value == 0:
            raise EventNormalizationError('Port zero is outside CUSE v1', field=field)
        if value is not None:
            patch[field] = value
    protocol = _string(payload.get('proto'), 'proto', 32)
    if protocol is not None:
        attrs['network_protocol'] = protocol.lower()
    uid = payload.get('uid' if zeek else 'flow_id')
    if uid is not None:
        if not isinstance(uid, str) and type(uid) is not int:
            raise EventNormalizationError('Invalid connection identity')
        attrs['connection_uid'] = _string(str(uid), 'connection_uid', 128)
    duration = payload.get('duration') if zeek else (payload.get('flow') or {}).get('age') if isinstance(payload.get('flow', {}), dict) else None
    if duration is not None:
        if type(duration) not in (int, float) or not math.isfinite(duration) or not 0 <= duration <= MAX_DURATION_SECONDS:
            raise EventNormalizationError('Invalid connection duration')
        attrs['network_duration_ms'] = round(duration * 1000)
    stream = envelope.stream
    detail = payload if zeek else payload.get(stream, {})
    if not isinstance(detail, dict):
        raise EventNormalizationError('Network detail must be an object')
    warnings = ['SOURCE_IDENTITY_CLAIMED']
    if stream == 'dns' and not zeek:
        if detail.get('version') is not None and (type(detail['version']) is not int or detail['version'] not in (2,3)):
            raise EventNormalizationError('Unsupported DNS EVE format', code='UNSUPPORTED_DNS_FORMAT')
        if 'queries' in detail:
            queries = detail['queries']
            if not isinstance(queries,list) or not 1 <= len(queries) <= 32:
                raise EventNormalizationError('DNS question count exceeds supported bounds')
            questions = []
            for question in queries:
                if not isinstance(question,dict):
                    raise EventNormalizationError('Invalid DNS question')
                name = _string(question.get('rrname'),'dns.queries.rrname',1024)
                if name is None:
                    raise EventNormalizationError('DNS question name required')
                questions.append({'rrname':name, **({'rrtype':_string(question['rrtype'],'dns.queries.rrtype',128)} if 'rrtype' in question else {})})
            encoded_questions = canonical_json(questions)
            if len(encoded_questions) > 4096:
                raise EventNormalizationError('DNS questions exceed supported bytes')
            attrs['dns_questions_json'] = encoded_questions
            primary = questions[0]['rrname']
            original_name = _string(detail.get('rrname'),'dns.rrname',1024)
            if original_name is not None and original_name.rstrip('.').lower() != primary.rstrip('.').lower():
                raise EventNormalizationError('Conflicting DNS question identities')
            detail = {**detail,'rrname':primary}
            if len(questions) > 1:
                warnings.append('MULTIPLE_DNS_QUESTIONS')
        if 'grouped' in detail:
            grouped = detail['grouped']
            if not isinstance(grouped,dict) or len(grouped) > 32:
                raise EventNormalizationError('Invalid grouped DNS answers')
            values = {}
            total = 0
            for rrtype, records in grouped.items():
                _string(rrtype,'dns.grouped.rrtype',128)
                if not isinstance(records,list):
                    raise EventNormalizationError('Invalid grouped DNS answer records')
                total += len(records)
                if total > 32:
                    raise EventNormalizationError('Grouped DNS answer count exceeded')
                values[rrtype] = [_string(value,'dns.grouped.rdata',1024) for value in records]
            encoded_grouped = canonical_json(values)
            if len(encoded_grouped) > 4096:
                raise EventNormalizationError('Grouped DNS answer bytes exceeded')
            attrs['dns_grouped_answers_json'] = encoded_grouped
    mappings = {
        'dns': (('query' if zeek else 'rrname', 'dns_question_name', 1024),
                ('rcode_name' if zeek else 'rcode', 'dns_response_code', 128)),
        'http': (('host' if zeek else 'hostname', 'http_host', 1024),
                 ('uri' if zeek else 'url', 'url_path', 2048)),
        'ssl': (('server_name', 'tls_server_name', 1024),),
        'tls': (('sni', 'tls_server_name', 1024),),
    }
    for key, target, maximum in mappings.get(stream, ()):
        value = _string(detail.get(key), key, maximum)
        if value is not None:
            attrs[target] = value
    answers = detail.get('answers')
    if answers is not None:
        if not isinstance(answers, list) or len(answers) > 32:
            raise EventNormalizationError('DNS answers exceed supported bounds')
        normalized_answers = []
        for answer in answers:
            # EVE answer objects and Zeek string arrays retain their distinct shape.
            if zeek:
                normalized_answers.append(_string(answer, 'dns.answers', 1024))
            elif isinstance(answer, dict):
                item = {key: _string(answer[key], 'dns.answers', 1024)
                        for key in ('rrname', 'rrtype', 'rdata') if key in answer}
                if 'ttl' in answer:
                    item['ttl'] = _integer(answer['ttl'],'dns.answers.ttl',2**32-1)
                normalized_answers.append(item)
            else:
                raise EventNormalizationError('Invalid DNS answer')
        encoded_answers = canonical_json(normalized_answers)
        if len(encoded_answers) > 4096:
            raise EventNormalizationError('DNS answers exceed supported bytes')
        attrs['dns_answers_json'] = encoded_answers
    if ('source_ip' not in patch or 'destination_ip' not in patch
            or stream == 'dns' and 'dns_question_name' not in attrs):
        warnings.append('SOURCE_CONTEXT_INCOMPLETE')
    severity, rule_id, action = None, None, 'observe'
    if stream == 'alert':
        signature = _integer(detail.get('signature_id'), 'signature_id', 2**32 - 1)
        if signature is None:
            raise EventNormalizationError('Suricata alert signature is required')
        rule_id = str(signature)
        rank = _integer(detail.get('severity'), 'alert.severity', 255)
        severity = {1: 12, 2: 8, 3: 4}.get(rank)
        for key in ('signature', 'category', 'action'):
            value = _string(detail.get(key), key, 1024)
            if value is not None:
                attrs['signature_' + key] = value
        action = 'alert'
    raw = {
        'timestamp': occurred.isoformat(), 'id': envelope.source_event_id,
        'agent': {'id': binding.source_id, 'name': binding.sensor_name},
        'manager': {'name': binding.collector_id},
        'decoder': {'name': 'm34-zeek' if zeek else 'm34-suricata'},
        'data': {'source_generation': binding.source_generation, 'stream': stream,
                 'source_type': binding.source_type, 'payload_sha256': envelope.integrity_fingerprint,
                 'network_event': redact_sensitive_payload(payload)},
        'rule': {'description': f'{binding.source_type} {stream} observation'},
    }
    base = _normalize_legacy_wazuh_event(raw, ingestion_source='collection:' + binding.source_id)
    metadata = CUSEMetadata(
        adapter_version='m34-network-v1', source_family='ZEEK' if zeek else 'SURICATA',
        normalization_status='PARTIAL' if len(warnings) > 1 else 'NORMALIZED', provenance_status='PARTIAL', transport_authenticated=True,
        source_event_time=occurred, collector_observation_time=envelope.observed_timestamp,
        timestamp_basis='SOURCE_EVENT_TIME', original_event_identity=envelope.source_event_id,
        source_identity_sha256=digest([binding.source_id, binding.source_type, binding.collector_id, binding.source_generation]),
        content_fingerprint=base.deduplication_id, idempotency_contract='REGISTERED_SOURCE_RECORD_SHA256',
        delivery_identity=envelope.delivery_identity, source_generation=binding.source_generation,
        warnings=warnings, attributes=redact_sensitive_payload(attrs),
    )
    values = base.model_dump()
    values.update(patch, event_id=source_record_identity(raw),
                  source_event_id='COLL-' + digest([binding.source_id, binding.source_generation, envelope.source_event_id]),
                  normalization_schema='collection-event-v1',
                  source_type='network', event_provider='Zeek' if zeek else 'Suricata', event_channel=stream,
                  event_category='network_' + ('tls' if stream == 'ssl' else stream), event_action=action,
                  outcome='observed', rule_id=rule_id, severity=severity,
                  structured_payload={**base.structured_payload, '_cuse': metadata.model_dump(mode='json')})
    return NormalizedSecurityEvent.model_validate(values)
