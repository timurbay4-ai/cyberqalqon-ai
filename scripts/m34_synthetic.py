"""Small explicitly synthetic source fixtures, no capture/collector activation."""
from datetime import datetime, timezone
import hashlib

from app.schemas.collection import SourceBinding
from app.services.network_telemetry import digest

SOURCE_KEY = 'SYNTHETIC-ONLY-m34-source-key-0001'
SURICATA_SOURCE_KEY = 'SYNTHETIC-ONLY-m34-suricata-key-0002'
MACHINE_KEY = 'SYNTHETIC-ONLY-m34-machine-key-0001'


def source_key(source_type='ZEEK_JSON'):
    return SOURCE_KEY if source_type == 'ZEEK_JSON' else SURICATA_SOURCE_KEY


def binding(source_type='ZEEK_JSON'):
    return SourceBinding(
        source_id='synthetic-zeek' if source_type == 'ZEEK_JSON' else 'synthetic-suricata',
        source_type=source_type, collector_id='synthetic-collector', source_generation='synthetic-generation-1',
        sensor_name='SYNTHETIC-M34-SENSOR',
        source_key_sha256=hashlib.sha256(source_key(source_type).encode()).hexdigest())


def envelope(stream='dns', *, source_type='ZEEK_JSON', record='record-1', at=None):
    at = at or datetime.now(timezone.utc).replace(microsecond=0)
    source = binding(source_type)
    if source_type == 'ZEEK_JSON':
        payload = {'ts': at.timestamp(), 'uid': 'SYNTHETIC-CONNECTION-1', 'id.orig_h': '192.0.2.34',
                   'id.resp_h': '198.51.100.34', 'id.orig_p': 50334, 'id.resp_p': 53, 'proto': 'udp'}
        if stream == 'conn':
            payload['duration'] = 1.25
        elif stream == 'dns':
            payload.update(query='synthetic.example.test', rcode_name='NOERROR', answers=['203.0.113.34'])
        elif stream == 'http':
            payload.update(host='synthetic.example.test', uri='/synthetic-path')
        elif stream == 'ssl':
            payload['server_name'] = 'synthetic.example.test'
    else:
        payload = {'timestamp': at.isoformat(), 'event_type': stream, 'flow_id': 34001,
                   'src_ip': '192.0.2.34', 'dest_ip': '198.51.100.34', 'src_port': 50334, 'dest_port': 443, 'proto': 'TCP'}
        payload[stream] = {
            'alert': {'signature_id': 34001, 'severity': 2, 'action': 'allowed', 'signature': 'SYNTHETIC test signature'},
            'dns': {'rrname': 'synthetic.example.test', 'rcode': 'NOERROR', 'answers': [{'rrname': 'synthetic.example.test', 'rrtype': 'A', 'rdata': '203.0.113.34'}]},
            'http': {'hostname': 'synthetic.example.test', 'url': '/synthetic-path'},
            'tls': {'sni': 'synthetic.example.test'},
            'flow': {'age': 5},
        }[stream]
    return {'contract': 'cq-collection-v1', 'source_id': source.source_id, 'source_type': source.source_type,
            'collector_id': source.collector_id, 'collector_version': 'synthetic-v1',
            'source_generation': source.source_generation, 'source_event_id': record,
            'delivery_identity': 'delivery-' + record, 'checkpoint_identity': 'checkpoint-' + record,
            'stream': stream, 'event_timestamp': at.isoformat(), 'observed_timestamp': at.isoformat(),
            'integrity_fingerprint': digest(payload), 'payload': payload}
