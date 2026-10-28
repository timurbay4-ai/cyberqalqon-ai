"""Compact crash-recovery witness for a bounded candidate set; no source writes."""
from __future__ import annotations

import re

from app.services.wazuh_normalizer import canonical_json
import hashlib

VERSION = 'm35-bounded-snapshot-intent-v1'


def digest(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def create_intent(store_id, source_binding, request_body, manifest):
    if (manifest.get('version') != 'm31-bounded-snapshot-v1'
            or type(manifest.get('truncated')) is not bool
            or not isinstance(manifest.get('entries'), list) or len(manifest['entries']) > 1000):
        raise ValueError('INVALID_RECOVERY_INTENT')
    intent = {'version': VERSION, 'source_binding': source_binding,
              'manifest_sha256': digest(manifest), 'candidate_rows': len(manifest['entries']),
              'candidate_truncated': manifest['truncated']}
    return {**intent, 'intent_sha256': digest([store_id, request_body, intent])}


def validate_intent(store_id, source_binding, request_body, intent):
    keys = {'version', 'source_binding', 'manifest_sha256', 'candidate_rows',
            'candidate_truncated', 'intent_sha256'}
    if (not isinstance(intent, dict) or set(intent) != keys or intent['version'] != VERSION
            or intent['source_binding'] != source_binding
            or type(intent['candidate_rows']) is not int or not 0 <= intent['candidate_rows'] <= 1000
            or type(intent['candidate_truncated']) is not bool
            or any(not isinstance(intent[key], str) or re.fullmatch(r'[a-f0-9]{64}', intent[key]) is None
                   for key in ('manifest_sha256', 'source_binding', 'intent_sha256'))):
        raise ValueError('INVALID_RECOVERY_INTENT')
    unsigned = {key: value for key, value in intent.items() if key != 'intent_sha256'}
    if digest([store_id, request_body, unsigned]) != intent['intent_sha256']:
        raise ValueError('INVALID_RECOVERY_INTENT')
    return intent
