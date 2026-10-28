"""Bounded collection observations; parser capability is never connectivity."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone

from app.schemas.collection import SourceBinding

FAMILIES = ('WINDOWS_EVENTCHANNEL', 'SYSMON', 'LINUX_AUTH', 'SYSLOG', 'JOURNALD', 'WAZUH_GENERIC', 'ZEEK', 'SURICATA')


class CollectionRegistry:
    def __init__(self, bindings: tuple[SourceBinding, ...] = (), *, synthetic=False):
        if len(bindings) > 32 or any(not isinstance(value, SourceBinding) for value in bindings):
            raise ValueError('Invalid source registration')
        self.bindings = {value.source_id: value for value in bindings}
        if len(self.bindings) != len(bindings):
            raise ValueError('Duplicate source registration')
        if len({value.source_key_sha256 for value in bindings}) != len(bindings):
            raise ValueError('Distinct source key digests are required for source-scoped authentication')
        self.synthetic = synthetic
        self._lock = threading.Lock()
        self._read_slot = threading.BoundedSemaphore(1)
        self._counters: dict[str, Counter] = {key: Counter() for key in self.bindings}
        self._commits: dict[str, str] = {}

    def record(self, source_id: str, outcome: str):
        with self._lock:
            if source_id in self._counters:
                self._counters[source_id][outcome] += 1
                if outcome in {'inserted', 'duplicate'}:
                    self._commits[source_id] = datetime.now(timezone.utc).isoformat()

    def coverage(self, repository):
        if not self._read_slot.acquire(blocking=False):
            raise sqlite3.OperationalError('source coverage busy')
        try:
            return self._coverage(repository)
        finally:
            self._read_slot.release()

    def _coverage(self, repository):
        # Existing occurred_at index, bounded sample and existing source DB only.
        # This is retained-event evidence, not an independent collection health probe.
        began = time.perf_counter()
        with closing(sqlite3.connect(repository.path.as_uri() + '?mode=ro', uri=True, timeout=.1)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA query_only=ON')
            connection.set_progress_handler(lambda: int(time.perf_counter() - began > 1.5), 1000)
            rows = connection.execute(
                "SELECT json_extract(e.structured_json,'$._cuse.source_family') AS family,"
                "json_extract(e.structured_json,'$._cuse.normalization_status') AS normalization_status,"
                'e.occurred_at,e.ingested_at,e.agent_id,e.event_id FROM security_events e '
                'ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT 1001'
            ).fetchall()
        truncated = len(rows) > 1000
        counts = Counter()
        last: dict[str, tuple[str, str]] = {}
        normalized = Counter()
        latest_ids = {}
        by_source = Counter()
        source_last = {}
        for row in rows[:1000]:
            if time.perf_counter() - began > 1.5:
                raise sqlite3.OperationalError('bounded source coverage deadline')
            family = row['family']
            if family not in FAMILIES:
                continue
            counts[family] += 1
            latest_ids.setdefault(family, row['event_id'])
            stamp = (row['occurred_at'], row['ingested_at'])
            last[family] = (max(stamp[0], last.get(family, stamp)[0]),
                            max(stamp[1], last.get(family, stamp)[1]))
            normalized[family] += int(row['normalization_status'] == 'NORMALIZED')
            key = (family, row['agent_id'])
            by_source[key] += 1
            source_last[key] = (max(stamp[0], source_last.get(key, stamp)[0]),
                                max(stamp[1], source_last.get(key, stamp)[1]))
        with self._lock:
            counters = {key: dict(value) for key, value in self._counters.items()}
            commits = dict(self._commits)
        registered = []
        now = datetime.now(timezone.utc)
        for binding in self.bindings.values():
            family = 'ZEEK' if binding.source_type == 'ZEEK_JSON' else 'SURICATA'
            committed_at = commits.get(binding.source_id)
            sample = source_last.get((family, binding.source_id))
            registered.append({
                'source_id': binding.source_id, 'source_type': binding.source_type,
                'host': binding.sensor_name, 'collector_id': binding.collector_id,
                'source_generation': binding.source_generation, 'configuration_authority': 'EXPLICIT_DISPOSABLE_CONSTRUCTOR',
                'configured': True, 'connected': 'UNKNOWN',
                'delivery_state': 'OBSERVED_COMMIT' if committed_at else 'UNKNOWN',
                'last_committed_delivery_at': committed_at, 'last_acknowledged_delivery': None,
                'sample_event_count': by_source[(family, binding.source_id)],
                'last_event_time': sample[0] if sample else None,
                'last_ingestion_time': sample[1] if sample else None,
                'queue_backlog': None, 'retry_count': None, 'dead_letter_count': None,
                'process_counters': counters[binding.source_id], 'counter_scope': 'SINCE_APPLICATION_START',
                'family': family,
            })
        return {
            'contract': 'cq-source-coverage-v1', 'observed_at': now.isoformat(),
            'scope': 'SYNTHETIC_TEST' if self.synthetic else 'UNKNOWN',
            'coverage': 'PARTIAL_SAMPLE' if truncated else 'RETAINED_SAMPLE',
            'sample_limit': 1000, 'sample_count': min(len(rows), 1000), 'truncated': truncated,
            'historical_continuity': 'UNPROVEN', 'production_active': False,
            'registered_sources': registered,
            'families': [{
                'family': family, 'parser_available': True,
                'observed': counts[family] > 0, 'sample_event_count': counts[family],
                'sample_normalized_count': normalized[family],
                'last_event_time': last[family][0] if family in last else None,
                'last_ingestion_time': last[family][1] if family in last else None,
                'latest_event_id': latest_ids.get(family),
                'freshness': ('STALE' if (now - datetime.fromisoformat(last[family][1])).total_seconds() > 300 else 'OBSERVED')
                    if family in last else 'UNKNOWN',
                'search_fields_available': True, 'detection_eligible': 'UNKNOWN',
                'connected': 'UNKNOWN', 'queue_backlog': None,
            } for family in FAMILIES],
        }
