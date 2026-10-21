"""Capture a bounded, read-only local lab health snapshot and record transitions.

The collector does not run as a daemon and does not change Wazuh, Windows
services, firewall rules, or enrollment. It records only sanitized metrics.
"""

from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
DEFAULT_DATABASE = BACKEND_ROOT / "data" / "cyberqalqon-local-lab.db"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "artifacts" / "runtime" / "operational-health.json"
sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import Settings  # noqa: E402
from app.db.operations import OperationalRepository  # noqa: E402
from app.schemas.operations import ComponentObservation, OperationalSnapshot  # noqa: E402
from app.services.wazuh_api import WazuhApiClient  # noqa: E402
from app.services.windows_agent_diagnostics import collect_windows_diagnostic  # noqa: E402


def _run(arguments: list[str], *, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )


def _wsl(distro: str, command: str) -> subprocess.CompletedProcess[str]:
    return _run(["wsl.exe", "-d", distro, "-u", "root", "--", "bash", "-lc", command])


def _component(
    key: str,
    kind: str,
    state: str,
    authority: str,
    summary: str,
    observed_at: datetime,
    *,
    metrics: dict[str, Any] | None = None,
    last_error: str | None = None,
) -> ComponentObservation:
    return ComponentObservation(
        component_key=key,
        component_kind=kind,
        state=state,
        authority=authority,
        summary=summary,
        metrics=metrics or {},
        last_error=last_error,
        observed_at=observed_at,
    )


def _m17_rate_metrics(*, archive_inode: int, now: datetime) -> dict[str, Any]:
    """Load one bounded sampler result; never scan the archive for a dashboard."""

    summary_path = REPOSITORY_ROOT / "artifacts" / "runtime" / "m17-rate-summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        captured_at = datetime.fromisoformat(str(summary["captured_at"]))
        age = max(0.0, (now - captured_at.astimezone(timezone.utc)).total_seconds())
        if int(summary["archive_inode"]) != archive_inode:
            raise ValueError("rate summary belongs to an older archive generation")
        rates = summary["rates_per_second"]
        deltas = summary["deltas"]
        return {
            "rate_snapshot_status": "FRESH" if age <= 900 else "STALE",
            "rate_snapshot_captured_at": captured_at.isoformat(),
            "rate_snapshot_age_seconds": round(age, 3),
            "rate_sample_duration_seconds": float(summary["window_seconds"]),
            "rate_sample_count": int(summary["sample_count"]),
            "archive_growth_bytes_per_second": float(rates["archive_growth_bytes"]),
            "cursor_progress_bytes_per_second": float(rates["cursor_progress_bytes"]),
            "net_archive_lag_bytes_per_second": float(rates["net_archive_lag_bytes"]),
            "successful_acknowledgements_per_second": float(
                rates["successful_acknowledgements_v2_mixed"]
            ),
            "filtered_records_per_second": float(rates["filtered_records"]),
            "sample_malformed_records": int(deltas["malformed_records"]),
            "sample_retry_attempts": int(deltas["retry_attempts"]),
            "backlog_trend": str(summary.get("backlog_trend", "UNKNOWN")),
            "estimated_drain_seconds": summary.get("estimated_drain_seconds"),
            "estimate_qualification": "MULTI_ENDPOINT_SAME_GENERATION_WINDOW",
        }
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        pass
    path = REPOSITORY_ROOT / "artifacts" / "runtime" / "m17-live-rate-sample.json"
    try:
        sample = json.loads(path.read_text(encoding="utf-8"))
        captured_at = datetime.fromisoformat(str(sample["captured_at"]))
        age = max(0.0, (now - captured_at.astimezone(timezone.utc)).total_seconds())
        end_shipper = sample["end"]["shipper"]
        if int(end_shipper["archive_inode"]) != archive_inode:
            return {
                "rate_snapshot_status": "STALE_ARCHIVE_GENERATION",
                "rate_snapshot_captured_at": captured_at.isoformat(),
                "rate_snapshot_age_seconds": round(age, 3),
            }
        rates = sample["rates_per_second"]
        deltas = sample["deltas"]
        return {
            "rate_snapshot_status": "FRESH" if age <= 900 else "STALE",
            "rate_snapshot_captured_at": captured_at.isoformat(),
            "rate_snapshot_age_seconds": round(age, 3),
            "rate_sample_duration_seconds": float(sample["duration_seconds"]),
            "archive_growth_bytes_per_second": float(rates["archive_growth_bytes"]),
            "cursor_progress_bytes_per_second": float(rates["cursor_progress_bytes"]),
            "net_archive_lag_bytes_per_second": float(rates["net_archive_lag_bytes"]),
            "successful_acknowledgements_per_second": float(
                rates["successful_acknowledgements"]
            ),
            "filtered_records_per_second": float(rates["filtered_records"]),
            "sample_malformed_records": int(deltas["malformed"]),
            "sample_retry_attempts": int(deltas["retry_attempts"]),
            "backlog_trend": str(sample.get("backlog_trend", "UNKNOWN")),
            "estimated_drain_seconds": (
                float(sample["estimated_drain_seconds"])
                if sample.get("estimated_drain_seconds") is not None
                else None
            ),
            "estimate_qualification": "SINGLE_BOUNDED_SAMPLE_NOT_SUSTAINED",
        }
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return {
            "rate_snapshot_status": "UNKNOWN",
            "rate_snapshot_captured_at": None,
            "rate_snapshot_age_seconds": None,
        }


def manager_observation(distro: str, now: datetime) -> ComponentObservation:
    result = _wsl(
        distro,
        "printf '%s\\n' \"$(systemctl is-active wazuh-manager 2>/dev/null || true)\" "
        "\"$(hostname)\" \"$(/var/ossec/bin/wazuh-control info 2>/dev/null "
        "| sed -n 's/^WAZUH_VERSION=\"\\(.*\\)\"/\\1/p' | head -n1)\"",
    )
    lines = [line.strip() for line in result.stdout.splitlines()]
    active = result.returncode == 0 and bool(lines) and lines[0] == "active"
    identity = lines[1][:255] if len(lines) > 1 and lines[1] else None
    version = lines[2][:64] if len(lines) > 2 and lines[2] else None
    return _component(
        "wazuh-manager-runtime",
        "manager",
        "HEALTHY" if active else "UNAVAILABLE",
        "OS_SERVICE_MANAGER",
        "Wazuh Manager service is active." if active else "Wazuh Manager service is not active.",
        now,
        metrics={"service_active": active, "identity": identity, "version": version},
        last_error=None if active else "systemd did not report wazuh-manager active",
    )


def api_observation(settings: Settings, now: datetime) -> ComponentObservation:
    inventory = WazuhApiClient(settings).fetch_inventory()
    metrics: dict[str, Any] = {
        "agent_count": len(inventory.agents) if inventory.available else None,
        "manager_identity": inventory.manager_identity,
    }
    return _component(
        "wazuh-manager-api",
        "wazuh_api",
        "HEALTHY" if inventory.available else "UNAVAILABLE",
        "WAZUH_API",
        inventory.reason,
        now,
        metrics=metrics,
        last_error=None if inventory.available else inventory.reason,
    )


def sender_observation(distro: str, now: datetime, settings: Settings) -> ComponentObservation:
    service = _wsl(distro, "systemctl is-active cyberqalqon-sender.service")
    service_active = service.returncode == 0 and service.stdout.strip() == "active"
    result = _wsl(
        distro,
        "set -a; . /etc/cyberqalqon/sender.env; set +a; "
        "/opt/cyberqalqon-sender/.venv/bin/cyberqalqon-sender status --json",
    )
    try:
        status = json.loads(result.stdout)
        queue = status["queue"]
        dead = status["dead_letter"]
        counters = status["counters"]
        queue_depth = max(0, int(queue.get("depth", 0)))
        queue_bytes = max(0, int(queue.get("payload_bytes", 0)))
        dead_count = max(0, int(dead.get("count", 0)))
        dead_bytes = max(0, int(dead.get("payload_bytes", 0)))
        terminal = max(0, int(queue.get("terminal_blocked", 0)))
        oldest_raw = queue.get("oldest_pending_age_seconds")
        oldest_age = float(oldest_raw) if oldest_raw is not None else None
        degraded = (
            dead_count > 0
            or terminal > 0
            or queue_depth >= settings.operational_queue_warning_depth
            or queue_bytes >= settings.operational_queue_warning_bytes
            or (
                oldest_age is not None
                and oldest_age >= settings.operational_oldest_pending_warning_seconds
            )
        )
        state = "UNAVAILABLE" if not service_active else ("DEGRADED" if degraded else "HEALTHY")
        metrics = {
            "service_active": service_active,
            "queue_depth": queue_depth,
            "queue_bytes": queue_bytes,
            "pending": max(0, int(queue.get("pending", 0))),
            "in_flight": max(0, int(queue.get("in_flight", 0))),
            "terminal_blocked": terminal,
            "oldest_pending_age_seconds": oldest_age,
            "queue_warning_threshold": settings.operational_queue_warning_depth,
            "queue_bytes_warning_threshold": settings.operational_queue_warning_bytes,
            "oldest_pending_warning_seconds": settings.operational_oldest_pending_warning_seconds,
            "dead_letter_count": dead_count,
            "dead_letter_bytes": dead_bytes,
            "retry_count": max(0, int(counters.get("retries", 0))),
            "delivered": max(0, int(counters.get("delivered", 0))),
            "duplicate_deliveries": max(0, int(counters.get("duplicates", 0))),
            "transient_failures": max(0, int(counters.get("transient_failures", 0))),
            "permanent_failures": max(0, int(counters.get("permanent_failures", 0))),
            "queue_rejected": max(0, int(counters.get("queue_rejected", 0))),
            "dead_letter_blocked": max(0, int(counters.get("dead_letter_blocked", 0))),
            "last_success_at": status.get("last_success_at"),
            "last_failure_at": status.get("last_failure_at"),
            "last_failure_category": status.get("last_failure_category"),
        }
        return _component(
            "wazuh-alert-sender",
            "sender",
            state,
            "DURABLE_SENDER_STATE",
            "Sender service is active and its durable queue is empty."
            if state == "HEALTHY"
            else "Sender service or durable queue requires attention.",
            now,
            metrics=metrics,
            last_error=status.get("last_safe_error") if state != "HEALTHY" else None,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _component(
            "wazuh-alert-sender",
            "sender",
            "UNAVAILABLE",
            "DURABLE_SENDER_STATE",
            "Durable sender status could not be read.",
            now,
            last_error="bounded sender status command failed",
        )


def shipper_observation(
    distro: str,
    now: datetime,
    settings: Settings,
    *,
    deep_backlog_audit: bool = False,
) -> ComponentObservation:
    command = rf'''/opt/cyberqalqon-sender/.venv/bin/python3 - <<'PY'
import hashlib, json, os, subprocess, sys, time, urllib.request
sys.path.insert(0, '/opt/cyberqalqon-sender')
from cyberqalqon_sender.event_shipper import select_archive_event
state_path='/var/lib/cyberqalqon-sender/event-shipper-state.json'
archive_path='/var/ossec/logs/archives/archives.json'
deep_audit={str(deep_backlog_audit)}
try:
    state=json.load(open(state_path, encoding='utf-8'))
    stat=os.stat(archive_path)
    current_generation_id=hashlib.sha256(f'active-archive-v1:{{stat.st_dev}}:{{stat.st_ino}}'.encode()).hexdigest()
    m16_dir='/var/lib/cyberqalqon-sender/m16'
    historical={{'eligible_records':None,'filtered_records':None,'generation_id':None,'source_available':False,'replay_state':'NOT_CONFIGURED'}}
    forward={{'state':'NOT_DEPLOYED','service_active':False,'approval_present':False}}
    forward_root='/var/lib/cyberqalqon-forward/m22-forward'
    if os.path.isdir(forward_root):
        candidates=[]
        for name in os.listdir(forward_root):
            candidate=os.path.join(forward_root,name)
            if name.endswith('.json') and not os.path.islink(candidate) and os.path.isfile(candidate):
                candidates.append(candidate)
        if len(candidates) > 1:
            forward={{'state':'BLOCKED','service_active':False,'approval_present':os.path.isfile('/etc/cyberqalqon/forward-approval.json'),'failure':'AMBIGUOUS_CHECKPOINT'}}
        elif len(candidates) == 1:
            fstate=json.load(open(candidates[0], encoding='utf-8'))
            source=os.stat(str(fstate['source_path']))
            source_match=(int(fstate['source_device']) == source.st_dev and int(fstate['source_inode']) == source.st_ino and int(fstate['offset']) <= source.st_size)
            legacy_match=False
            legacy_path=fstate.get('legacy_state_path')
            if legacy_path and os.path.isfile(legacy_path):
                legacy_match=hashlib.sha256(open(legacy_path,'rb').read()).hexdigest() == fstate.get('legacy_state_sha256')
            forward_active=subprocess.run(['systemctl','is-active','cyberqalqon-forward-ingestion.service'],capture_output=True,text=True).stdout.strip()=='active'
            terminal=bool(fstate.get('terminal_blocked',False)) or str(fstate.get('status')) == 'BLOCKED'
            approval_path='/etc/cyberqalqon/forward-approval.json'
            approval_present=os.path.isfile(approval_path)
            approval_state='ABSENT'
            approval_expiry=None
            approval_remaining=None
            approval_sha=None
            if approval_present:
                try:
                    approval_bytes=open(approval_path,'rb').read()
                    approval=json.loads(approval_bytes)
                    approval_stat=os.stat(approval_path)
                    approval_sha=hashlib.sha256(approval_bytes).hexdigest()
                    approval_expiry=float(approval.get('expires_at_epoch'))
                    issued=float(approval.get('issued_at_epoch'))
                    security_scope=(
                        approval_stat.st_uid == 0 and approval_stat.st_mode & 0o022 == 0
                        and approval.get('version') == 1
                        and approval.get('decision') == 'APPROVED'
                        and approval.get('purpose') == 'M22_LIVE_FORWARD_INGESTION'
                        and approval.get('historical_continuity') == 'UNPROVEN'
                        and approval.get('accepts_unproven_history') is True
                        and approval.get('historical_replay_approved') is False
                        and approval.get('legacy_checkpoint_mutation_approved') is False
                        and approval.get('single_event_ingestion_only') is True
                        and approval.get('contains_raw_payload') is False
                    )
                    identity_scope=(
                        approval.get('generation_id') == fstate.get('generation_id')
                        and int(approval.get('source_device',-1)) == int(fstate.get('source_device',-2))
                        and int(approval.get('source_inode',-1)) == int(fstate.get('source_inode',-2))
                        and int(approval.get('start_offset',-1)) == int(fstate.get('start_offset',-2))
                        and approval.get('start_prefix_sha256') == fstate.get('start_prefix_sha256')
                        and approval.get('legacy_state_sha256') == fstate.get('legacy_state_sha256')
                        and approval.get('legacy_cursor') == fstate.get('legacy_cursor_at_registration')
                    )
                    window_valid=issued <= time.time()+300 and approval_expiry > issued and approval_expiry-issued <= 86400
                    approval_remaining=max(0.0,approval_expiry-time.time())
                    approval_state=(
                        'INVALID' if not security_scope or not window_valid
                        else 'MISMATCH' if not identity_scope
                        else 'EXPIRED' if approval_expiry <= time.time()
                        else 'VALID'
                    )
                except Exception:
                    approval_state='INVALID'
            forward={{
                'state':'BLOCKED' if terminal or not source_match or not legacy_match else 'ACTIVE' if forward_active else 'READY',
                'service_active':forward_active,
                'approval_present':approval_present,
                'approval_state':approval_state,
                'approval_expires_at':approval_expiry,
                'approval_remaining_seconds':approval_remaining,
                'approval_sha256':approval_sha,
                'generation_id':fstate.get('generation_id'),
                'source_device':source.st_dev,
                'source_inode':source.st_ino,
                'source_size':source.st_size,
                'start_offset':fstate.get('start_offset'),
                'cursor':fstate.get('offset'),
                'byte_lag':max(0,source.st_size-int(fstate.get('offset',0))) if fstate.get('compression') == 'NONE' else None,
                'accepted':fstate.get('accepted'),
                'duplicates':fstate.get('duplicates'),
                'filtered':fstate.get('filtered'),
                'malformed':fstate.get('malformed'),
                'retry_attempts':fstate.get('retry_attempts'),
                'protocol_errors':fstate.get('protocol_errors'),
                'delivery_rejected':fstate.get('delivery_rejected'),
                'last_success_at':fstate.get('last_success_at_epoch'),
                'checkpoint_updated_at':fstate.get('updated_at_epoch'),
                'source_identity_matches':source_match,
                'legacy_state_unchanged':legacy_match,
            }}
    tail_path=os.path.join(m16_dir,'rotated-tail-audit.json')
    if os.path.isfile(tail_path):
        tail=json.load(open(tail_path, encoding='utf-8'))
        inventory=tail.get('inventory', {{}})
        historical.update({{'eligible_records':inventory.get('eligible_records'),'filtered_records':inventory.get('filtered_records'),'generation_id':tail.get('generation_id'),'source_available':True}})
        replay_path=os.path.join(m16_dir,'replay',f"{{tail.get('generation_id')}}.json")
        if os.path.isfile(replay_path):
            replay=json.load(open(replay_path, encoding='utf-8'))
            historical['replay_state']=str(replay.get('status','PAUSED'))
    active=subprocess.run(['systemctl','is-active','cyberqalqon-event-shipper.service'],capture_output=True,text=True).stdout.strip()=='active'
    try:
        with urllib.request.urlopen('http://127.0.0.1:18000/health', timeout=2) as response:
            backend_reachable=response.status == 200
    except Exception:
        backend_reachable=False
    audit={{'status':'NOT_REQUESTED','unread_records':None,'eligible_records':None,'filtered_records':None,'malformed_records':None,'oversized_records':None,'partial_tail_records':None,'scan_seconds':None}}
    if deep_audit:
        started=time.monotonic()
        counts={{'unread_records':0,'eligible_records':0,'filtered_records':0,'malformed_records':0,'oversized_records':0,'partial_tail_records':0}}
        limit=stat.st_size
        offset=max(0, int(state.get('offset', 0)))
        if int(state.get('device', -1)) != stat.st_dev or int(state.get('inode', -1)) != stat.st_ino or offset > limit:
            audit['status']='IDENTITY_MISMATCH'
        else:
            with open(archive_path, 'rb') as stream:
                stream.seek(offset)
                while stream.tell() < limit:
                    remaining=limit-stream.tell()
                    line=stream.readline(min(262145, remaining))
                    if not line:
                        break
                    if len(line) > 262144 or (not line.endswith(b'\n') and stream.tell() < limit):
                        counts['unread_records'] += 1
                        counts['oversized_records'] += 1
                        while stream.tell() < limit and not line.endswith(b'\n'):
                            line=stream.readline(min(65536, limit-stream.tell()))
                        continue
                    if not line.endswith(b'\n'):
                        counts['partial_tail_records'] += 1
                        break
                    counts['unread_records'] += 1
                    try:
                        event=json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        counts['malformed_records'] += 1
                        continue
                    if isinstance(event, dict) and select_archive_event(event):
                        counts['eligible_records'] += 1
                    else:
                        counts['filtered_records'] += 1
            audit={{'status':'COMPLETE',**counts,'scan_seconds':round(time.monotonic()-started,3)}}
    rotated_count=sum(name.endswith('.json.gz') for _,_,files in os.walk(os.path.dirname(archive_path)) for name in files)
    print(json.dumps({{'service_active':active,'backend_reachable':backend_reachable,'archive_size':stat.st_size,'archive_mtime':stat.st_mtime,'archive_device':stat.st_dev,'archive_inode':stat.st_ino,'archive_generation_id':current_generation_id,'rotated_archive_count':rotated_count,'state':state,'backlog_audit':audit,'historical':historical,'forward':forward}}))
except Exception as exc:
    print(json.dumps({{'error_type':type(exc).__name__}}))
PY'''
    result = _wsl(distro, command)
    try:
        payload = json.loads(result.stdout)
        if "error_type" in payload:
            raise ValueError("shipper state unavailable")
        state_data = payload["state"]
        archive_size = max(0, int(payload["archive_size"]))
        offset = max(0, int(state_data.get("offset", 0)))
        lag_bytes = max(0, archive_size - offset)
        service_active = bool(payload.get("service_active"))
        backend_reachable = bool(payload.get("backend_reachable"))
        retry_attempts = max(0, int(state_data.get("retry_attempts", 0)))
        audit = payload.get("backlog_audit", {})
        if not isinstance(audit, dict):
            audit = {}
        historical = payload.get("historical", {})
        if not isinstance(historical, dict):
            historical = {}
        forward = payload.get("forward", {})
        if not isinstance(forward, dict):
            forward = {"state": "UNKNOWN"}
        blocked = service_active and not backend_reachable and lag_bytes > 0 and retry_attempts > 0
        backlog = lag_bytes >= settings.operational_shipper_lag_warning_bytes
        healthy = service_active and not blocked and not backlog
        metrics = {
            "service_active": service_active,
            "backend_reachable": backend_reachable,
            "archive_size_bytes": archive_size,
            "archive_cursor_bytes": offset,
            "archive_lag_bytes": lag_bytes,
            "archive_lag_warning_bytes": settings.operational_shipper_lag_warning_bytes,
            "archive_device": int(payload["archive_device"]),
            "archive_inode": int(payload["archive_inode"]),
            "archive_generation_id": str(payload["archive_generation_id"]),
            "cursor_device": max(0, int(state_data.get("device", 0))),
            "cursor_inode": max(0, int(state_data.get("inode", 0))),
            "archive_identity_matches_cursor": (
                int(payload["archive_device"]) == int(state_data.get("device", -1))
                and int(payload["archive_inode"]) == int(state_data.get("inode", -1))
            ),
            "rotated_archive_count": max(0, int(payload.get("rotated_archive_count", 0))),
            "historical_generation_id": historical.get("generation_id"),
            "historical_archive_available": bool(historical.get("source_available")),
            "historical_eligible_backlog": historical.get("eligible_records"),
            "historical_filtered_backlog": historical.get("filtered_records"),
            "historical_replay_state": str(historical.get("replay_state", "NOT_CONFIGURED")),
            "legacy_checkpoint_state": (
                "BLOCKED"
                if int(payload["archive_device"]) != int(state_data.get("device", -1))
                or int(payload["archive_inode"]) != int(state_data.get("inode", -1))
                or bool(state_data.get("terminal_blocked", False))
                else "ACTIVE"
                if service_active
                else "PAUSED"
            ),
            "legacy_continuity_status": "UNPROVEN",
            "forward_ingestion_state": str(forward.get("state", "UNKNOWN")),
            "forward_service_active": bool(forward.get("service_active", False)),
            "forward_approval_present": bool(forward.get("approval_present", False)),
            "forward_approval_state": str(forward.get("approval_state", "UNKNOWN")),
            "forward_approval_validation_basis": (
                "BOUNDED_SCOPE_TIME_IDENTITY"
                if forward.get("approval_state") in {{"VALID", "EXPIRED", "MISMATCH", "INVALID"}}
                else "UNKNOWN"
            ),
            "forward_approval_expires_at_epoch": forward.get("approval_expires_at"),
            "forward_approval_remaining_seconds": forward.get("approval_remaining_seconds"),
            "forward_approval_sha256": forward.get("approval_sha256"),
            "forward_generation_id": forward.get("generation_id"),
            "forward_source_device": forward.get("source_device"),
            "forward_source_inode": forward.get("source_inode"),
            "forward_source_size_bytes": forward.get("source_size"),
            "forward_start_offset_bytes": forward.get("start_offset"),
            "forward_cursor_bytes": forward.get("cursor"),
            "forward_lag_bytes": forward.get("byte_lag"),
            "forward_unique_insertions": forward.get("accepted"),
            "forward_duplicate_acknowledgements": forward.get("duplicates"),
            "forward_filtered_records": forward.get("filtered"),
            "forward_malformed_records": forward.get("malformed"),
            "forward_retry_attempts": forward.get("retry_attempts"),
            "forward_protocol_errors": forward.get("protocol_errors"),
            "forward_delivery_rejected": forward.get("delivery_rejected"),
            "forward_last_successful_delivery_epoch": forward.get("last_success_at"),
            "forward_checkpoint_updated_at_epoch": forward.get("checkpoint_updated_at"),
            "forward_cursor_progress_bytes_per_second": None,
            "forward_net_lag_bytes_per_second": None,
            "forward_backlog_trend": "UNKNOWN",
            "forward_rate_measurement_state": "UNKNOWN",
            "forward_unreconciled_historical_records": None,
            "forward_source_identity_matches": forward.get("source_identity_matches"),
            "forward_legacy_state_unchanged": forward.get("legacy_state_unchanged"),
            "backlog_audit_status": str(audit.get("status", "UNKNOWN")),
            "unread_record_backlog": audit.get("unread_records"),
            "eligible_record_backlog": audit.get("eligible_records"),
            "filtered_record_backlog": audit.get("filtered_records"),
            "malformed_record_backlog": audit.get("malformed_records"),
            "oversized_record_backlog": audit.get("oversized_records"),
            "partial_tail_record_backlog": audit.get("partial_tail_records"),
            "backlog_scan_seconds": audit.get("scan_seconds"),
            "accepted": max(0, int(state_data.get("accepted", 0))),
            "shipper_state_version": max(0, int(state_data.get("version", 0))),
            "unique_insertions": (
                max(0, int(state_data.get("accepted", 0)))
                if int(state_data.get("version", 0)) >= 3 else None
            ),
            "legacy_successful_acknowledgements": state_data.get(
                "legacy_successful_acknowledgements"
            ),
            "filtered_events": max(0, int(state_data.get("filtered_events", 0))),
            "malformed_json": max(0, int(state_data.get("malformed_json", 0))),
            "oversized_lines": max(0, int(state_data.get("oversized_lines", 0))),
            "delivery_rejected": max(0, int(state_data.get("delivery_rejected", 0))),
            "retry_attempts": retry_attempts,
            "duplicate_attempts": state_data.get("duplicate_attempts"),
            "historic_duplicate_acknowledgements": (
                state_data.get("duplicate_attempts")
                if int(state_data.get("version", 0)) >= 3 else None
            ),
            "protocol_errors": max(0, int(state_data.get("protocol_errors", 0))),
            "ingress_protocol": str(state_data.get("ingress_protocol", "single-v1")),
            "single_http_requests": max(
                0, int(state_data.get("single_http_requests", 0))
            ),
            "batch_http_requests": max(
                0, int(state_data.get("batch_http_requests", 0))
            ),
            "batch_events_acknowledged": max(
                0, int(state_data.get("batch_events_acknowledged", 0))
            ),
            "last_batch_size": max(0, int(state_data.get("last_batch_size", 0))),
            "terminal_blocked": bool(state_data.get("terminal_blocked", False)),
            "current_batch_size": state_data.get("current_batch_size"),
            "last_request_latency_ms": state_data.get("last_request_latency_ms"),
            "last_successful_delivery_epoch": state_data.get("last_success_at"),
            "delivery_rate_per_second": state_data.get("delivery_rate_per_second"),
            "state_updated_epoch": float(state_data.get("updated_at", 0)),
            "metric_source": "DURABLE_CURSOR_PLUS_POINT_IN_TIME_ARCHIVE_SCAN",
        }
        metrics.update(
            _m17_rate_metrics(
                archive_inode=int(payload["archive_inode"]),
                now=now,
            )
        )
        rate_status = metrics.get("rate_snapshot_status")
        rate_trend = metrics.get("backlog_trend")
        metrics["pipeline_condition"] = (
            "BLOCKED"
            if blocked or metrics["terminal_blocked"]
            else "RECOVERING"
            if backlog and rate_status == "FRESH" and rate_trend == "DRAINING"
            else "WARNING"
            if backlog and rate_status == "FRESH"
            else "UNKNOWN"
            if backlog
            else "HEALTHY"
        )
        return _component(
            "wazuh-event-shipper",
            "event_shipper",
            "HEALTHY" if healthy else ("UNAVAILABLE" if not service_active else "DEGRADED"),
            "DURABLE_SHIPPER_STATE",
            "Event shipper is advancing its durable archive cursor."
            if healthy
            else "Event shipper service is unavailable."
            if not service_active
            else "Event shipper cursor is blocked behind a retried delivery."
            if blocked
            else "Event shipper is active with backlog above the warning threshold.",
            now,
            metrics=metrics,
            last_error=(
                "event shipper service is not active"
                if not service_active
                else "delivery retry is preventing cursor advance"
                if blocked
                else "archive lag exceeded the configured threshold"
                if backlog
                else None
            ),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _component(
            "wazuh-event-shipper",
            "event_shipper",
            "UNAVAILABLE",
            "DURABLE_SHIPPER_STATE",
            "Durable event-shipper state could not be read.",
            now,
            last_error="bounded shipper state command failed",
        )


def windows_agent_observation(now: datetime) -> ComponentObservation:
    diagnostic = collect_windows_diagnostic()
    state = {
        "CONNECTED": "HEALTHY",
        "STATUS_UNKNOWN": "UNKNOWN",
        "SERVICE_STOPPED": "UNAVAILABLE",
        "MANAGER_UNREACHABLE": "DEGRADED",
        "ENROLLMENT_REQUIRED": "UNAVAILABLE",
        "ENROLLMENT_PORT_UNAVAILABLE": "UNAVAILABLE",
        "AUTHENTICATION_FAILED": "DEGRADED",
    }[diagnostic.classification]
    summary = {
        "CONNECTED": "Windows agent connection is confirmed by the Wazuh Manager.",
        "STATUS_UNKNOWN": "Windows agent is running, but the manager has not confirmed its connection.",
        "SERVICE_STOPPED": "Windows Wazuh agent service is not running.",
        "MANAGER_UNREACHABLE": "Windows agent manager endpoint is not reachable.",
        "ENROLLMENT_REQUIRED": "Windows agent requires supported enrollment.",
        "ENROLLMENT_PORT_UNAVAILABLE": "Windows agent requires enrollment, but the enrollment endpoint is unavailable.",
        "AUTHENTICATION_FAILED": "Windows agent logs contain an authentication failure signal.",
    }[diagnostic.classification]
    return _component(
        "windows-wazuh-agent",
        "windows_agent",
        state,
        "OS_SERVICE_MANAGER",
        summary,
        now,
        metrics={
            "classification": diagnostic.classification,
            "service_active": diagnostic.service_running,
            "service_start_mode": diagnostic.service_start_mode,
            "version": diagnostic.agent_version,
            "manager_address_class": diagnostic.manager_address_class,
            "manager_port": diagnostic.manager_port,
            "manager_reachable": diagnostic.configured_manager_reachable,
            "manager_matches_current_wsl": diagnostic.configured_manager_matches_current_wsl,
            "enrollment_enabled": diagnostic.enrollment_enabled,
            "enrollment_port": diagnostic.enrollment_port,
            "enrollment_port_reachable": diagnostic.enrollment_port_reachable,
            "enrollment_key_present": diagnostic.enrollment_key_present,
            "server_confirmed_connection": diagnostic.server_confirmed_connection,
            "loopback_relay_1514": diagnostic.loopback_relay_communication_reachable,
            "loopback_relay_1515": diagnostic.loopback_relay_enrollment_reachable,
            "protected_log_status": diagnostic.protected_log_status,
        },
        last_error=None if state in {"HEALTHY", "UNKNOWN"} else summary,
    )


def database_observation(database: Path, now: datetime) -> ComponentObservation:
    try:
        with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=5) as connection:
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
            events = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
            latest = connection.execute(
                "SELECT MAX(occurred_at), MAX(ingested_at) FROM security_events"
            ).fetchone()
        healthy = quick_check == "ok"
        return _component(
            "cyberqalqon-database",
            "database",
            "HEALTHY" if healthy else "DEGRADED",
            "APPLICATION_DATABASE",
            "SQLite quick_check passed." if healthy else "SQLite quick_check did not pass.",
            now,
            metrics={
                "quick_check": quick_check,
                "schema_version": schema,
                "security_events": events,
                "last_accepted_event_at": latest[0],
                "last_ingestion_at": latest[1],
                "size_bytes": database.stat().st_size,
            },
            last_error=None if healthy else "SQLite quick_check failed",
        )
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return _component(
            "cyberqalqon-database",
            "database",
            "UNAVAILABLE",
            "APPLICATION_DATABASE",
            "SQLite diagnostics could not be read.",
            now,
            last_error="bounded read-only database check failed",
        )


def source_observations(
    database: Path,
    now: datetime,
    settings: Settings,
) -> list[ComponentObservation]:
    try:
        with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=5) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT source_type, COALESCE(NULLIF(agent_id, ''), NULLIF(agent_name, ''),
                       NULLIF(hostname, ''), 'unattributed') AS identity,
                       MAX(occurred_at) AS last_event_at,
                       MAX(ingested_at) AS last_ingested_at,
                       COUNT(*) AS event_count
                FROM security_events
                GROUP BY source_type, identity
                ORDER BY last_ingested_at DESC LIMIT 10
                """
            ).fetchall()
    except sqlite3.Error:
        return []
    observations: list[ComponentObservation] = []
    for row in rows:
        try:
            last_event = datetime.fromisoformat(str(row["last_event_at"])).astimezone(timezone.utc)
            last_ingested = datetime.fromisoformat(str(row["last_ingested_at"])).astimezone(timezone.utc)
        except ValueError:
            continue
        source_active = (now - last_event).total_seconds() <= settings.operational_source_stale_seconds
        pipeline_active = (now - last_ingested).total_seconds() <= settings.operational_source_stale_seconds
        digest = hashlib.sha256(
            f"{row['source_type']}\0{row['identity']}".encode("utf-8")
        ).hexdigest()[:24]
        state = "HEALTHY" if source_active and pipeline_active else "DEGRADED"
        observations.append(
            _component(
                f"telemetry-source-{digest}",
                "telemetry_source",
                state,
                "APPLICATION_DATABASE",
                "Telemetry source and ingestion activity are current."
                if state == "HEALTHY"
                else "Telemetry source or ingestion activity is stale.",
                now,
                metrics={
                    "source_type": row["source_type"],
                    "identity": str(row["identity"])[:255],
                    "source_state": "SOURCE_ACTIVE" if source_active else "SOURCE_STALE",
                    "pipeline_state": "PIPELINE_ACTIVE" if pipeline_active else "PIPELINE_DEGRADED",
                    "agent_connectivity": "METRIC_UNAVAILABLE",
                    "last_event_at": last_event.isoformat(),
                    "last_ingested_at": last_ingested.isoformat(),
                    "event_count": int(row["event_count"]),
                    "stale_after_seconds": settings.operational_source_stale_seconds,
                },
                last_error=None if state == "HEALTHY" else "freshness threshold exceeded",
            )
        )
    return observations


def _bounded_text(path: Path, maximum: int) -> str | None:
    try:
        if path.stat().st_size > maximum:
            return None
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def capture(
    database: Path,
    manager_distro: str,
    *,
    deep_shipper_audit: bool = False,
) -> OperationalSnapshot:
    now = datetime.now(timezone.utc)
    settings = Settings.from_env()
    return OperationalSnapshot(
        collected_at=now,
        components=[
            manager_observation(manager_distro, now),
            api_observation(settings, now),
            sender_observation(manager_distro, now, settings),
            shipper_observation(
                manager_distro,
                now,
                settings,
                deep_backlog_audit=deep_shipper_audit,
            ),
            windows_agent_observation(now),
            database_observation(database, now),
            *source_observations(database, now, settings),
        ],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manager-distro", default="Ubuntu-24.04")
    parser.add_argument("--no-record", action="store_true")
    parser.add_argument(
        "--deep-shipper-audit",
        action="store_true",
        help="perform one streaming archive scan; disabled by default to avoid high-frequency I/O",
    )
    args = parser.parse_args()
    database = args.database.resolve()
    output = args.output.resolve()
    if not database.is_relative_to(REPOSITORY_ROOT) or not output.is_relative_to(REPOSITORY_ROOT):
        raise SystemExit("database and output paths must stay within the repository")
    snapshot = capture(
        database,
        args.manager_distro,
        deep_shipper_audit=args.deep_shipper_audit,
    )
    payload = json.dumps(snapshot.model_dump(mode="json"), indent=2) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, output)
    transitions = 0
    if not args.no_record:
        transitions = OperationalRepository(database).record_snapshot(snapshot)
    states = ", ".join(
        f"{item.component_key}={item.state}" for item in snapshot.components
    )
    print(f"PASS: snapshot={output}; transitions={transitions}; {states}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
