"""Durable M14 detection readiness state isolated from production alert routing."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from uuid import uuid4

from app.schemas.auth import AnalystPrincipal
from app.schemas.detection_readiness import (
    CanarySafetyStatus,
    CorrelationReplayRequest,
    CorrelationReplayResult,
    CountByEntity,
    DetectionConfigurationCreate,
    DetectionConfigurationDiff,
    DetectionConfigurationDifference,
    DetectionConfigurationDefinition,
    DetectionConfigurationValidation,
    DetectionConfigurationVersion,
    DetectionDeploymentEligibility,
    DetectionDiagnostics,
    DetectionLifecycleState,
    DetectionLifecycleTransition,
    DetectionRuleLifecycle,
    DetectionTuningComparison,
    DetectionTuningRequest,
    DetectionValidationState,
    ShadowFinding,
    ShadowRun,
    ShadowRunDetail,
    ShadowRunRequest,
    TelemetryPrerequisiteEvidence,
    TelemetryReadinessStatus,
    TuningCandidateResult,
)
from app.services.advanced_detection import (
    RULES,
    RULE_BY_ID,
    AdvancedDetectionEngine,
    AdvancedDetectionEvaluationLimitError,
    DetectionEvent,
    RuleSpec,
)
from app.services.wazuh_normalizer import canonical_json


class DetectionReadinessNotFoundError(LookupError):
    pass


class DetectionReadinessConflictError(RuntimeError):
    pass


class DetectionReadinessLifecycleError(RuntimeError):
    pass


class DetectionReadinessSchemaUnavailableError(DetectionReadinessLifecycleError):
    pass


class DetectionReadinessEvaluationError(RuntimeError):
    pass


class _SimulatedInterruption(RuntimeError):
    pass


_FIXED_THRESHOLDS = {
    "DET-003": 2,
    "DET-004": 1,
    "DET-005": 1,
    "DET-006": 1,
    "DET-007": 3,
    "DET-008": 1,
    "DET-009": 1,
}
_FIXED_WINDOWS = {
    "DET-003": 120,
    "DET-004": 300,
    "DET-005": 300,
    "DET-006": 600,
    "DET-007": 600,
    "DET-008": 300,
    "DET-009": 3600,
}
_REQUIRED_EVENT_CODE_SETS = {
    "DET-001": ({"4625"},),
    "DET-002": ({"4625"}, {"4624"}),
    "DET-003": ({"4624"}, {"4672"}),
    "DET-006": ({"7045"},),
}
_RAW_EVENTDATA_ALLOWLIST = {
    "targetUserName", "memberName", "targetGroupName", "groupName", "targetSid",
    "groupSid", "logonType", "targetLogonId", "subjectLogonId", "imagePath",
    "serviceName", "startType", "accountName", "serviceAccount", "threatName",
    "threatID", "path", "status", "subStatus",
}
_TRANSITIONS: dict[DetectionLifecycleState, set[DetectionLifecycleState]] = {
    DetectionLifecycleState.DRAFT: {
        DetectionLifecycleState.VALIDATED,
        DetectionLifecycleState.ROLLED_BACK,
    },
    DetectionLifecycleState.VALIDATED: {
        DetectionLifecycleState.TESTED,
        DetectionLifecycleState.DRAFT,
        DetectionLifecycleState.ROLLED_BACK,
    },
    DetectionLifecycleState.TESTED: {
        DetectionLifecycleState.SHADOW_READY,
        DetectionLifecycleState.DRAFT,
        DetectionLifecycleState.ROLLED_BACK,
    },
    DetectionLifecycleState.SHADOW_READY: {
        DetectionLifecycleState.CANARY_READY,
        DetectionLifecycleState.PAUSED,
        DetectionLifecycleState.ROLLED_BACK,
    },
    DetectionLifecycleState.CANARY_READY: {
        DetectionLifecycleState.PAUSED,
        DetectionLifecycleState.ROLLED_BACK,
    },
    DetectionLifecycleState.PAUSED: {
        DetectionLifecycleState.SHADOW_READY,
        DetectionLifecycleState.ROLLED_BACK,
    },
    DetectionLifecycleState.ROLLED_BACK: {DetectionLifecycleState.DRAFT},
    DetectionLifecycleState.DISABLED_BY_POLICY: {DetectionLifecycleState.DRAFT},
    DetectionLifecycleState.ACTIVE: {DetectionLifecycleState.PAUSED},
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).astimezone(timezone.utc).isoformat()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().upper()


def _telemetry_status(status: str) -> TelemetryReadinessStatus:
    return {
        "RECENTLY_OBSERVED": TelemetryReadinessStatus.READY,
        "OBSERVED_STALE": TelemetryReadinessStatus.PARTIAL,
        "PREREQUISITE_MISSING": TelemetryReadinessStatus.PARTIAL,
        "NO_DATA": TelemetryReadinessStatus.UNAVAILABLE,
        "UNKNOWN": TelemetryReadinessStatus.UNKNOWN,
    }.get(status, TelemetryReadinessStatus.FAILED)


class DetectionReadinessRepository:
    """Persistence and bounded evaluation facade; it has no production output adapter."""

    def __init__(self, database_path: Path, engine: AdvancedDetectionEngine) -> None:
        self.path = database_path
        self.engine = engine

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        action: str,
        actor: AnalystPrincipal,
        rule_id: str,
        details: Mapping[str, object] | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO security_audit_events (
                audit_id, action, actor_id, actor_display, target_type,
                target_id, outcome, occurred_at, details_json
            ) VALUES (?, ?, ?, ?, 'advanced_detection_rule', ?, 'SUCCESS', ?, ?)
            """,
            (
                f"AUD-{uuid4().hex.upper()}", action, actor.analyst_id,
                actor.audit_display, rule_id, _iso(), canonical_json(dict(details or {})),
            ),
        )

    @staticmethod
    def _default_configuration(spec: RuleSpec) -> DetectionConfigurationDefinition:
        return DetectionConfigurationDefinition(
            threshold_count=spec.threshold,
            time_window_seconds=spec.window_seconds,
            severity=spec.severity,
            supported_event_sources=list(spec.source_types),
            required_normalized_fields=list(spec.required_fields),
            entity_grouping=list(spec.grouping_fields),
            safe_exclusions=[],
            evaluation_limits={
                "max_events": 1000,
                "max_findings": 100,
                "max_execution_ms": 1000,
            },
            state_expiration_seconds=min(604800, max(3600, spec.window_seconds * 4)),
            state_schema_version=1,
        )

    def ensure_defaults(self) -> None:
        """Seed immutable M11-compatible defaults after an approved schema migration."""

        with closing(self._connect()) as connection, connection:
            try:
                existing_count = int(connection.execute(
                    "SELECT COUNT(*) FROM advanced_detection_rule_state"
                ).fetchone()[0])
            except sqlite3.OperationalError as exc:
                if "no such table" in str(exc).casefold():
                    raise DetectionReadinessSchemaUnavailableError(
                        "M14 schema 18 is not applied; explicit migration approval is required"
                    ) from exc
                raise
            if existing_count >= len(RULES):
                return
            connection.execute("BEGIN IMMEDIATE")
            now = _iso()
            for spec in RULES:
                exists = connection.execute(
                    "SELECT 1 FROM advanced_detection_rule_state WHERE rule_id = ?",
                    (spec.rule_id,),
                ).fetchone()
                if exists:
                    continue
                config = self._default_configuration(spec)
                config_id = f"ADCFG-{uuid4().hex.upper()}"
                validation = [
                    "M11 deterministic fixtures validated this packaged configuration.",
                    "Live activation remains disabled by policy.",
                ]
                connection.execute(
                    """
                    INSERT INTO advanced_detection_config_versions (
                        config_id, rule_id, version, lifecycle_state, configuration_json,
                        validation_json, author_id, author_display, change_reason, created_at
                    ) VALUES (?, ?, 1, 'TESTED', ?, ?, NULL, 'SYSTEM', ?, ?)
                    """,
                    (
                        config_id, spec.rule_id, canonical_json(config.model_dump(mode="json")),
                        canonical_json(validation), "Imported M11 tested baseline", now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO advanced_detection_rule_state (
                        rule_id, configuration_state, validation_state,
                        deployment_eligibility, runtime_activation_state, telemetry_status,
                        active_configuration_version, state_version, updated_at, updated_by
                    ) VALUES (?, 'TESTED', 'VALID', 'SHADOW_ONLY',
                              'DISABLED_BY_POLICY', 'UNKNOWN', 1, 1, ?, 'SYSTEM')
                    """,
                    (spec.rule_id, now),
                )
                connection.execute(
                    """
                    INSERT INTO advanced_detection_lifecycle_history (
                        history_id, rule_id, from_state, to_state, configuration_version,
                        actor_id, actor_display, reason, occurred_at
                    ) VALUES (?, ?, NULL, 'TESTED', 1, NULL, 'SYSTEM', ?, ?)
                    """,
                    (
                        f"ADH-{uuid4().hex.upper()}", spec.rule_id,
                        "Imported M11 tested baseline; activation stays disabled", now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO advanced_detection_diagnostics (rule_id, updated_at)
                    VALUES (?, ?)
                    """,
                    (spec.rule_id, now),
                )
            connection.commit()

    @staticmethod
    def _configuration(row: sqlite3.Row) -> DetectionConfigurationVersion:
        definition = json.loads(row["configuration_json"])
        return DetectionConfigurationVersion(
            **definition,
            config_id=row["config_id"],
            rule_id=row["rule_id"],
            version=int(row["version"]),
            lifecycle_state=row["lifecycle_state"],
            author_id=row["author_id"],
            author_display=row["author_display"],
            change_reason=row["change_reason"],
            created_at=row["created_at"],
            validation_results=json.loads(row["validation_json"]),
        )

    def configuration(
        self, rule_id: str, version: int | None = None,
        *, connection: sqlite3.Connection | None = None,
    ) -> DetectionConfigurationVersion:
        self._require_rule(rule_id)
        self.ensure_defaults()
        owned = connection is None
        handle = connection or self._connect()
        try:
            if version is None:
                row = handle.execute(
                    """
                    SELECT c.* FROM advanced_detection_config_versions c
                    JOIN advanced_detection_rule_state s
                      ON s.rule_id = c.rule_id
                     AND s.active_configuration_version = c.version
                    WHERE c.rule_id = ?
                    """,
                    (rule_id,),
                ).fetchone()
            else:
                row = handle.execute(
                    "SELECT * FROM advanced_detection_config_versions WHERE rule_id = ? AND version = ?",
                    (rule_id, version),
                ).fetchone()
            if row is None:
                raise DetectionReadinessNotFoundError("Detection configuration does not exist")
            return self._configuration(row)
        finally:
            if owned:
                handle.close()

    def configurations(self, rule_id: str) -> list[DetectionConfigurationVersion]:
        self._require_rule(rule_id)
        self.ensure_defaults()
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT * FROM advanced_detection_config_versions
                WHERE rule_id = ? ORDER BY version DESC LIMIT 100
                """,
                (rule_id,),
            ).fetchall()
        return [self._configuration(row) for row in rows]

    def configuration_diff(
        self, rule_id: str, from_version: int, to_version: int,
    ) -> DetectionConfigurationDiff:
        before = self.configuration(rule_id, from_version)
        after = self.configuration(rule_id, to_version)
        excluded = {
            "config_id", "rule_id", "version", "lifecycle_state", "author_id",
            "author_display", "change_reason", "created_at", "validation_results",
        }
        left = before.model_dump(mode="json", exclude=excluded)
        right = after.model_dump(mode="json", exclude=excluded)
        differences = [
            DetectionConfigurationDifference(
                field=field, before=left.get(field), after=right.get(field)
            )
            for field in sorted(set(left) | set(right))
            if left.get(field) != right.get(field)
        ]
        return DetectionConfigurationDiff(
            rule_id=rule_id, from_version=from_version,
            to_version=to_version, differences=differences,
        )

    @staticmethod
    def _lifecycle_from_row(
        row: sqlite3.Row, *, telemetry: TelemetryReadinessStatus | None = None,
    ) -> DetectionRuleLifecycle:
        status = telemetry or TelemetryReadinessStatus(row["telemetry_status"])
        blockers = ["Live activation is disabled by policy and requires a future approval milestone."]
        if status is not TelemetryReadinessStatus.READY:
            blockers.append(f"Telemetry prerequisite status is {status.value}.")
        return DetectionRuleLifecycle(
            rule_id=row["rule_id"],
            configuration_state=row["configuration_state"],
            validation_state=row["validation_state"],
            deployment_eligibility=row["deployment_eligibility"],
            runtime_activation_state="DISABLED_BY_POLICY",
            telemetry_status=status,
            active_configuration_version=int(row["active_configuration_version"]),
            state_version=int(row["state_version"]),
            updated_at=row["updated_at"],
            updated_by=row["updated_by"],
            inactive_reason=" ".join(blockers),
        )

    def lifecycle(self, rule_id: str) -> DetectionRuleLifecycle:
        self._require_rule(rule_id)
        self.ensure_defaults()
        evidence = self.telemetry_readiness(rule_id)
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM advanced_detection_rule_state WHERE rule_id = ?", (rule_id,)
            ).fetchone()
        assert row is not None
        return self._lifecycle_from_row(row, telemetry=evidence.status)

    def lifecycle_inventory(self) -> list[DetectionRuleLifecycle]:
        return [self.lifecycle(spec.rule_id) for spec in RULES]

    @staticmethod
    def _require_rule(rule_id: str) -> RuleSpec:
        spec = RULE_BY_ID.get(rule_id.upper())
        if spec is None:
            raise DetectionReadinessNotFoundError("Advanced detection rule does not exist")
        return spec

    def create_configuration(
        self,
        rule_id: str,
        payload: DetectionConfigurationCreate,
        actor: AnalystPrincipal,
    ) -> DetectionConfigurationVersion:
        self._require_rule(rule_id)
        self.ensure_defaults()
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            state = connection.execute(
                "SELECT * FROM advanced_detection_rule_state WHERE rule_id = ?", (rule_id,)
            ).fetchone()
            assert state is not None
            current = int(state["active_configuration_version"])
            if current != payload.expected_version:
                raise DetectionReadinessConflictError(
                    f"Configuration version changed; expected {payload.expected_version}, current {current}"
                )
            version = current + 1
            definition = DetectionConfigurationDefinition.model_validate(
                payload.model_dump(exclude={"expected_version", "change_reason"})
            )
            config_id = f"ADCFG-{uuid4().hex.upper()}"
            now = _iso()
            connection.execute(
                """
                INSERT INTO advanced_detection_config_versions (
                    config_id, rule_id, version, lifecycle_state, configuration_json,
                    validation_json, author_id, author_display, change_reason, created_at
                ) VALUES (?, ?, ?, 'DRAFT', ?, '[]', ?, ?, ?, ?)
                """,
                (
                    config_id, rule_id, version,
                    canonical_json(definition.model_dump(mode="json")), actor.analyst_id,
                    actor.audit_display, payload.change_reason, now,
                ),
            )
            connection.execute(
                """
                UPDATE advanced_detection_rule_state
                SET configuration_state = 'DRAFT', validation_state = 'NOT_VALIDATED',
                    deployment_eligibility = 'BLOCKED', active_configuration_version = ?,
                    state_version = state_version + 1, updated_at = ?, updated_by = ?
                WHERE rule_id = ?
                """,
                (version, now, actor.audit_display, rule_id),
            )
            self._history(
                connection, rule_id=rule_id, from_state=state["configuration_state"],
                to_state="DRAFT", version=version, actor=actor, reason=payload.change_reason,
            )
            self._audit(
                connection, action="ADVANCED_DETECTION_CONFIGURATION_CREATED", actor=actor,
                rule_id=rule_id, details={"configuration_version": version},
            )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM advanced_detection_config_versions WHERE config_id = ?",
                (config_id,),
            ).fetchone()
        assert row is not None
        return self._configuration(row)

    @staticmethod
    def _history(
        connection: sqlite3.Connection,
        *,
        rule_id: str,
        from_state: str | None,
        to_state: str,
        version: int,
        actor: AnalystPrincipal,
        reason: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO advanced_detection_lifecycle_history (
                history_id, rule_id, from_state, to_state, configuration_version,
                actor_id, actor_display, reason, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"ADH-{uuid4().hex.upper()}", rule_id, from_state, to_state, version,
                actor.analyst_id, actor.audit_display, reason, _iso(),
            ),
        )

    def _validation(
        self, spec: RuleSpec, config: DetectionConfigurationVersion,
    ) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        if set(config.supported_event_sources) != set(spec.source_types):
            errors.append("Supported event sources must exactly match the packaged M11 semantics.")
        missing_fields = sorted(set(spec.required_fields) - set(config.required_normalized_fields))
        if missing_fields:
            errors.append("Required normalized fields removed: " + ", ".join(missing_fields))
        if set(config.entity_grouping) != set(spec.grouping_fields):
            errors.append("Entity grouping cannot diverge from the deterministic M11 correlation key.")
        fixed = _FIXED_THRESHOLDS.get(spec.rule_id)
        if fixed is not None and config.threshold_count != fixed:
            errors.append(f"{spec.rule_id} has a fixed semantic threshold of {fixed}.")
        fixed_window = _FIXED_WINDOWS.get(spec.rule_id)
        if fixed_window is not None and config.time_window_seconds != fixed_window:
            errors.append(f"{spec.rule_id} has a fixed semantic window of {fixed_window} seconds.")
        if config.time_window_seconds > spec.window_seconds * 4:
            warnings.append("The candidate time window is more than four times the packaged default.")
        if config.threshold_count < spec.threshold:
            warnings.append("A lower threshold may increase finding volume and false positives.")
        if config.safe_exclusions:
            warnings.append("Exclusions require historical comparison before readiness review.")
        return errors, warnings

    def validate_configuration(
        self, rule_id: str, version: int, actor: AnalystPrincipal,
    ) -> DetectionConfigurationValidation:
        spec = self._require_rule(rule_id)
        config = self.configuration(rule_id, version)
        errors, warnings = self._validation(spec, config)
        validated_at = _now()
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            state = connection.execute(
                "SELECT * FROM advanced_detection_rule_state WHERE rule_id = ?", (rule_id,)
            ).fetchone()
            assert state is not None
            if int(state["active_configuration_version"]) != version:
                raise DetectionReadinessConflictError("Only the active configuration version can be validated")
            target = "VALIDATED" if not errors else "DRAFT"
            validation_state = "VALID" if not errors else "INVALID"
            eligibility = "SHADOW_ONLY" if not errors else "BLOCKED"
            results = [*(f"ERROR: {item}" for item in errors), *(f"WARNING: {item}" for item in warnings)]
            connection.execute(
                """
                UPDATE advanced_detection_config_versions
                SET lifecycle_state = ?, validation_json = ?
                WHERE rule_id = ? AND version = ?
                """,
                (target, canonical_json(results), rule_id, version),
            )
            connection.execute(
                """
                UPDATE advanced_detection_rule_state
                SET configuration_state = ?, validation_state = ?, deployment_eligibility = ?,
                    state_version = state_version + 1, updated_at = ?, updated_by = ?
                WHERE rule_id = ?
                """,
                (target, validation_state, eligibility, _iso(validated_at), actor.audit_display, rule_id),
            )
            self._history(
                connection, rule_id=rule_id, from_state=state["configuration_state"],
                to_state=target, version=version, actor=actor,
                reason="Configuration validation passed" if not errors else "Configuration validation failed",
            )
            if errors:
                connection.execute(
                    """
                    UPDATE advanced_detection_diagnostics
                    SET configuration_validation_failure_count = configuration_validation_failure_count + 1,
                        updated_at = ? WHERE rule_id = ?
                    """,
                    (_iso(validated_at), rule_id),
                )
            self._audit(
                connection, action="ADVANCED_DETECTION_CONFIGURATION_VALIDATED", actor=actor,
                rule_id=rule_id,
                details={"configuration_version": version, "valid": not errors},
            )
            connection.commit()
        lifecycle = self.lifecycle(rule_id)
        return DetectionConfigurationValidation(
            rule_id=rule_id, configuration_version=version, valid=not errors,
            errors=errors, warnings=warnings, validated_at=validated_at, lifecycle=lifecycle,
        )

    def restore_configuration(
        self,
        rule_id: str,
        source_version: int,
        expected_version: int,
        reason: str,
        actor: AnalystPrincipal,
    ) -> DetectionConfigurationVersion:
        source = self.configuration(rule_id, source_version)
        payload = DetectionConfigurationCreate(
            **source.model_dump(
                exclude={
                    "config_id", "rule_id", "version", "lifecycle_state", "author_id",
                    "author_display", "change_reason", "created_at", "validation_results",
                }
            ),
            expected_version=expected_version,
            change_reason=reason,
        )
        result = self.create_configuration(rule_id, payload, actor)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._audit(
                connection, action="ADVANCED_DETECTION_CONFIGURATION_RESTORED", actor=actor,
                rule_id=rule_id,
                details={"source_version": source_version, "new_version": result.version},
            )
            connection.commit()
        return result

    def transition(
        self,
        rule_id: str,
        payload: DetectionLifecycleTransition,
        actor: AnalystPrincipal,
    ) -> DetectionRuleLifecycle:
        self._require_rule(rule_id)
        self.ensure_defaults()
        if payload.target_state is DetectionLifecycleState.ACTIVE:
            raise DetectionReadinessLifecycleError(
                "ACTIVE is hard-blocked in M14; a separate approved activation milestone is required"
            )
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM advanced_detection_rule_state WHERE rule_id = ?", (rule_id,)
            ).fetchone()
            assert row is not None
            current_version = int(row["state_version"])
            if current_version != payload.expected_state_version:
                raise DetectionReadinessConflictError(
                    f"Lifecycle changed; expected {payload.expected_state_version}, current {current_version}"
                )
            current = DetectionLifecycleState(row["configuration_state"])
            if payload.target_state not in _TRANSITIONS[current]:
                raise DetectionReadinessLifecycleError(
                    f"Transition {current.value} -> {payload.target_state.value} is not allowed"
                )
            completed_shadow = connection.execute(
                """
                SELECT 1 FROM advanced_detection_shadow_runs
                WHERE rule_id = ? AND configuration_version = ? AND status = 'COMPLETED'
                LIMIT 1
                """,
                (rule_id, int(row["active_configuration_version"])),
            ).fetchone()
            if payload.target_state in {
                DetectionLifecycleState.TESTED,
                DetectionLifecycleState.SHADOW_READY,
                DetectionLifecycleState.CANARY_READY,
            } and completed_shadow is None:
                raise DetectionReadinessLifecycleError(
                    "A completed shadow evaluation for this configuration is required"
                )
            telemetry = self.telemetry_readiness(rule_id).status
            if payload.target_state is DetectionLifecycleState.CANARY_READY and telemetry is not TelemetryReadinessStatus.READY:
                raise DetectionReadinessLifecycleError("CANARY_READY requires READY telemetry evidence")
            eligibility = (
                DetectionDeploymentEligibility.CANARY_REVIEW_REQUIRED.value
                if payload.target_state is DetectionLifecycleState.CANARY_READY
                else DetectionDeploymentEligibility.SHADOW_ONLY.value
            )
            if payload.target_state in {DetectionLifecycleState.DRAFT, DetectionLifecycleState.ROLLED_BACK}:
                eligibility = DetectionDeploymentEligibility.BLOCKED.value
            now = _iso()
            connection.execute(
                """
                UPDATE advanced_detection_rule_state
                SET configuration_state = ?, deployment_eligibility = ?, telemetry_status = ?,
                    state_version = state_version + 1, updated_at = ?, updated_by = ?
                WHERE rule_id = ?
                """,
                (payload.target_state.value, eligibility, telemetry.value, now, actor.audit_display, rule_id),
            )
            connection.execute(
                """
                UPDATE advanced_detection_config_versions SET lifecycle_state = ?
                WHERE rule_id = ? AND version = ?
                """,
                (payload.target_state.value, rule_id, int(row["active_configuration_version"])),
            )
            self._history(
                connection, rule_id=rule_id, from_state=current.value,
                to_state=payload.target_state.value,
                version=int(row["active_configuration_version"]), actor=actor,
                reason=payload.reason,
            )
            self._audit(
                connection, action="ADVANCED_DETECTION_LIFECYCLE_TRANSITION", actor=actor,
                rule_id=rule_id,
                details={"from": current.value, "to": payload.target_state.value},
            )
            connection.commit()
        return self.lifecycle(rule_id)

    @staticmethod
    def _profile(config: DetectionConfigurationVersion, **overrides: int) -> dict[str, object]:
        return {
            "threshold_count": overrides.get("threshold_count", config.threshold_count),
            "time_window_seconds": overrides.get(
                "time_window_seconds", config.time_window_seconds
            ),
            "severity": config.severity,
        }

    @staticmethod
    def _event_value(event: DetectionEvent, field: str) -> str | None:
        direct = {
            "hostname": event.hostname,
            "username": event.username,
            "source_ip": event.source_ip,
            "process_name": event.process_name,
            "event_code": event.event_code,
            "event_category": event.category,
            "outcome": event.outcome,
            "command_or_script": event.command_line or event.message,
        }
        if field in direct:
            return direct[field]
        data = event.raw.get("data") if isinstance(event.raw.get("data"), Mapping) else {}
        win = data.get("win") if isinstance(data.get("win"), Mapping) else {}
        event_data = win.get("eventdata") if isinstance(win.get("eventdata"), Mapping) else {}
        aliases = {
            "logon_type": "logonType",
            "logon_id": "targetLogonId",
            "account_or_group_context": "targetUserName",
            "service_metadata": "serviceName",
            "defender_threat_context": "threatName",
        }
        key = aliases.get(field)
        value = event_data.get(key) if key else None
        return str(value) if value not in {None, ""} else None

    def _apply_exclusions(
        self, events: Sequence[DetectionEvent], config: DetectionConfigurationVersion,
    ) -> tuple[list[DetectionEvent], int]:
        kept: list[DetectionEvent] = []
        skipped = 0
        for event in events:
            excluded = False
            for exclusion in config.safe_exclusions:
                value = self._event_value(event, exclusion.field)
                if value is None:
                    continue
                left, right = value.casefold(), exclusion.value.casefold()
                if (
                    exclusion.operator == "EQUALS" and left == right
                ) or (
                    exclusion.operator == "STARTS_WITH" and left.startswith(right)
                ):
                    excluded = True
                    break
            if excluded:
                skipped += 1
            else:
                kept.append(event)
        return kept, skipped

    def _missing_fields(
        self, events: Sequence[DetectionEvent], config: DetectionConfigurationVersion,
    ) -> int:
        return sum(
            1
            for event in events
            for field in config.required_normalized_fields
            if not self._event_value(event, field)
        )

    def tuning_comparison(
        self, rule_id: str, payload: DetectionTuningRequest,
    ) -> DetectionTuningComparison:
        spec = self._require_rule(rule_id)
        config = self.configuration(rule_id)
        start, end = payload.resolved()
        if end > _now() + timedelta(minutes=5):
            raise DetectionReadinessEvaluationError("Future evaluation windows are not accepted")
        deadline = time.perf_counter() + payload.max_execution_ms / 1000
        events = self.engine.load_events(start, end, payload.max_events, deadline=deadline)
        events, skipped = self._apply_exclusions(events, config)
        results: list[TuningCandidateResult] = []
        for candidate in payload.candidates:
            fixed_threshold = _FIXED_THRESHOLDS.get(rule_id)
            fixed_window = _FIXED_WINDOWS.get(rule_id)
            if fixed_threshold is not None and candidate.threshold_count != fixed_threshold:
                raise DetectionReadinessEvaluationError(
                    f"{rule_id} uses a fixed threshold of {fixed_threshold}; tuning would diverge from M11 semantics"
                )
            if fixed_window is not None and candidate.time_window_seconds != fixed_window:
                raise DetectionReadinessEvaluationError(
                    f"{rule_id} uses a fixed window of {fixed_window} seconds; tuning would diverge from M11 semantics"
                )
            started = time.perf_counter()
            if time.perf_counter() >= deadline:
                raise DetectionReadinessEvaluationError("Tuning comparison exceeded its budget")
            _, _, findings_with_extra, duplicate_count = self.engine.evaluate_events(
                rule_id,
                events,
                evaluation_end=end,
                max_findings=min(500, payload.max_findings + 1),
                profile=self._profile(
                    config,
                    threshold_count=candidate.threshold_count,
                    time_window_seconds=candidate.time_window_seconds,
                ),
            )
            truncated = len(findings_with_extra) > payload.max_findings
            findings = findings_with_extra[:payload.max_findings]
            source_by_event = {event.event_id: event.source_type for event in events}
            sources: Counter[str] = Counter()
            hosts: Counter[str] = Counter()
            users: Counter[str] = Counter()
            groups: Counter[str] = Counter()
            for finding in findings:
                for event_id in finding.event_ids:
                    if event_id in source_by_event:
                        sources[source_by_event[event_id]] += 1
                        break
                host = finding.group.get("hostname")
                user = finding.group.get("username")
                if host:
                    hosts[host] += 1
                if user:
                    users[user] += 1
                groups[canonical_json(finding.group)] += 1
            to_counts = lambda values: [
                CountByEntity(entity=name, count=count)
                for name, count in values.most_common(20)
            ]
            results.append(TuningCandidateResult(
                candidate=candidate,
                evaluated_event_count=len(events),
                finding_count=len(findings_with_extra),
                duplicate_count=duplicate_count,
                missing_field_count=self._missing_fields(events, config),
                findings_by_source=to_counts(sources),
                findings_by_host=to_counts(hosts),
                findings_by_user=to_counts(users),
                repeated_finding_count=sum(max(0, count - 1) for count in groups.values()),
                execution_ms=max(0.0, (time.perf_counter() - started) * 1000),
                truncated=truncated,
            ))
        return DetectionTuningComparison(
            rule_id=rule_id, start_time=start, end_time=end, results=results,
            interpretation=(
                "Finding-count differences measure sensitivity only; they do not label unmatched "
                "or unlabeled events as benign, true positive, or false positive."
            ),
        )

    def telemetry_readiness(self, rule_id: str) -> TelemetryPrerequisiteEvidence:
        spec = self._require_rule(rule_id)
        try:
            end = _now()
            events = self.engine.load_rule_events(
                rule_id, end - timedelta(days=30), end, 1000,
                deadline=time.perf_counter() + 2.0,
            )
            _, availability, _, _ = self.engine.evaluate_events(
                rule_id, events, evaluation_end=end, max_findings=1
            )
            status = _telemetry_status(availability.status)
            freshness = (
                max(0, int((_now() - availability.latest_event_at).total_seconds()))
                if availability.latest_event_at is not None else None
            )
            missing = list(availability.missing_required_fields)
            if not availability.data_observed:
                missing.append("eligible_source_events")
            observed_codes = {event.event_code for event in events if event.event_code}
            for required_set in _REQUIRED_EVENT_CODE_SETS.get(rule_id, ()):
                if not (observed_codes & required_set):
                    missing.append("event_code:" + "|".join(sorted(required_set)))
            if missing and status is TelemetryReadinessStatus.READY:
                status = TelemetryReadinessStatus.PARTIAL
            return TelemetryPrerequisiteEvidence(
                rule_id=rule_id,
                required_sources=list(spec.source_types),
                required_event_codes=list(spec.event_codes),
                required_categories=list(spec.event_categories),
                required_fields=list(spec.required_fields),
                latest_observed_event=availability.latest_event_at,
                source_freshness_seconds=freshness,
                normalization_compatible=not missing,
                status=status,
                missing_prerequisites=sorted(set(missing)),
                authoritative_evidence_reference=(
                    "security_events bounded by source/event prerequisites; collector status not inferred"
                ),
                explanation=availability.explanation,
            )
        except (AdvancedDetectionEvaluationLimitError, sqlite3.Error) as exc:
            return TelemetryPrerequisiteEvidence(
                rule_id=rule_id, required_sources=list(spec.source_types),
                required_event_codes=list(spec.event_codes),
                required_categories=list(spec.event_categories),
                required_fields=list(spec.required_fields), latest_observed_event=None,
                source_freshness_seconds=None, normalization_compatible=False,
                status=TelemetryReadinessStatus.FAILED,
                missing_prerequisites=["bounded_evidence_query_failed"],
                authoritative_evidence_reference="security_events query failed",
                explanation=f"Telemetry readiness could not be derived: {type(exc).__name__}",
            )

    def telemetry_inventory(self) -> list[TelemetryPrerequisiteEvidence]:
        return [self.telemetry_readiness(spec.rule_id) for spec in RULES]

    def run_shadow(
        self, rule_id: str, payload: ShadowRunRequest, actor: AnalystPrincipal,
    ) -> ShadowRunDetail:
        self._require_rule(rule_id)
        config = self.configuration(rule_id, payload.configuration_version)
        if config.lifecycle_state is DetectionLifecycleState.DRAFT:
            raise DetectionReadinessLifecycleError("Shadow evaluation requires a validated configuration")
        start, end = payload.resolved()
        if end > _now() + timedelta(minutes=5):
            raise DetectionReadinessEvaluationError("Future evaluation windows are not accepted")
        run_id = f"SHADOW-{uuid4().hex.upper()}"
        started_at = _now()
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO advanced_detection_shadow_runs (
                    run_id, rule_id, configuration_version, status, started_at,
                    start_time, end_time, operator_id, operator_display,
                    source_availability, outcome
                ) VALUES (?, ?, ?, 'RUNNING', ?, ?, ?, ?, ?, 'UNKNOWN', 'RUNNING')
                """,
                (
                    run_id, rule_id, config.version, _iso(started_at), start.isoformat(),
                    end.isoformat(), actor.analyst_id, actor.audit_display,
                ),
            )
            connection.commit()
        wall_started = time.perf_counter()
        cpu_started = time.process_time()
        try:
            deadline = wall_started + payload.max_execution_ms / 1000
            events = self.engine.load_events(start, end, payload.max_events, deadline=deadline)
            filtered, skipped = self._apply_exclusions(events, config)
            _, availability, findings_with_extra, duplicate_count = self.engine.evaluate_events(
                rule_id, filtered, evaluation_end=end,
                max_findings=min(500, payload.max_findings + 1),
                profile=self._profile(config),
            )
            if time.perf_counter() >= deadline:
                raise AdvancedDetectionEvaluationLimitError("Shadow execution exceeded its budget")
            truncated = len(findings_with_extra) > payload.max_findings
            findings = findings_with_extra[:payload.max_findings]
            duration = max(0.0, (time.perf_counter() - wall_started) * 1000)
            resources = {
                "cpu_ms": max(0.0, (time.process_time() - cpu_started) * 1000),
                "wall_ms": duration,
                "input_events": len(events),
                "excluded_events": skipped,
            }
            status = _telemetry_status(availability.status)
            missing = self._missing_fields(filtered, config)
            completed_at = _now()
            stored_findings: list[ShadowFinding] = []
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                for finding in findings:
                    shadow_id = f"SHF-{uuid4().hex.upper()}"
                    connection.execute(
                        """
                        INSERT INTO advanced_detection_shadow_findings (
                            shadow_finding_id, run_id, rule_id, deduplication_key,
                            first_event_at, last_event_at, finding_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            shadow_id, run_id, rule_id, finding.deduplication_key,
                            finding.first_event_at.isoformat(), finding.last_event_at.isoformat(),
                            canonical_json(finding.model_dump(mode="json")), _iso(completed_at),
                        ),
                    )
                    stored_findings.append(ShadowFinding(
                        shadow_finding_id=shadow_id, run_id=run_id, rule_id=rule_id,
                        finding=finding, created_at=completed_at,
                    ))
                connection.execute(
                    """
                    UPDATE advanced_detection_shadow_runs
                    SET status = 'COMPLETED', completed_at = ?, source_availability = ?,
                        evaluated_event_count = ?, match_count = ?, duplicate_count = ?,
                        missing_field_count = ?, execution_ms = ?, resource_json = ?,
                        truncated = ?, outcome = 'COMPLETED_NO_PRODUCTION_SIDE_EFFECTS'
                    WHERE run_id = ?
                    """,
                    (
                        _iso(completed_at), status.value, len(events), len(findings_with_extra),
                        duplicate_count, missing, duration, canonical_json(resources),
                        int(truncated), run_id,
                    ),
                )
                self._update_diagnostics(
                    connection, rule_id=rule_id, duration=duration,
                    findings=len(findings_with_extra), duplicates=duplicate_count,
                    skipped=skipped, missing=missing, truncated=truncated,
                    start=start, end=end, source_freshness=status.value,
                )
                self._audit(
                    connection, action="ADVANCED_DETECTION_SHADOW_RUN", actor=actor,
                    rule_id=rule_id,
                    details={
                        "run_id": run_id, "configuration_version": config.version,
                        "findings": len(findings_with_extra), "truncated": truncated,
                        "production_side_effects": False,
                    },
                )
                connection.commit()
            run = ShadowRun(
                run_id=run_id, rule_id=rule_id, configuration_version=config.version,
                status="COMPLETED", started_at=started_at, completed_at=completed_at,
                start_time=start, end_time=end, operator_display=actor.audit_display,
                source_availability=status, evaluated_event_count=len(events),
                match_count=len(findings_with_extra), duplicate_count=duplicate_count,
                missing_field_count=missing, execution_ms=duration, truncated=truncated,
                outcome="COMPLETED_NO_PRODUCTION_SIDE_EFFECTS",
                resource_measurements=resources,
            )
            return ShadowRunDetail(run=run, findings=stored_findings)
        except Exception as exc:
            failed_at = _now()
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    UPDATE advanced_detection_shadow_runs
                    SET status = 'FAILED', completed_at = ?, outcome = 'FAILED_CLOSED',
                        error_code = ?, execution_ms = ? WHERE run_id = ?
                    """,
                    (
                        _iso(failed_at), type(exc).__name__,
                        max(0.0, (time.perf_counter() - wall_started) * 1000), run_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE advanced_detection_diagnostics
                    SET evaluation_count = evaluation_count + 1,
                        evaluation_timeout_count = evaluation_timeout_count + ?,
                        last_failed_evaluation = ?, updated_at = ? WHERE rule_id = ?
                    """,
                    (
                        int(isinstance(exc, AdvancedDetectionEvaluationLimitError)),
                        _iso(failed_at), _iso(failed_at), rule_id,
                    ),
                )
                connection.commit()
            raise DetectionReadinessEvaluationError(
                "Shadow evaluation failed closed without production side effects"
            ) from exc

    @staticmethod
    def _update_diagnostics(
        connection: sqlite3.Connection,
        *,
        rule_id: str,
        duration: float,
        findings: int,
        duplicates: int,
        skipped: int,
        missing: int,
        truncated: bool,
        start: datetime,
        end: datetime,
        source_freshness: str,
        recovered: bool = False,
    ) -> None:
        now = _iso()
        connection.execute(
            """
            UPDATE advanced_detection_diagnostics
            SET evaluation_count = evaluation_count + 1,
                total_duration_ms = total_duration_ms + ?,
                rule_match_count = rule_match_count + ?,
                finding_count = finding_count + ?,
                duplicate_event_count = duplicate_event_count + ?,
                skipped_event_count = skipped_event_count + ?,
                missing_field_count = missing_field_count + ?,
                state_recovery_count = state_recovery_count + ?,
                truncation_count = truncation_count + ?,
                last_successful_evaluation = ?, last_event_range_start = ?,
                last_event_range_end = ?, source_freshness = ?, updated_at = ?
            WHERE rule_id = ?
            """,
            (
                duration, findings, findings, duplicates, skipped, missing, int(recovered),
                int(truncated), now, start.isoformat(), end.isoformat(), source_freshness,
                now, rule_id,
            ),
        )

    @staticmethod
    def _serialize_event(event: DetectionEvent) -> dict[str, object]:
        data = event.raw.get("data") if isinstance(event.raw.get("data"), Mapping) else {}
        win = data.get("win") if isinstance(data.get("win"), Mapping) else {}
        event_data = win.get("eventdata") if isinstance(win.get("eventdata"), Mapping) else {}
        subset = {
            key: event_data[key]
            for key in _RAW_EVENTDATA_ALLOWLIST
            if key in event_data and isinstance(event_data[key], (str, int, float, bool))
        }
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "source_type": event.source_type,
            "hostname": event.hostname,
            "username": event.username,
            "source_ip": event.source_ip,
            "event_code": event.event_code,
            "category": event.category,
            "action": event.action,
            "outcome": event.outcome,
            "process_name": event.process_name,
            "process_path": event.process_path,
            "command_line": event.command_line,
            "parent_process_name": event.parent_process_name,
            "message": event.message[:2048],
            "raw_eventdata": subset,
        }

    @staticmethod
    def _deserialize_event(value: Mapping[str, object]) -> DetectionEvent:
        timestamp = datetime.fromisoformat(str(value["timestamp"]))
        return DetectionEvent(
            event_id=str(value["event_id"]), timestamp=timestamp,
            source_type=str(value["source_type"]),
            hostname=value.get("hostname") if isinstance(value.get("hostname"), str) else None,
            username=value.get("username") if isinstance(value.get("username"), str) else None,
            source_ip=value.get("source_ip") if isinstance(value.get("source_ip"), str) else None,
            event_code=value.get("event_code") if isinstance(value.get("event_code"), str) else None,
            category=value.get("category") if isinstance(value.get("category"), str) else None,
            action=value.get("action") if isinstance(value.get("action"), str) else None,
            outcome=value.get("outcome") if isinstance(value.get("outcome"), str) else None,
            process_name=value.get("process_name") if isinstance(value.get("process_name"), str) else None,
            process_path=value.get("process_path") if isinstance(value.get("process_path"), str) else None,
            command_line=value.get("command_line") if isinstance(value.get("command_line"), str) else None,
            parent_process_name=(
                value.get("parent_process_name")
                if isinstance(value.get("parent_process_name"), str) else None
            ),
            message=str(value.get("message", "")),
            raw={"data": {"win": {"eventdata": value.get("raw_eventdata", {})}}},
        )

    def _correlation_key(
        self, rule_id: str, config: DetectionConfigurationVersion, event: DetectionEvent,
    ) -> str:
        material = {
            "rule_id": rule_id,
            "hostname": event.hostname or "unknown-host",
            "username": event.username or "unknown-account",
            "source_ip": event.source_ip or "unknown-source",
            "group": {
                field: self._event_value(event, field) or "unknown"
                for field in config.entity_grouping
            },
        }
        return _hash(canonical_json(material))

    def replay_correlation_state(
        self, rule_id: str, payload: CorrelationReplayRequest,
    ) -> CorrelationReplayResult:
        self._require_rule(rule_id)
        config = self.configuration(rule_id, payload.configuration_version)
        start, end = payload.resolved()
        if end > _now() + timedelta(minutes=5):
            raise DetectionReadinessEvaluationError("Future evaluation windows are not accepted")
        deadline = time.perf_counter() + payload.max_execution_ms / 1000
        loaded = self.engine.load_events(start, end, payload.max_events, deadline=deadline)
        events, skipped = self._apply_exclusions(loaded, config)
        initial_state_count = 0
        initial_processed_count = 0
        expired_count = 0
        duplicate_count = 0
        newly_processed = 0
        recovered = False
        try:
            with closing(self._connect()) as connection, connection:
                initial_state_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM advanced_detection_correlation_state
                    WHERE rule_id = ? AND configuration_version = ?
                    """,
                    (rule_id, config.version),
                ).fetchone()[0]
                initial_processed_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM advanced_detection_processed_events
                    WHERE rule_id = ? AND configuration_version = ?
                    """,
                    (rule_id, config.version),
                ).fetchone()[0]
                connection.execute("BEGIN IMMEDIATE")
                incompatible = connection.execute(
                    """
                    SELECT 1 FROM advanced_detection_correlation_state
                    WHERE rule_id = ? AND configuration_version = ? AND state_version <> ?
                    LIMIT 1
                    """,
                    (rule_id, config.version, config.state_schema_version),
                ).fetchone()
                if incompatible:
                    raise DetectionReadinessLifecycleError(
                        "Correlation-state version mismatch; evaluation failed closed"
                    )
                recovered = initial_state_count > 0
                now = _now()
                expired_count += connection.execute(
                    "DELETE FROM advanced_detection_correlation_state WHERE expires_at < ?",
                    (_iso(now),),
                ).rowcount
                connection.execute(
                    "DELETE FROM advanced_detection_processed_events WHERE expires_at < ?",
                    (_iso(now),),
                )
                state_rows = connection.execute(
                    """
                    SELECT * FROM advanced_detection_correlation_state
                    WHERE rule_id = ? AND configuration_version = ?
                    """,
                    (rule_id, config.version),
                ).fetchall()
                state_by_key: dict[str, list[dict[str, object]]] = {
                    row["correlation_key_hash"]: list(json.loads(row["normalized_state_json"]))
                    for row in state_rows
                }
                for index, event in enumerate(
                    sorted(events, key=lambda item: (item.timestamp, item.event_id))
                ):
                    if index % 100 == 0 and time.perf_counter() >= deadline:
                        raise DetectionReadinessEvaluationError(
                            "Correlation replay exceeded its execution budget"
                        )
                    event_hash = _hash(f"{rule_id}:{config.version}:{event.event_id}")
                    exists = connection.execute(
                        """
                        SELECT 1 FROM advanced_detection_processed_events
                        WHERE rule_id = ? AND configuration_version = ? AND event_id_hash = ?
                        """,
                        (rule_id, config.version, event_hash),
                    ).fetchone()
                    if exists:
                        duplicate_count += 1
                        continue
                    expiry = max(now, event.timestamp) + timedelta(
                        seconds=config.state_expiration_seconds
                    )
                    connection.execute(
                        """
                        INSERT INTO advanced_detection_processed_events (
                            rule_id, configuration_version, event_id_hash, event_time, expires_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (rule_id, config.version, event_hash, event.timestamp.isoformat(), _iso(expiry)),
                    )
                    key = self._correlation_key(rule_id, config, event)
                    state_by_key.setdefault(key, []).append(self._serialize_event(event))
                    newly_processed += 1
                for index, (key, snapshots) in enumerate(state_by_key.items()):
                    if index % 25 == 0 and time.perf_counter() >= deadline:
                        raise DetectionReadinessEvaluationError(
                            "Correlation replay exceeded its execution budget"
                        )
                    snapshots.sort(key=lambda item: (str(item["timestamp"]), str(item["event_id"])))
                    watermark = max(datetime.fromisoformat(str(item["timestamp"])) for item in snapshots)
                    cutoff = watermark - timedelta(seconds=config.state_expiration_seconds)
                    retained = [
                        item for item in snapshots
                        if datetime.fromisoformat(str(item["timestamp"])) >= cutoff
                    ][-200:]
                    connection.execute(
                        """
                        INSERT INTO advanced_detection_correlation_state (
                            rule_id, configuration_version, correlation_key_hash, state_version,
                            watermark_at, expires_at, normalized_state_json, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(rule_id, configuration_version, correlation_key_hash)
                        DO UPDATE SET state_version = excluded.state_version,
                            watermark_at = excluded.watermark_at, expires_at = excluded.expires_at,
                            normalized_state_json = excluded.normalized_state_json,
                            updated_at = excluded.updated_at
                        """,
                        (
                            rule_id, config.version, key, config.state_schema_version,
                            watermark.isoformat(),
                            (watermark + timedelta(seconds=config.state_expiration_seconds)).isoformat(),
                            canonical_json(retained), _iso(),
                        ),
                    )
                if payload.simulate_interruption:
                    raise _SimulatedInterruption("intentional transaction interruption")
                connection.commit()
        except _SimulatedInterruption:
            with closing(self._connect()) as verification, verification:
                state_count = verification.execute(
                    """
                    SELECT COUNT(*) FROM advanced_detection_correlation_state
                    WHERE rule_id = ? AND configuration_version = ?
                    """,
                    (rule_id, config.version),
                ).fetchone()[0]
                processed_count = verification.execute(
                    """
                    SELECT COUNT(*) FROM advanced_detection_processed_events
                    WHERE rule_id = ? AND configuration_version = ?
                    """,
                    (rule_id, config.version),
                ).fetchone()[0]
            if state_count != initial_state_count or processed_count != initial_processed_count:
                raise DetectionReadinessEvaluationError("Interrupted state transaction did not roll back")
            return CorrelationReplayResult(
                rule_id=rule_id, configuration_version=config.version,
                evaluated_event_count=len(loaded), newly_processed_event_count=0,
                duplicate_event_count=0, state_record_count=state_count,
                expired_state_count=0, finding_count=0, watermark_at=None,
                recovered_after_restart=recovered, interrupted_transaction_rolled_back=True,
            )

        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT normalized_state_json, watermark_at
                FROM advanced_detection_correlation_state
                WHERE rule_id = ? AND configuration_version = ?
                """,
                (rule_id, config.version),
            ).fetchall()
            persisted_events = [
                self._deserialize_event(item)
                for row in rows
                for item in json.loads(row["normalized_state_json"])
            ]
            state_count = len(rows)
            watermark = max(
                (datetime.fromisoformat(row["watermark_at"]) for row in rows), default=None
            )
            _, readiness, findings, evaluator_duplicates = self.engine.evaluate_events(
                rule_id, persisted_events, evaluation_end=end,
                max_findings=payload.max_findings, profile=self._profile(config),
            )
            duration = max(0.0, (time.perf_counter() - (deadline - payload.max_execution_ms / 1000)) * 1000)
            connection.execute("BEGIN IMMEDIATE")
            self._update_diagnostics(
                connection, rule_id=rule_id, duration=duration, findings=len(findings),
                duplicates=duplicate_count + evaluator_duplicates, skipped=skipped,
                missing=self._missing_fields(events, config), truncated=False,
                start=start, end=end, source_freshness=_telemetry_status(readiness.status).value,
                recovered=recovered,
            )
            connection.commit()
        return CorrelationReplayResult(
            rule_id=rule_id, configuration_version=config.version,
            evaluated_event_count=len(loaded), newly_processed_event_count=newly_processed,
            duplicate_event_count=duplicate_count + evaluator_duplicates,
            state_record_count=state_count, expired_state_count=expired_count,
            finding_count=len(findings), watermark_at=watermark,
            recovered_after_restart=recovered, interrupted_transaction_rolled_back=False,
        )

    def diagnostics(self, rule_id: str) -> DetectionDiagnostics:
        self._require_rule(rule_id)
        self.ensure_defaults()
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM advanced_detection_diagnostics WHERE rule_id = ?", (rule_id,)
            ).fetchone()
        assert row is not None
        count = int(row["evaluation_count"])
        return DetectionDiagnostics(
            rule_id=rule_id, evaluation_count=count,
            average_duration_ms=(float(row["total_duration_ms"]) / count if count else 0.0),
            rule_match_count=int(row["rule_match_count"]),
            finding_count=int(row["finding_count"]),
            duplicate_event_count=int(row["duplicate_event_count"]),
            skipped_event_count=int(row["skipped_event_count"]),
            missing_field_count=int(row["missing_field_count"]),
            evaluation_timeout_count=int(row["evaluation_timeout_count"]),
            state_recovery_count=int(row["state_recovery_count"]),
            configuration_validation_failure_count=int(
                row["configuration_validation_failure_count"]
            ),
            truncation_count=int(row["truncation_count"]),
            last_successful_evaluation=row["last_successful_evaluation"],
            last_failed_evaluation=row["last_failed_evaluation"],
            evaluated_event_range_start=row["last_event_range_start"],
            evaluated_event_range_end=row["last_event_range_end"],
            source_freshness=row["source_freshness"],
        )

    def shadow_runs(self, rule_id: str, *, limit: int = 50) -> list[ShadowRun]:
        self._require_rule(rule_id)
        self.ensure_defaults()
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT * FROM advanced_detection_shadow_runs
                WHERE rule_id = ? ORDER BY started_at DESC, run_id DESC LIMIT ?
                """,
                (rule_id, limit),
            ).fetchall()
        return [self._shadow_run(row) for row in rows]

    @staticmethod
    def _shadow_run(row: sqlite3.Row) -> ShadowRun:
        return ShadowRun(
            run_id=row["run_id"], rule_id=row["rule_id"],
            configuration_version=int(row["configuration_version"]), status=row["status"],
            started_at=row["started_at"], completed_at=row["completed_at"],
            start_time=row["start_time"], end_time=row["end_time"],
            operator_display=row["operator_display"],
            source_availability=row["source_availability"],
            evaluated_event_count=int(row["evaluated_event_count"]),
            match_count=int(row["match_count"]), duplicate_count=int(row["duplicate_count"]),
            missing_field_count=int(row["missing_field_count"]),
            execution_ms=float(row["execution_ms"]), truncated=bool(row["truncated"]),
            outcome=row["outcome"], error_code=row["error_code"],
            resource_measurements=json.loads(row["resource_json"]),
        )

    def shadow_run(self, run_id: str) -> ShadowRunDetail:
        self.ensure_defaults()
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM advanced_detection_shadow_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise DetectionReadinessNotFoundError("Shadow run does not exist")
            finding_rows = connection.execute(
                """
                SELECT * FROM advanced_detection_shadow_findings
                WHERE run_id = ? ORDER BY first_event_at, shadow_finding_id LIMIT 200
                """,
                (run_id,),
            ).fetchall()
        findings = [
            ShadowFinding(
                shadow_finding_id=item["shadow_finding_id"], run_id=run_id,
                rule_id=item["rule_id"], finding=json.loads(item["finding_json"]),
                created_at=item["created_at"],
            )
            for item in finding_rows
        ]
        return ShadowRunDetail(run=self._shadow_run(row), findings=findings)

    def shadow_finding(self, shadow_finding_id: str) -> tuple[ShadowFinding, ShadowRun]:
        self.ensure_defaults()
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                """
                SELECT f.*, r.* FROM advanced_detection_shadow_findings f
                JOIN advanced_detection_shadow_runs r ON r.run_id = f.run_id
                WHERE f.shadow_finding_id = ?
                """,
                (shadow_finding_id,),
            ).fetchone()
        if row is None:
            raise DetectionReadinessNotFoundError("Shadow finding does not exist")
        finding = ShadowFinding(
            shadow_finding_id=row["shadow_finding_id"], run_id=row["run_id"],
            rule_id=row["rule_id"], finding=json.loads(row["finding_json"]),
            created_at=row["created_at"],
        )
        return finding, self._shadow_run(row)

    def canary_safety(self, rule_id: str) -> CanarySafetyStatus:
        lifecycle = self.lifecycle(rule_id)
        config = self.configuration(rule_id)
        diagnostics = self.diagnostics(rule_id)
        with closing(self._connect()) as connection, connection:
            shadow = connection.execute(
                """
                SELECT 1 FROM advanced_detection_shadow_runs
                WHERE rule_id = ? AND configuration_version = ? AND status = 'COMPLETED'
                LIMIT 1
                """,
                (rule_id, config.version),
            ).fetchone() is not None
        blockers = [
            "Canary target scope has not been selected.",
            "Operator activation approval has not been recorded.",
            "M14 activation path is hard-disabled.",
        ]
        if lifecycle.telemetry_status is not TelemetryReadinessStatus.READY:
            blockers.append(f"Telemetry is {lifecycle.telemetry_status.value}.")
        if not shadow:
            blockers.append("No completed shadow run exists for the active configuration.")
        return CanarySafetyStatus(
            rule_id=rule_id,
            prerequisites_validated=lifecycle.telemetry_status is TelemetryReadinessStatus.READY,
            historical_evaluation_passed=shadow,
            configuration_reviewed=lifecycle.validation_state is DetectionValidationState.VALID,
            resource_budget_reviewed=diagnostics.evaluation_count > 0,
            false_positive_baseline_measured=shadow,
            version_locked=lifecycle.configuration_state in {
                DetectionLifecycleState.SHADOW_READY,
                DetectionLifecycleState.CANARY_READY,
            },
            blockers=blockers,
        )
