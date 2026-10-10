from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from app.schemas.ai import AIAnalysisResult
from app.services.wazuh_normalizer import normalize_wazuh_alert


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPOSITORY_ROOT / "shared" / "schemas" / "normalized_alert.schema.json"


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_shared_example_matches_normalized_alert_contract() -> None:
    example_path = REPOSITORY_ROOT / "shared" / "examples" / "alert-example.json"
    example = json.loads(example_path.read_text(encoding="utf-8"))

    _validator().validate(example)


def test_normalizer_output_matches_shared_contract(sample_alert: dict) -> None:
    normalized = normalize_wazuh_alert(sample_alert).model_dump(mode="json", exclude_none=True)

    _validator().validate(normalized)


def test_shared_contract_accepts_level_16_without_mitre_mapping(sample_alert: dict) -> None:
    sample_alert["rule"]["level"] = 16
    del sample_alert["rule"]["mitre"]
    normalized = normalize_wazuh_alert(sample_alert).model_dump(mode="json", exclude_none=True)

    _validator().validate(normalized)


def test_shared_contract_accepts_typed_windows_event_context() -> None:
    fixture = json.loads(
        (REPOSITORY_ROOT / "wazuh" / "samples" / "windows-security-failure.json").read_text(
            encoding="utf-8"
        )
    )
    normalized = normalize_wazuh_alert(fixture).model_dump(mode="json", exclude_none=True)
    _validator().validate(normalized)
    assert normalized["windows"]["event_id"] == "4625"


def test_shared_ai_schema_matches_backend_structured_result_contract() -> None:
    schema_path = REPOSITORY_ROOT / "shared" / "schemas" / "ai_analysis.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    result = AIAnalysisResult(
        summary="Review the alert.",
        assessment="Evidence is incomplete.",
        key_evidence=[],
        mitre_context=[],
        timeline_summary=None,
        hypotheses=[],
        investigation_steps=["Review adjacent events."],
        possible_false_positive_reasons=[],
        recommended_actions=[],
        containment_considerations=[],
        uncertainties=["Source evidence is limited."],
    )
    Draft202012Validator(schema).validate(result.model_dump(mode="json"))
