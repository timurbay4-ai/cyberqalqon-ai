"""
Regression tests for wazuh/scripts/send_fixture.py

Tests verify:
  - load_fixture() correctly reads plain UTF-8 files
  - load_fixture() correctly reads UTF-8-BOM files (regression: was broken before fix)
  - load_fixture() rejects non-dict JSON
  - load_fixture() handles missing files gracefully
  - load_fixture() returns the parsed dict
"""

import importlib.util
import json
import sys
import os
import tempfile
import pytest

# Load send_fixture module from its actual location using importlib
# Path: <repo_root>/wazuh/scripts/send_fixture.py
# This test file lives at: <repo_root>/backend/tests/unit/test_send_fixture.py
# So: 3 levels up from __file__ reaches backend/, then one more reaches repo root.
_SEND_FIXTURE_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..",  # backend/tests/unit -> repo root
        "wazuh", "scripts", "send_fixture.py",
    )
)
_spec = importlib.util.spec_from_file_location("send_fixture", _SEND_FIXTURE_PATH)
_send_fixture_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_send_fixture_mod)  # type: ignore[union-attr]
load_fixture = _send_fixture_mod.load_fixture


def write_fixture(path: str, data: dict, encoding: str, bom: bool = False) -> None:
    content = json.dumps(data, ensure_ascii=False)
    encoded = content.encode(encoding)
    if bom:
        encoded = b"\xef\xbb\xbf" + encoded  # UTF-8 BOM
    with open(path, "wb") as fh:
        fh.write(encoded)


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


class TestLoadFixturePlainUTF8:
    """Plain UTF-8 files (no BOM) must load correctly."""

    def test_simple_alert(self, tmp_path):
        alert = {"rule": {"id": "1234", "level": 5}, "agent": {"name": "test-host"}}
        p = tmp_path / "plain.json"
        write_fixture(str(p), alert, encoding="utf-8", bom=False)
        result = load_fixture(str(p))
        assert result["rule"]["id"] == "1234"
        assert result["agent"]["name"] == "test-host"

    def test_unicode_values(self, tmp_path):
        """Non-ASCII field values are preserved after round-trip."""
        alert = {"agent": {"name": "сервер-01"}, "rule": {"level": 3}}
        p = tmp_path / "unicode.json"
        write_fixture(str(p), alert, encoding="utf-8", bom=False)
        result = load_fixture(str(p))
        assert result["agent"]["name"] == "сервер-01"


class TestLoadFixtureUTF8BOM:
    """
    UTF-8-BOM files (U+FEFF prefix) — this was the bug.
    Before the fix, json.load() failed with a JSONDecodeError because the BOM
    character appeared inside the JSON string.
    """

    def test_bom_file_loads_correctly(self, tmp_path):
        """Regression test: UTF-8-BOM fixtures must load without error."""
        alert = {"rule": {"id": "9999", "level": 12}, "agent": {"name": "win-pc"}}
        p = tmp_path / "bom_fixture.json"
        write_fixture(str(p), alert, encoding="utf-8", bom=True)
        result = load_fixture(str(p))
        assert result["rule"]["id"] == "9999"
        assert result["rule"]["level"] == 12
        assert result["agent"]["name"] == "win-pc"

    def test_bom_file_matches_plain_content(self, tmp_path):
        """BOM and plain UTF-8 versions of the same content are identical after parse."""
        alert = {"timestamp": "2026-09-30T12:00:00Z", "rule": {"level": 7}}
        p_plain = tmp_path / "plain.json"
        p_bom = tmp_path / "bom.json"
        write_fixture(str(p_plain), alert, encoding="utf-8", bom=False)
        write_fixture(str(p_bom), alert, encoding="utf-8", bom=True)
        assert load_fixture(str(p_plain)) == load_fixture(str(p_bom))

    def test_committed_samples_are_bom_encoded(self):
        """
        The committed wazuh/samples/*.json files actually have BOM.
        Verifies that our fix handles the exact files in the repository.
        """
        samples_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "..", "..",
            "wazuh", "samples"
        ))
        sample_files = [
            os.path.join(samples_dir, f)
            for f in os.listdir(samples_dir)
            if f.endswith(".json")
        ]
        assert len(sample_files) >= 1, "No sample files found"
        for sample_path in sample_files:
            # Verify the file actually has a BOM (i.e., this test covers the real case)
            with open(sample_path, "rb") as fh:
                first_bytes = fh.read(3)
            assert first_bytes == b"\xef\xbb\xbf", (
                f"{os.path.basename(sample_path)} does not have a UTF-8 BOM — "
                "this test expects BOM-encoded files"
            )
            # Verify load_fixture() successfully parses it
            result = load_fixture(sample_path)
            assert isinstance(result, dict), f"{os.path.basename(sample_path)}: expected dict"
            # All sample fixtures must have a 'rule' key per Wazuh schema
            assert "rule" in result, (
                f"{os.path.basename(sample_path)}: missing 'rule' key"
            )


# ---------------------------------------------------------------------------
# Error-path tests
# ---------------------------------------------------------------------------


class TestLoadFixtureErrors:
    def test_missing_file_exits_with_code_1(self, tmp_path):
        """load_fixture() calls sys.exit(1) when file is not found."""
        with pytest.raises(SystemExit) as exc_info:
            load_fixture(str(tmp_path / "nonexistent.json"))
        assert exc_info.value.code == 1

    def test_non_dict_json_exits_with_code_1(self, tmp_path):
        """load_fixture() rejects JSON arrays — Wazuh events must be objects."""
        p = tmp_path / "array.json"
        p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            load_fixture(str(p))
        assert exc_info.value.code == 1

    def test_string_json_exits_with_code_1(self, tmp_path):
        """load_fixture() rejects a bare string value."""
        p = tmp_path / "string.json"
        p.write_text('"just a string"', encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            load_fixture(str(p))
        assert exc_info.value.code == 1
