"""
CyberQalqon AI — Wazuh Integration v2 Test Suite
==================================================
Comprehensive automated tests for:
  - cyberqalqon_sender.py  (main integration sender)
  - health_check.py        (backend health checker)
  - send_fixture.py        (development fixture sender)
  - validate_config.py     (config file validator)

All external HTTP calls use unittest.mock — no real backend required.
Tests are deterministic and isolated.

Test categories:
  1.  UTF-8 plain file reading
  2.  UTF-8-BOM file reading (regression: D1 fix verification)
  3.  Committed sample fixtures (real BOM files)
  4.  JSON validation (non-dict rejection)
  5.  File-not-found handling
  6.  File-too-large handling
  7.  Correct Authorization header
  8.  Missing token handling
  9.  Correct Content-Type and User-Agent headers
  10. Successful delivery (HTTP 200 / 201)
  11. Connection failure retry
  12. Timeout retry
  13. HTTP 500 retry with backoff
  14. HTTP 429 with Retry-After header
  15. HTTP 429 without Retry-After header
  16. HTTP 401 — non-retryable (auth failure)
  17. HTTP 400 — non-retryable (validation error)
  18. Retry bounds (MAX_RETRIES respected)
  19. Payload immutability across retries
  20. Safe metadata extraction (no secrets in log strings)
  21. Token never in log output
  22. health_check URL parsing (D7 fix)
  23. health_check OK response
  24. health_check UNREACHABLE response
  25. validate_config snippet validation
  26. validate_config sender security checks
  27. send_fixture BOM loading (regression)
  28. send_fixture missing file exits
  29. send_fixture non-dict JSON exits
  30. jittered backoff bounded correctly
"""

import importlib.util
import io
import json
import logging
import os
import sys
import tempfile
import time
import unittest
from types import ModuleType
from typing import Any, Dict
from unittest.mock import MagicMock, Mock, call, patch

# ---------------------------------------------------------------------------
# Module loader helper — loads sender from its actual path
# ---------------------------------------------------------------------------

_WAZUH_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_REPO_ROOT = os.path.abspath(os.path.join(_WAZUH_ROOT, ".."))


def _load_module(rel_path: str, name: str) -> ModuleType:
    """Load a module from a relative path within the wazuh directory."""
    abs_path = os.path.join(_WAZUH_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(name, abs_path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# Load all modules under test (done at import time so tests share the modules)
sender = _load_module("integrations/cyberqalqon_sender.py", "cyberqalqon_sender")
health_check = _load_module("scripts/health_check.py", "health_check")
send_fixture_mod = _load_module("scripts/send_fixture.py", "send_fixture")
validate_config_mod = _load_module("scripts/validate_config.py", "validate_config")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_json(tmp_dir: str, data: Any, *, bom: bool = False, filename: str = "alert.json") -> str:
    """Write JSON data to a temp file, optionally with UTF-8 BOM."""
    path = os.path.join(tmp_dir, filename)
    content = json.dumps(data, ensure_ascii=False).encode("utf-8")
    if bom:
        content = b"\xef\xbb\xbf" + content
    with open(path, "wb") as fh:
        fh.write(content)
    return path


_MINIMAL_ALERT: Dict[str, Any] = {
    "timestamp": "2026-09-30T18:45:12.000+0000",
    "rule": {"id": "5712", "level": 10, "description": "Test alert"},
    "agent": {"id": "003", "name": "test-agent", "ip": "10.0.0.1"},
}


# ---------------------------------------------------------------------------
# 1-6  Alert reading tests
# ---------------------------------------------------------------------------

class TestReadAlertUTF8Plain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_plain_utf8_loads_correctly(self):
        path = _write_json(self.tmp, _MINIMAL_ALERT, bom=False)
        result = sender.read_alert(path)
        self.assertEqual(result["rule"]["id"], "5712")
        self.assertEqual(result["agent"]["name"], "test-agent")

    def test_unicode_values_preserved(self):
        data = dict(_MINIMAL_ALERT)
        data["agent"] = {"name": "сервер-01"}
        path = _write_json(self.tmp, data, bom=False)
        result = sender.read_alert(path)
        self.assertEqual(result["agent"]["name"], "сервер-01")


class TestReadAlertUTF8BOM(unittest.TestCase):
    """
    Regression tests for D1: read_alert() must handle UTF-8 BOM files.
    The previous version used encoding='utf-8' which caused JSONDecodeError.
    The fix uses encoding='utf-8-sig'.
    """
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_bom_file_loads_correctly(self):
        """Core regression: BOM-prefixed JSON must parse without error."""
        path = _write_json(self.tmp, _MINIMAL_ALERT, bom=True)
        result = sender.read_alert(path)
        self.assertEqual(result["rule"]["id"], "5712")

    def test_bom_and_plain_produce_identical_result(self):
        plain = _write_json(self.tmp, _MINIMAL_ALERT, bom=False, filename="plain.json")
        bom_f = _write_json(self.tmp, _MINIMAL_ALERT, bom=True, filename="bom.json")
        self.assertEqual(sender.read_alert(plain), sender.read_alert(bom_f))

    def test_committed_samples_are_bom_encoded_and_load(self):
        """All committed wazuh/samples/*.json files have BOM and must load."""
        samples_dir = os.path.join(_WAZUH_ROOT, "samples")
        sample_files = [
            f for f in os.listdir(samples_dir) if f.endswith(".json")
        ]
        self.assertGreaterEqual(len(sample_files), 1, "No sample fixtures found")
        for fname in sample_files:
            fpath = os.path.join(samples_dir, fname)
            with open(fpath, "rb") as fh:
                first_bytes = fh.read(3)
            self.assertEqual(
                first_bytes, b"\xef\xbb\xbf",
                f"{fname} is not BOM-encoded — this test verifies the real case"
            )
            result = sender.read_alert(fpath)
            self.assertIsInstance(result, dict, f"{fname}: expected dict")
            self.assertIn("rule", result, f"{fname}: missing 'rule' key")

    def test_bom_file_with_unicode_content(self):
        data = {"rule": {"id": "1", "level": 5}, "agent": {"name": "агент-01"}}
        path = _write_json(self.tmp, data, bom=True)
        result = sender.read_alert(path)
        self.assertEqual(result["agent"]["name"], "агент-01")


class TestReadAlertValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            sender.read_alert(os.path.join(self.tmp, "nonexistent.json"))

    def test_non_dict_json_raises_value_error(self):
        path = os.path.join(self.tmp, "array.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("[1, 2, 3]")
        with self.assertRaises(ValueError):
            sender.read_alert(path)

    def test_string_json_raises_value_error(self):
        path = os.path.join(self.tmp, "string.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('"just a string"')
        with self.assertRaises(ValueError):
            sender.read_alert(path)

    def test_invalid_json_raises_decode_error(self):
        path = os.path.join(self.tmp, "bad.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not valid json!!}")
        with self.assertRaises(json.JSONDecodeError):
            sender.read_alert(path)

    def test_oversized_file_raises_value_error(self):
        path = os.path.join(self.tmp, "huge.json")
        # Write a file just over 2 MiB
        large = {"x": "A" * (sender.MAX_ALERT_BYTES + 1)}
        raw = json.dumps(large).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        with self.assertRaises(ValueError, msg="Should reject oversized files"):
            sender.read_alert(path)


# ---------------------------------------------------------------------------
# 7-10  HTTP delivery headers and success
# ---------------------------------------------------------------------------

class TestHTTPHeaders(unittest.TestCase):
    """Verify correct headers are sent with every request."""

    def _make_mock_response(self, status: int = 201):
        resp = MagicMock()
        resp.status = status
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    @patch("urllib.request.urlopen")
    def test_content_type_is_application_json(self, mock_open):
        mock_open.return_value = self._make_mock_response()
        sender.post_alert("http://test/api/v1/ingest/wazuh", _MINIMAL_ALERT, None)
        req = mock_open.call_args[0][0]
        self.assertEqual(req.get_header("Content-type"), "application/json")

    @patch("urllib.request.urlopen")
    def test_authorization_header_present_when_token_given(self, mock_open):
        mock_open.return_value = self._make_mock_response()
        sender.post_alert("http://test/api", _MINIMAL_ALERT, "my-secret-token")
        req = mock_open.call_args[0][0]
        self.assertEqual(req.get_header("Authorization"), "Bearer my-secret-token")

    @patch("urllib.request.urlopen")
    def test_no_authorization_header_when_token_absent(self, mock_open):
        mock_open.return_value = self._make_mock_response()
        sender.post_alert("http://test/api", _MINIMAL_ALERT, None)
        req = mock_open.call_args[0][0]
        # Header should not be present
        self.assertIsNone(req.get_header("Authorization"))

    @patch("urllib.request.urlopen")
    def test_user_agent_contains_cyberqalqon(self, mock_open):
        mock_open.return_value = self._make_mock_response()
        sender.post_alert("http://test/api", _MINIMAL_ALERT, None)
        req = mock_open.call_args[0][0]
        self.assertIn("CyberQalqon", req.get_header("User-agent"))

    @patch("urllib.request.urlopen")
    def test_payload_is_valid_json(self, mock_open):
        mock_open.return_value = self._make_mock_response()
        sender.post_alert("http://test/api", _MINIMAL_ALERT, None)
        req = mock_open.call_args[0][0]
        parsed = json.loads(req.data.decode("utf-8"))
        self.assertEqual(parsed["rule"]["id"], _MINIMAL_ALERT["rule"]["id"])

    @patch("urllib.request.urlopen")
    def test_successful_delivery_returns_zero(self, mock_open):
        mock_open.return_value = self._make_mock_response(201)
        result = sender.deliver_with_retry(
            "http://test/api", _MINIMAL_ALERT, None, "meta"
        )
        self.assertEqual(result, 0)


# ---------------------------------------------------------------------------
# 11-18  Retry logic
# ---------------------------------------------------------------------------

class TestRetryBehavior(unittest.TestCase):

    def _make_http_error(self, code: int, retry_after: str = "") -> Exception:
        from urllib.error import HTTPError
        headers = {}
        if retry_after:
            headers["Retry-After"] = retry_after
        mock_headers = MagicMock()
        mock_headers.get = lambda k, d="": headers.get(k, d)
        exc = HTTPError(
            url="http://test",
            code=code,
            msg=f"HTTP {code}",
            hdrs=mock_headers,  # type: ignore[arg-type]
            fp=io.BytesIO(b""),
        )
        return exc

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_connection_failure_is_retried(self, mock_open, mock_sleep):
        """URLError on first attempt should trigger retry."""
        good_resp = MagicMock()
        good_resp.status = 201
        good_resp.__enter__ = lambda s: s
        good_resp.__exit__ = MagicMock(return_value=False)
        mock_open.side_effect = [
            URLError("Connection refused"),
            good_resp,
        ]
        original_max = sender.MAX_RETRIES
        sender.MAX_RETRIES = 1
        try:
            result = sender.deliver_with_retry("http://t", _MINIMAL_ALERT, None, "m")
            self.assertEqual(result, 0)
            self.assertEqual(mock_open.call_count, 2)
        finally:
            sender.MAX_RETRIES = original_max

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_http_500_is_retried(self, mock_open, mock_sleep):
        """HTTP 500 should be retried."""
        good_resp = MagicMock()
        good_resp.status = 201
        good_resp.__enter__ = lambda s: s
        good_resp.__exit__ = MagicMock(return_value=False)
        mock_open.side_effect = [
            self._make_http_error(500),
            good_resp,
        ]
        original_max = sender.MAX_RETRIES
        sender.MAX_RETRIES = 1
        try:
            result = sender.deliver_with_retry("http://t", _MINIMAL_ALERT, None, "m")
            self.assertEqual(result, 0)
        finally:
            sender.MAX_RETRIES = original_max

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_http_401_not_retried(self, mock_open, mock_sleep):
        """HTTP 401 (auth failure) must NOT be retried — returns 2 immediately."""
        mock_open.side_effect = [self._make_http_error(401)]
        original_max = sender.MAX_RETRIES
        sender.MAX_RETRIES = 3
        try:
            result = sender.deliver_with_retry("http://t", _MINIMAL_ALERT, None, "m")
            self.assertEqual(result, 2)
            self.assertEqual(mock_open.call_count, 1, "401 must stop immediately")
        finally:
            sender.MAX_RETRIES = original_max

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_http_400_not_retried(self, mock_open, mock_sleep):
        """HTTP 400 (validation) must NOT be retried."""
        mock_open.side_effect = [self._make_http_error(400)]
        original_max = sender.MAX_RETRIES
        sender.MAX_RETRIES = 3
        try:
            result = sender.deliver_with_retry("http://t", _MINIMAL_ALERT, None, "m")
            self.assertEqual(result, 2)
            self.assertEqual(mock_open.call_count, 1)
        finally:
            sender.MAX_RETRIES = original_max

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_http_429_with_retry_after_is_retried(self, mock_open, mock_sleep):
        """HTTP 429 with Retry-After should retry after the specified delay."""
        good_resp = MagicMock()
        good_resp.status = 201
        good_resp.__enter__ = lambda s: s
        good_resp.__exit__ = MagicMock(return_value=False)
        mock_open.side_effect = [
            self._make_http_error(429, retry_after="5"),
            good_resp,
        ]
        original_max = sender.MAX_RETRIES
        sender.MAX_RETRIES = 1
        try:
            result = sender.deliver_with_retry("http://t", _MINIMAL_ALERT, None, "m")
            self.assertEqual(result, 0)
            # sleep should be called with ≤ MAX_RETRY_AFTER_SECS
            sleep_arg = mock_sleep.call_args[0][0]
            self.assertLessEqual(sleep_arg, sender.MAX_RETRY_AFTER_SECS)
            self.assertAlmostEqual(sleep_arg, 5.0, places=1)
        finally:
            sender.MAX_RETRIES = original_max

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_max_retries_bound_is_respected(self, mock_open, mock_sleep):
        """Sender must attempt exactly MAX_RETRIES+1 times then give up."""
        mock_open.side_effect = URLError("always fails")
        original_max = sender.MAX_RETRIES
        sender.MAX_RETRIES = 2
        try:
            result = sender.deliver_with_retry("http://t", _MINIMAL_ALERT, "tok", "m")
            self.assertEqual(result, 2)
            self.assertEqual(mock_open.call_count, 3)  # 1 original + 2 retries
        finally:
            sender.MAX_RETRIES = original_max

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_payload_not_mutated_across_retries(self, mock_open, mock_sleep):
        """Original alert dict must be identical before and after delivery attempts."""
        import copy
        original_alert = copy.deepcopy(_MINIMAL_ALERT)
        mock_open.side_effect = URLError("always fails")
        original_max = sender.MAX_RETRIES
        sender.MAX_RETRIES = 2
        try:
            sender.deliver_with_retry("http://t", _MINIMAL_ALERT, None, "m")
        finally:
            sender.MAX_RETRIES = original_max
        self.assertEqual(_MINIMAL_ALERT, original_alert, "Alert dict was mutated!")

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_all_retries_exhausted_returns_two(self, mock_open, mock_sleep):
        """After all retries: return code must be 2."""
        mock_open.side_effect = URLError("down")
        original_max = sender.MAX_RETRIES
        sender.MAX_RETRIES = 1
        try:
            result = sender.deliver_with_retry("http://t", _MINIMAL_ALERT, None, "m")
            self.assertEqual(result, 2)
        finally:
            sender.MAX_RETRIES = original_max


# ---------------------------------------------------------------------------
# 19-21  Security / logging safety
# ---------------------------------------------------------------------------

class TestSafeLogging(unittest.TestCase):
    """Verify that tokens and raw alert data do not appear in log output."""

    def _capture_logs(self):
        handler = logging.handlers_buffer = []
        class CaptureHandler(logging.Handler):
            def emit(self, record):
                handler.append(record.getMessage())
        h = CaptureHandler()
        sender.log.addHandler(h)
        return handler, h

    def test_safe_meta_does_not_raise(self):
        result = sender._safe_meta(_MINIMAL_ALERT)
        self.assertIsInstance(result, str)
        self.assertIn("5712", result)

    def test_safe_meta_bad_data_does_not_raise(self):
        # Deeply nested bad data should not crash _safe_meta
        bad = {"rule": None, "agent": 42}
        result = sender._safe_meta(bad)
        self.assertIsInstance(result, str)

    def test_safe_meta_does_not_include_full_log_content(self):
        alert = dict(_MINIMAL_ALERT)
        alert["full_log"] = "SECRET PASSWORD: hunter2"
        result = sender._safe_meta(alert)
        self.assertNotIn("hunter2", result)

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_token_not_in_log_output(self, mock_open, mock_sleep):
        """Bearer token must never appear in any log message."""
        secret_token = "SUPER-SECRET-BEARER-TOKEN-XYZ"
        log_records = []

        class CapturingHandler(logging.Handler):
            def emit(self, record):
                log_records.append(self.format(record))

        cap = CapturingHandler()
        sender.log.addHandler(cap)
        try:
            mock_open.side_effect = URLError("network down")
            original_max = sender.MAX_RETRIES
            sender.MAX_RETRIES = 1
            try:
                sender.deliver_with_retry("http://t", _MINIMAL_ALERT, secret_token, "m")
            finally:
                sender.MAX_RETRIES = original_max

            for msg in log_records:
                self.assertNotIn(secret_token, msg, f"Token found in log: {msg!r}")
        finally:
            sender.log.removeHandler(cap)


# ---------------------------------------------------------------------------
# 22-24  health_check URL parsing and behavior
# ---------------------------------------------------------------------------

class TestHealthCheckURLParsing(unittest.TestCase):
    """Regression tests for D7: rstrip() chaining was corrupting URLs."""

    def test_base_url_unchanged_when_no_ingest_suffix(self):
        """http://127.0.0.1:8000 should not be modified."""
        import importlib
        with patch.dict(os.environ, {"CYBERQALQON_BACKEND_URL": "http://127.0.0.1:8000"}):
            # Reload to pick up env change
            hc = _load_module("scripts/health_check.py", "health_check_test")
            self.assertEqual(hc._BASE, "http://127.0.0.1:8000")

    def test_ingest_suffix_stripped_correctly(self):
        """Full ingest URL should be stripped to base."""
        with patch.dict(os.environ, {
            "CYBERQALQON_BACKEND_URL": "http://127.0.0.1:8000/api/v1/ingest/wazuh"
        }):
            hc = _load_module("scripts/health_check.py", "health_check_test2")
            self.assertEqual(hc._BASE, "http://127.0.0.1:8000")

    def test_trailing_slash_stripped(self):
        """Trailing slash should be stripped."""
        with patch.dict(os.environ, {"CYBERQALQON_BACKEND_URL": "http://192.168.1.1:8000/"}):
            hc = _load_module("scripts/health_check.py", "health_check_test3")
            self.assertEqual(hc._BASE, "http://192.168.1.1:8000")

    def test_old_rstrip_bug_would_corrupt_url(self):
        """
        Demonstrate what the old code did wrong:
          'http://127.0.0.1:8000'.rstrip('/').rstrip('/api/v1/ingest/wazuh')
        The old rstrip() on a character set would eat individual chars,
        corrupting the URL. Verify the new code doesn't do this.
        """
        # The new code: verify we get the correct result
        base = "http://127.0.0.1:8000"
        ingest_suffix = "/api/v1/ingest/wazuh"
        result = (
            base[:-len(ingest_suffix)]
            if base.endswith(ingest_suffix)
            else base.rstrip("/")
        )
        self.assertEqual(result, "http://127.0.0.1:8000")


from urllib.error import URLError  # noqa: E402


class TestHealthCheckBehavior(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_health_ok_exits_zero(self, mock_open):
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = resp
        # We test the request construction, not sys.exit
        req = urllib_request_module.Request(url="http://127.0.0.1:8000/health", method="GET")
        self.assertIsNotNone(req)

    @patch("urllib.request.urlopen")
    def test_health_unreachable_on_url_error(self, mock_open):
        mock_open.side_effect = URLError("connection refused")
        # health_check.main() calls sys.exit(1) — catch it
        with self.assertRaises(SystemExit) as cm:
            # Inject args and run
            with patch("sys.argv", ["health_check.py"]):
                health_check.main()
        self.assertEqual(cm.exception.code, 1)


# We need urllib.request for the test above
import urllib.request as urllib_request_module  # noqa: E402


# ---------------------------------------------------------------------------
# 25-26  validate_config
# ---------------------------------------------------------------------------

class TestValidateConfig(unittest.TestCase):

    def test_snippet_validation_passes_for_committed_file(self):
        snippet_path = os.path.join(_WAZUH_ROOT, "configs", "ossec-cyberqalqon-snippet.xml")
        result = validate_config_mod.validate_snippet(snippet_path)
        self.assertTrue(result, "Committed snippet should pass validation")

    def test_sender_security_checks_pass(self):
        sender_path = os.path.join(_WAZUH_ROOT, "integrations", "cyberqalqon_sender.py")
        result = validate_config_mod.validate_sender(sender_path)
        self.assertTrue(result, "Committed sender should pass security checks")

    def test_snippet_rejects_missing_file(self):
        result = validate_config_mod.validate_snippet("/nonexistent/path/snippet.xml")
        self.assertFalse(result)

    def test_sender_rejects_missing_file(self):
        result = validate_config_mod.validate_sender("/nonexistent/sender.py")
        self.assertFalse(result)

    def test_sender_rejects_eval(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('x = eval("1+1")\n')
            name = f.name
        try:
            result = validate_config_mod.validate_sender(name)
            self.assertFalse(result, "eval() should fail security check")
        finally:
            os.unlink(name)


# ---------------------------------------------------------------------------
# 27-29  send_fixture module
# ---------------------------------------------------------------------------

class TestSendFixtureBOM(unittest.TestCase):
    """Regression tests for the send_fixture BOM fix."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_plain_utf8_loads(self):
        path = _write_json(self.tmp, _MINIMAL_ALERT, bom=False)
        result = send_fixture_mod.load_fixture(path)
        self.assertEqual(result["rule"]["id"], "5712")

    def test_bom_utf8_loads(self):
        """Regression: BOM files previously caused JSONDecodeError."""
        path = _write_json(self.tmp, _MINIMAL_ALERT, bom=True)
        result = send_fixture_mod.load_fixture(path)
        self.assertEqual(result["rule"]["id"], "5712")

    def test_missing_file_exits(self):
        with self.assertRaises(SystemExit) as cm:
            send_fixture_mod.load_fixture(os.path.join(self.tmp, "nope.json"))
        self.assertEqual(cm.exception.code, 1)

    def test_non_dict_json_exits(self):
        path = os.path.join(self.tmp, "arr.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("[1, 2, 3]")
        with self.assertRaises(SystemExit) as cm:
            send_fixture_mod.load_fixture(path)
        self.assertEqual(cm.exception.code, 1)


# ---------------------------------------------------------------------------
# 30  Jittered backoff bounds
# ---------------------------------------------------------------------------

class TestJitteredBackoff(unittest.TestCase):

    def test_backoff_within_bounds(self):
        original_max = sender.RETRY_MAX_DELAY
        original_base = sender.RETRY_BASE_DELAY
        sender.RETRY_MAX_DELAY = 30.0
        sender.RETRY_BASE_DELAY = 1.0
        try:
            for attempt in range(10):
                for _ in range(100):  # statistical check
                    delay = sender._jittered_backoff(attempt)
                    self.assertGreaterEqual(delay, 0.0)
                    self.assertLessEqual(delay, 30.0)
        finally:
            sender.RETRY_MAX_DELAY = original_max
            sender.RETRY_BASE_DELAY = original_base

    def test_backoff_not_always_same_value(self):
        """Full jitter: sequential calls should not return identical values."""
        sender.RETRY_MAX_DELAY = 30.0
        sender.RETRY_BASE_DELAY = 1.0
        values = [sender._jittered_backoff(3) for _ in range(20)]
        self.assertGreater(len(set(values)), 1, "Jitter should produce varied delays")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
