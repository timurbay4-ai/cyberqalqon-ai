#!/usr/bin/env python3
"""
CyberQalqon AI -- Wazuh Integration Config Validator
=====================================================
Validates that the ossec-cyberqalqon-snippet.xml is well-formed XML
and contains the expected CyberQalqon integration fields.

This script does NOT modify any Wazuh configuration.

Usage:
  python validate_config.py
  python validate_config.py --snippet ../../wazuh/configs/ossec-cyberqalqon-snippet.xml
  python validate_config.py --sender  ../../wazuh/integrations/cyberqalqon_sender.py
"""

import argparse
import ast
import os
import sys
import xml.etree.ElementTree as ET

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_DEFAULT_SNIPPET = os.path.join(_REPO_ROOT, "wazuh", "configs", "ossec-cyberqalqon-snippet.xml")
_DEFAULT_SENDER  = os.path.join(_REPO_ROOT, "wazuh", "integrations", "cyberqalqon_sender.py")

PASS = "[PASS]"
FAIL = "[FAIL]"
WARN = "[WARN]"
INFO = "[INFO]"


def validate_snippet(path: str) -> bool:
    ok = True
    print(f"\n{INFO} Validating snippet: {path}")
    if not os.path.isfile(path):
        print(f"{FAIL} File not found: {path}")
        return False

    try:
        # Wrap in a root element to allow comment-only files
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
        # Strip XML comments for parsing check
        import re
        stripped = re.sub(r"<!--.*?-->", "", raw, flags=re.DOTALL).strip()
        if not stripped:
            print(f"{WARN} Snippet contains no XML elements (only comments).")
            return True
        wrapped = f"<root>{stripped}</root>"
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        print(f"{FAIL} XML parse error: {exc}")
        return False

    integrations = root.findall("integration")
    if not integrations:
        print(f"{FAIL} No <integration> element found.")
        return False

    for integ in integrations:
        name = integ.findtext("name", "")
        if not name.startswith("custom-"):
            print(f"{FAIL} <name> must start with 'custom-', got: {name!r}")
            ok = False
        else:
            print(f"{PASS} <name> = {name!r}")

        hook_url = integ.findtext("hook_url", "")
        if not hook_url:
            print(f"{FAIL} <hook_url> is empty or missing.")
            ok = False
        elif "your-" in hook_url or "example" in hook_url:
            print(f"{WARN} <hook_url> looks like a placeholder: {hook_url!r}")
        else:
            print(f"{PASS} <hook_url> = {hook_url!r}")

        alert_fmt = integ.findtext("alert_format", "")
        if alert_fmt != "json":
            print(f"{FAIL} <alert_format> must be 'json', got {alert_fmt!r}")
            ok = False
        else:
            print(f"{PASS} <alert_format> = 'json'")

        level = integ.findtext("level", "")
        if level:
            try:
                lvl = int(level)
                if 1 <= lvl <= 15:
                    print(f"{PASS} <level> = {lvl}")
                else:
                    print(f"{FAIL} <level> must be 1-15, got {lvl}")
                    ok = False
            except ValueError:
                print(f"{FAIL} <level> is not an integer: {level!r}")
                ok = False

        api_key = integ.findtext("api_key", "")
        if api_key and len(api_key) > 5:
            print(f"{WARN} <api_key> is non-empty. Ensure it is NOT committed as a real secret.")
        else:
            print(f"{PASS} <api_key> is empty (no hardcoded secret)")

    return ok


def validate_sender(path: str) -> bool:
    ok = True
    print(f"\n{INFO} Validating sender: {path}")
    if not os.path.isfile(path):
        print(f"{FAIL} File not found: {path}")
        return False

    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()

    # Parse AST
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        print(f"{FAIL} Python syntax error: {exc}")
        return False

    print(f"{PASS} Python syntax valid")

    # Security checks: look for dangerous patterns
    dangerous = ["eval(", "exec(", "shell=True", "subprocess.call", "os.system("]
    for pattern in dangerous:
        if pattern in source:
            print(f"{FAIL} SECURITY: Found dangerous pattern: {pattern!r}")
            ok = False
        else:
            print(f"{PASS} No {pattern!r} found")

    # Check for timeout usage
    if "timeout" in source:
        print(f"{PASS} timeout parameter is present")
    else:
        print(f"{WARN} No 'timeout' found in sender — verify timeouts are set.")

    # Check for hardcoded non-placeholder URLs
    import re
    urls = re.findall(r'https?://[^\s\'"]+', source)
    for url in urls:
        if "127.0.0.1" in url or "localhost" in url:
            print(f"{PASS} URL {url!r} is a safe local placeholder")
        else:
            print(f"{WARN} Non-localhost URL found: {url!r} — verify this is intentional")

    return ok


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate CyberQalqon Wazuh integration files.")
    parser.add_argument("--snippet", default=_DEFAULT_SNIPPET)
    parser.add_argument("--sender", default=_DEFAULT_SENDER)
    args = parser.parse_args()

    results = []
    results.append(("snippet", validate_snippet(args.snippet)))
    results.append(("sender", validate_sender(args.sender)))

    print("\n=== Validation Summary ===")
    all_ok = True
    for name, passed in results:
        status = PASS if passed else FAIL
        print(f"  {status} {name}")
        if not passed:
            all_ok = False

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
