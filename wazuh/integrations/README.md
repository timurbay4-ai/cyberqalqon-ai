# wazuh/integrations — CyberQalqon Custom Integration

## Purpose

Contains the Wazuh custom integration that forwards alerts to the CyberQalqon backend.

## Files

| File | Description |
|---|---|
| `custom-cyberqalqon` | Shell wrapper (required by Wazuh integratord) |
| `cyberqalqon_sender.py` | Python alert sender |

## Wazuh Integration Interface (verified against Wazuh 4.x docs)

Wazuh integratord calls `custom-*` scripts with four arguments:

| Argument | Content |
|---|---|
| argv[1] | Path to the alert JSON file written by integratord |
| argv[2] | `<api_key>` value from ossec.conf (empty string if not set) |
| argv[3] | `<hook_url>` value from ossec.conf |
| argv[4] | Path to the full alert file (same file; interface compatibility) |

The integration must:
- Use `alert_format=json` in ossec.conf
- Be named with `custom-` prefix
- Be executable by the `wazuh` user
- Be placed in `/var/ossec/integrations/`

## Implementation Assumptions

The following assumptions were verified against the official Wazuh documentation
at `https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html`
(accessed 2026-09-30):

1. The `integratord` daemon passes the alert file path as `argv[1]`.
2. Scripts must be named `custom-<name>` and placed in `/var/ossec/integrations/`.
3. The `<alert_format>json</alert_format>` element instructs integratord to
   write the alert as a JSON file rather than a formatted text block.
4. The bundled Python interpreter path is `/var/ossec/framework/python/bin/python3`.
5. Wazuh continues security processing regardless of integration exit codes.
6. The `<api_key>` element content is passed verbatim as argv[2]; it is empty
   if the element is empty.

## Source Reference

Official page: External API integration — Wazuh server documentation
URL: `https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html`