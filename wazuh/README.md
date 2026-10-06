# Wazuh Integration — CyberQalqon AI

**Owner:** Security / Integration Lead
**Status:** Wazuh manager setup and forwarding are not implemented; the backend receiver is available

---

## Important Note

**Wazuh is not installed by this repository.**
Do not attempt to install or configure Wazuh agents until the backend API is ready to receive events.

---

## Future Responsibilities

### Agent Integration
- Deploy Wazuh agents on monitored endpoints (Windows workstations, Linux servers)
- Configure agent enrollment and communication with the Wazuh manager
- Document the agent deployment process in `wazuh/configs/`

### Custom Integration
- Create a custom Wazuh integration script in `wazuh/integrations/`
- The future integration script will forward raw Wazuh alert JSON to the CyberQalqon backend API (`POST /api/v1/alerts/ingest`)
- The request must include the configured `WAZUH_INGEST_API_KEY` in the `X-API-Key` header
- The backend performs deterministic normalization, validation, and idempotent persistence
- Use the `NormalizedAlert` schema in `shared/schemas/normalized_alert.schema.json`

### Rule Mapping
- Add custom Wazuh rules in `wazuh/rules/` for security events not covered by default ruleset
- Map rules to MITRE ATT&CK technique IDs
- Preserve MITRE context during normalization

### MITRE ATT&CK Preservation
- All custom rules must include a `<mitre>` element
- The integration pipeline must extract and preserve MITRE IDs into the `NormalizedAlert.mitre.ids` array
- Refer to `shared/schemas/normalized_alert.schema.json` for the expected format

### Sample Alerts
- Add representative sample Wazuh alert JSON payloads in `wazuh/samples/`
- These are used by the backend developer for integration testing
- Use sanitized, non-real data only

---

## Directory Structure

```
wazuh/
├── integrations/   ← Custom integration scripts (Python)
├── rules/          ← Custom Wazuh XML rules
├── decoders/       ← Custom Wazuh XML decoders
├── configs/        ← Wazuh manager and agent config templates
├── scripts/        ← Utility scripts (enrollment, testing)
└── samples/        ← Example raw Wazuh alert JSON payloads
```

---

## Key References

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- Shared alert schema: `shared/schemas/normalized_alert.schema.json`
