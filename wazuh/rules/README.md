# wazuh/rules — Custom Wazuh Rules

## Status

Phase 2: Not yet implemented.

## Purpose

Custom Wazuh rules will be added here for security events not covered by
the default Wazuh ruleset that are specific to CyberQalqon deployments.

## Convention

All custom rules must:
- Use rule IDs in the 100000-199999 range (Wazuh custom rule space)
- Include a `<mitre>` element with relevant ATT&CK technique IDs
- Be tested against sample events before deployment

## Example Rule Structure

```xml
<rule id="100001" level="10">
  <if_sid>5710</if_sid>
  <match>Failed password</match>
  <description>CyberQalqon: Multiple SSH authentication failures</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,cyberqalqon,</group>
</rule>
```