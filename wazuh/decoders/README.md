# wazuh/decoders — Custom Wazuh Decoders

## Status

Phase 2: Not yet implemented.

## Purpose

Custom decoders will be added here to parse log formats from sources
not covered by default Wazuh decoders in CyberQalqon environments.

## Convention

All custom decoders must:
- Be placed before or after the default decoders as appropriate
- Be tested against real log samples
- Not conflict with existing decoder names
- Be named with the `cyberqalqon-` prefix

## Resources

- [Wazuh Decoders Syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html)