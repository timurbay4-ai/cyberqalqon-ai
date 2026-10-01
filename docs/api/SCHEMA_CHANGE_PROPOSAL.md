# Shared Normalized Alert Schema Change Proposal

No shared schema was changed in Backend Phase 2.

The existing `shared/schemas/normalized_alert.schema.json` conflicts with the accepted Wazuh ingestion behavior in two places:

1. `rule.level` has a minimum of 1, while Wazuh levels and the Phase 2 scoring contract include level 0.
2. `mitre.ids` requires at least one item, while valid Wazuh alerts may have no MITRE mapping.
3. The shared schema requires alert identity, timestamp, agent identity, and rule fields, while the raw ingestion boundary must tolerate optional missing Wazuh fields and preserve rather than fabricate evidence.
4. The Phase 2 normalized representation additionally retains agent IP, destination IP, source/destination users, raw event, Wazuh rule metadata, tactics, techniques, decoder, location, and full log.

Proposed non-breaking direction: distinguish a tolerant backend ingestion model from a stricter downstream normalized-event contract, or revise the shared contract to permit level 0, an empty MITRE ID list, nullable optional evidence, and the additional evidence fields. All consumers should review a concrete shared-schema revision before it is committed.
