// SYNTHETIC: captured from real disposable ingest/CQQL/shadow APIs, not production.
export const M30_API_CONTRACT = {
  "catalog": {
    "version": "cdrc-v2",
    "scope": "SOURCE_TEST_RESULTS",
    "production_active": false,
    "simulation_enabled": true,
    "rules": [
      {
        "definition": {
          "contract": "cdrc-v2",
          "rule_id": "SHADOW-WINDOWS-AUTH",
          "title": "Potential suspicious Windows authentication sequence",
          "description": "Three failures followed by a success in the same claimed endpoint/account/source scope; requires analyst validation.",
          "author": "CyberQalqon M30",
          "status": "SHADOW_ONLY",
          "severity": 8,
          "confidence": 40,
          "minimum_confidence": 0,
          "source_families": [
            "WINDOWS_EVENTCHANNEL"
          ],
          "required_fields": [
            "host.name",
            "user.name",
            "source.ip"
          ],
          "steps": [
            {
              "query": "event.code = \"4625\" AND event.outcome = \"failure\"",
              "threshold": 3,
              "process_basename_equals": null,
              "parent_basename_equals": null
            },
            {
              "query": "event.code = \"4624\" AND event.outcome = \"success\"",
              "threshold": 1,
              "process_basename_equals": null,
              "parent_basename_equals": null
            }
          ],
          "group_by": [
            "user.name",
            "source.ip"
          ],
          "window_seconds": 600,
          "allowed_lateness": 60,
          "suppression_policy": "EVIDENCE_IDENTITY_ONLY",
          "account_identity_policy": "SID_WHEN_PRESENT_NO_DOWNGRADE",
          "source_duplicate_policy": "SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY",
          "mitre_ids": [
            "T1110.001",
            "T1078"
          ],
          "tags": [
            "related:DET-002"
          ],
          "references": [],
          "created_at": "2026-10-24T00:00:00Z",
          "updated_at": "2026-10-24T00:00:00Z"
        },
        "rule_version": "0265a87342b65eadc0dce1575a5ca9ae4aa83b10e2ef7b2b44db846af483e5df"
      },
      {
        "definition": {
          "contract": "cdrc-v2",
          "rule_id": "SHADOW-SSH-AUTH",
          "title": "Potential suspicious SSH authentication sequence",
          "description": "Three SSH failures followed by success; NAT and legitimate retries remain alternative explanations.",
          "author": "CyberQalqon M30",
          "status": "SHADOW_ONLY",
          "severity": 8,
          "confidence": 40,
          "minimum_confidence": 0,
          "source_families": [
            "LINUX_AUTH"
          ],
          "required_fields": [
            "host.name",
            "user.name",
            "source.ip"
          ],
          "steps": [
            {
              "query": "event.category = \"linux_ssh\" AND event.outcome = \"failure\"",
              "threshold": 3,
              "process_basename_equals": null,
              "parent_basename_equals": null
            },
            {
              "query": "event.category = \"linux_ssh\" AND event.outcome = \"success\"",
              "threshold": 1,
              "process_basename_equals": null,
              "parent_basename_equals": null
            }
          ],
          "group_by": [
            "user.name",
            "source.ip"
          ],
          "window_seconds": 600,
          "allowed_lateness": 60,
          "suppression_policy": "EVIDENCE_IDENTITY_ONLY",
          "account_identity_policy": "SID_WHEN_PRESENT_NO_DOWNGRADE",
          "source_duplicate_policy": "SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY",
          "mitre_ids": [
            "T1110.001",
            "T1078"
          ],
          "tags": [
            "related:DET-007"
          ],
          "references": [],
          "created_at": "2026-10-24T00:00:00Z",
          "updated_at": "2026-10-24T00:00:00Z"
        },
        "rule_version": "3761f4e3d050cb1a6415761b464476f23e9d0cb598db954c2a6a3c7f6b4303c6"
      },
      {
        "definition": {
          "contract": "cdrc-v2",
          "rule_id": "SHADOW-OFFICE-SCRIPT",
          "title": "Office parent with script interpreter",
          "description": "Recorded parent/child executable names, not proof of malicious payload or verified process ancestry.",
          "author": "CyberQalqon M30",
          "status": "SHADOW_ONLY",
          "severity": 8,
          "confidence": 40,
          "minimum_confidence": 0,
          "source_families": [
            "SYSMON"
          ],
          "required_fields": [
            "host.name",
            "process.name",
            "process.parent.name"
          ],
          "steps": [
            {
              "query": "event.code = \"1\"",
              "threshold": 1,
              "process_basename_equals": "powershell.exe",
              "parent_basename_equals": "WINWORD.EXE"
            }
          ],
          "group_by": [
            "host.name"
          ],
          "window_seconds": 600,
          "allowed_lateness": 60,
          "suppression_policy": "EVIDENCE_IDENTITY_ONLY",
          "account_identity_policy": "SID_WHEN_PRESENT_NO_DOWNGRADE",
          "source_duplicate_policy": "SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY",
          "mitre_ids": [
            "T1059.001"
          ],
          "tags": [],
          "references": [],
          "created_at": "2026-10-24T00:00:00Z",
          "updated_at": "2026-10-24T00:00:00Z"
        },
        "rule_version": "188406fd50fe6b6ede72f1eb86103088747fb39dda10980a5e14f813c39c4f5b"
      },
      {
        "definition": {
          "contract": "cdrc-v2",
          "rule_id": "SHADOW-PROCESS-NETWORK",
          "title": "Observed process/network sequence",
          "description": "Process creation then connection sharing a real source ProcessGuid, scoped to one claimed endpoint. Not exfiltration evidence.",
          "author": "CyberQalqon M30",
          "status": "SHADOW_ONLY",
          "severity": 8,
          "confidence": 40,
          "minimum_confidence": 0,
          "source_families": [
            "SYSMON"
          ],
          "required_fields": [
            "host.name",
            "process.guid"
          ],
          "steps": [
            {
              "query": "event.code = \"1\"",
              "threshold": 1,
              "process_basename_equals": null,
              "parent_basename_equals": null
            },
            {
              "query": "event.code = \"3\"",
              "threshold": 1,
              "process_basename_equals": null,
              "parent_basename_equals": null
            }
          ],
          "group_by": [
            "process.guid"
          ],
          "window_seconds": 600,
          "allowed_lateness": 60,
          "suppression_policy": "EVIDENCE_IDENTITY_ONLY",
          "account_identity_policy": "SID_WHEN_PRESENT_NO_DOWNGRADE",
          "source_duplicate_policy": "SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY",
          "mitre_ids": [],
          "tags": [],
          "references": [],
          "created_at": "2026-10-24T00:00:00Z",
          "updated_at": "2026-10-24T00:00:00Z"
        },
        "rule_version": "6e9f779cb384bdf7688e80df3100ac163dc0af9ac968b0b947044ab24fee53ee"
      },
      {
        "definition": {
          "contract": "cdrc-v2",
          "rule_id": "SHADOW-ACCOUNT-PRIVILEGE",
          "title": "Account creation followed by privilege context",
          "description": "Same scoped account name and host, not a proven privilege transition or globally verified SID identity.",
          "author": "CyberQalqon M30",
          "status": "SHADOW_ONLY",
          "severity": 8,
          "confidence": 40,
          "minimum_confidence": 0,
          "source_families": [
            "WINDOWS_EVENTCHANNEL"
          ],
          "required_fields": [
            "host.name",
            "user.name"
          ],
          "steps": [
            {
              "query": "event.code = \"4720\"",
              "threshold": 1,
              "process_basename_equals": null,
              "parent_basename_equals": null
            },
            {
              "query": "event.code = \"4672\"",
              "threshold": 1,
              "process_basename_equals": null,
              "parent_basename_equals": null
            }
          ],
          "group_by": [
            "user.name"
          ],
          "window_seconds": 600,
          "allowed_lateness": 60,
          "suppression_policy": "EVIDENCE_IDENTITY_ONLY",
          "account_identity_policy": "SID_WHEN_PRESENT_NO_DOWNGRADE",
          "source_duplicate_policy": "SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY",
          "mitre_ids": [
            "T1136"
          ],
          "tags": [],
          "references": [],
          "created_at": "2026-10-24T00:00:00Z",
          "updated_at": "2026-10-24T00:00:00Z"
        },
        "rule_version": "95a146c76a7333e2ff45c37b719566d7c4e67f771e81164ff49790b5fbd9fe6a"
      },
      {
        "definition": {
          "contract": "cdrc-v2",
          "rule_id": "SHADOW-HOST-CONTEXT",
          "title": "Cross-source logon/process context hypothesis",
          "description": "Two source families in the same claimed endpoint/account-name scope. Temporal context only: no verified SID/logon-ID or causal process ownership claim.",
          "author": "CyberQalqon M30",
          "status": "SHADOW_ONLY",
          "severity": 8,
          "confidence": 20,
          "minimum_confidence": 0,
          "source_families": [
            "WINDOWS_EVENTCHANNEL",
            "SYSMON"
          ],
          "required_fields": [
            "host.name",
            "user.name"
          ],
          "steps": [
            {
              "query": "event.code = \"4624\"",
              "threshold": 1,
              "process_basename_equals": null,
              "parent_basename_equals": null
            },
            {
              "query": "event.code = \"1\"",
              "threshold": 1,
              "process_basename_equals": null,
              "parent_basename_equals": null
            }
          ],
          "group_by": [
            "user.name"
          ],
          "window_seconds": 600,
          "allowed_lateness": 60,
          "suppression_policy": "EVIDENCE_IDENTITY_ONLY",
          "account_identity_policy": "SID_WHEN_PRESENT_NO_DOWNGRADE",
          "source_duplicate_policy": "SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY",
          "mitre_ids": [],
          "tags": [],
          "references": [],
          "created_at": "2026-10-24T00:00:00Z",
          "updated_at": "2026-10-24T00:00:00Z"
        },
        "rule_version": "44fbf60451e0c8ff0cf95526d68e014a02cfb700214acb32b4698dc398dc92bb"
      }
    ],
    "legacy_compatibility": [
      {
        "rule_id": "DET-001",
        "required_fields": [
          "hostname",
          "username",
          "logon_type"
        ],
        "source_types": [
          "windows_event"
        ],
        "window_seconds": 300,
        "mitre_ids": [
          "T1110.001"
        ],
        "enabled": false,
        "runtime_activation_state": "DISABLED_BY_POLICY",
        "deployment_eligibility": "SHADOW_ONLY",
        "semantics": "UNCHANGED_EXISTING_M11_EVALUATOR"
      },
      {
        "rule_id": "DET-002",
        "required_fields": [
          "hostname",
          "username",
          "logon_type"
        ],
        "source_types": [
          "windows_event"
        ],
        "window_seconds": 600,
        "mitre_ids": [
          "T1110.001",
          "T1078"
        ],
        "enabled": false,
        "runtime_activation_state": "DISABLED_BY_POLICY",
        "deployment_eligibility": "SHADOW_ONLY",
        "semantics": "UNCHANGED_EXISTING_M11_EVALUATOR"
      },
      {
        "rule_id": "DET-003",
        "required_fields": [
          "hostname",
          "username",
          "logon_id",
          "source_ip",
          "logon_type"
        ],
        "source_types": [
          "windows_event"
        ],
        "window_seconds": 120,
        "mitre_ids": [
          "T1078"
        ],
        "enabled": false,
        "runtime_activation_state": "DISABLED_BY_POLICY",
        "deployment_eligibility": "SHADOW_ONLY",
        "semantics": "UNCHANGED_EXISTING_M11_EVALUATOR"
      },
      {
        "rule_id": "DET-004",
        "required_fields": [
          "hostname",
          "account_or_group_context"
        ],
        "source_types": [
          "windows_event"
        ],
        "window_seconds": 300,
        "mitre_ids": [
          "T1136",
          "T1098.007"
        ],
        "enabled": false,
        "runtime_activation_state": "DISABLED_BY_POLICY",
        "deployment_eligibility": "SHADOW_ONLY",
        "semantics": "UNCHANGED_EXISTING_M11_EVALUATOR"
      },
      {
        "rule_id": "DET-005",
        "required_fields": [
          "hostname",
          "command_or_script"
        ],
        "source_types": [
          "windows_event"
        ],
        "window_seconds": 300,
        "mitre_ids": [
          "T1059.001",
          "T1027.010"
        ],
        "enabled": false,
        "runtime_activation_state": "DISABLED_BY_POLICY",
        "deployment_eligibility": "SHADOW_ONLY",
        "semantics": "UNCHANGED_EXISTING_M11_EVALUATOR"
      },
      {
        "rule_id": "DET-006",
        "required_fields": [
          "hostname",
          "service_metadata"
        ],
        "source_types": [
          "windows_event"
        ],
        "window_seconds": 600,
        "mitre_ids": [
          "T1543.003"
        ],
        "enabled": false,
        "runtime_activation_state": "DISABLED_BY_POLICY",
        "deployment_eligibility": "SHADOW_ONLY",
        "semantics": "UNCHANGED_EXISTING_M11_EVALUATOR"
      },
      {
        "rule_id": "DET-007",
        "required_fields": [
          "hostname",
          "username",
          "source_ip"
        ],
        "source_types": [
          "authentication",
          "wazuh_alert",
          "wazuh_archive"
        ],
        "window_seconds": 600,
        "mitre_ids": [
          "T1110.001",
          "T1078"
        ],
        "enabled": false,
        "runtime_activation_state": "DISABLED_BY_POLICY",
        "deployment_eligibility": "SHADOW_ONLY",
        "semantics": "UNCHANGED_EXISTING_M11_EVALUATOR"
      },
      {
        "rule_id": "DET-008",
        "required_fields": [
          "hostname",
          "username",
          "command_or_failure"
        ],
        "source_types": [
          "authentication",
          "wazuh_alert",
          "wazuh_archive"
        ],
        "window_seconds": 300,
        "mitre_ids": [
          "T1548.003"
        ],
        "enabled": false,
        "runtime_activation_state": "DISABLED_BY_POLICY",
        "deployment_eligibility": "SHADOW_ONLY",
        "semantics": "UNCHANGED_EXISTING_M11_EVALUATOR"
      },
      {
        "rule_id": "DET-009",
        "required_fields": [
          "hostname",
          "defender_threat_context"
        ],
        "source_types": [
          "windows_event"
        ],
        "window_seconds": 3600,
        "mitre_ids": [],
        "enabled": false,
        "runtime_activation_state": "DISABLED_BY_POLICY",
        "deployment_eligibility": "SHADOW_ONLY",
        "semantics": "UNCHANGED_EXISTING_M11_EVALUATOR"
      }
    ],
    "fields": [
      {
        "name": "event.id",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.event_id",
        "derived": false,
        "searchable": true
      },
      {
        "name": "event.code",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.event_code",
        "derived": false,
        "searchable": true
      },
      {
        "name": "event.category",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.event_category",
        "derived": false,
        "searchable": true
      },
      {
        "name": "event.action",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.event_action",
        "derived": false,
        "searchable": true
      },
      {
        "name": "event.outcome",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.outcome",
        "derived": false,
        "searchable": true
      },
      {
        "name": "event.severity",
        "data_type": "integer",
        "operators": [
          "=",
          "!=",
          ">",
          ">=",
          "<",
          "<="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.severity",
        "derived": false,
        "searchable": true
      },
      {
        "name": "event.source_type",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.source_type",
        "derived": false,
        "searchable": true
      },
      {
        "name": "event.provider",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.event_provider",
        "derived": false,
        "searchable": true
      },
      {
        "name": "event.channel",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": false,
        "sensitivity": "standard",
        "source": "security_events.event_channel",
        "derived": false,
        "searchable": true
      },
      {
        "name": "event.timestamp",
        "data_type": "timestamp",
        "operators": [],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.occurred_at",
        "derived": false,
        "searchable": false
      },
      {
        "name": "host.name",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.hostname",
        "derived": false,
        "searchable": true
      },
      {
        "name": "host.os",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.operating_system",
        "derived": false,
        "searchable": true
      },
      {
        "name": "agent.id",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.agent_id",
        "derived": false,
        "searchable": true
      },
      {
        "name": "agent.name",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": false,
        "sensitivity": "standard",
        "source": "security_events.agent_name",
        "derived": false,
        "searchable": true
      },
      {
        "name": "source.ip",
        "data_type": "ip",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "network",
        "source": "security_events.source_ip",
        "derived": false,
        "searchable": true
      },
      {
        "name": "destination.ip",
        "data_type": "ip",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "network",
        "source": "security_events.destination_ip",
        "derived": false,
        "searchable": true
      },
      {
        "name": "source.port",
        "data_type": "integer",
        "operators": [
          "=",
          "!=",
          ">",
          ">=",
          "<",
          "<="
        ],
        "indexed": false,
        "sensitivity": "network",
        "source": "security_events.source_port",
        "derived": false,
        "searchable": true
      },
      {
        "name": "destination.port",
        "data_type": "integer",
        "operators": [
          "=",
          "!=",
          ">",
          ">=",
          "<",
          "<="
        ],
        "indexed": false,
        "sensitivity": "network",
        "source": "security_events.destination_port",
        "derived": false,
        "searchable": true
      },
      {
        "name": "user.name",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "identity",
        "source": "security_events.username",
        "derived": false,
        "searchable": true
      },
      {
        "name": "rule.id",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "standard",
        "source": "security_events.rule_id",
        "derived": false,
        "searchable": true
      },
      {
        "name": "mitre.id",
        "data_type": "mitre",
        "operators": [
          "=",
          "!="
        ],
        "indexed": false,
        "sensitivity": "standard",
        "source": "security_events.mitre_ids_json",
        "derived": true,
        "searchable": true
      },
      {
        "name": "process.name",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": true,
        "sensitivity": "evidence",
        "source": "security_events.process_name",
        "derived": false,
        "searchable": true
      },
      {
        "name": "process.parent.name",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": false,
        "sensitivity": "evidence",
        "source": "security_events.parent_process_name",
        "derived": false,
        "searchable": true
      },
      {
        "name": "ingestion.source",
        "data_type": "string",
        "operators": [
          "=",
          "!="
        ],
        "indexed": false,
        "sensitivity": "standard",
        "source": "security_events.ingestion_source",
        "derived": false,
        "searchable": true
      },
      {
        "name": "text",
        "data_type": "text",
        "operators": [
          "CONTAINS"
        ],
        "indexed": true,
        "sensitivity": "evidence",
        "source": "security_events_fts.search_text",
        "derived": true,
        "searchable": true
      }
    ],
    "source_specific_extensions": [
      "process.guid",
      "process.parent.guid"
    ],
    "limits": {
      "max_events": 1000,
      "max_groups": 256,
      "max_events_per_group": 64,
      "max_input_bytes": 8388608,
      "max_findings": 100,
      "max_graph_nodes": 128,
      "max_graph_edges": 256,
      "max_concurrent_evaluations": 2,
      "cqql_deadline_ms": 1500,
      "cqql_slots": 4
    }
  },
  "validation": {
    "valid": true,
    "rule_version": "0265a87342b65eadc0dce1575a5ca9ae4aa83b10e2ef7b2b44db846af483e5df",
    "definition": {
      "contract": "cdrc-v2",
      "rule_id": "SHADOW-WINDOWS-AUTH",
      "title": "Potential suspicious Windows authentication sequence",
      "description": "Three failures followed by a success in the same claimed endpoint/account/source scope; requires analyst validation.",
      "author": "CyberQalqon M30",
      "status": "SHADOW_ONLY",
      "severity": 8,
      "confidence": 40,
      "minimum_confidence": 0,
      "source_families": [
        "WINDOWS_EVENTCHANNEL"
      ],
      "required_fields": [
        "host.name",
        "user.name",
        "source.ip"
      ],
      "steps": [
        {
          "query": "event.code = \"4625\" AND event.outcome = \"failure\"",
          "threshold": 3,
          "process_basename_equals": null,
          "parent_basename_equals": null
        },
        {
          "query": "event.code = \"4624\" AND event.outcome = \"success\"",
          "threshold": 1,
          "process_basename_equals": null,
          "parent_basename_equals": null
        }
      ],
      "group_by": [
        "user.name",
        "source.ip"
      ],
      "window_seconds": 600,
      "allowed_lateness": 60,
      "suppression_policy": "EVIDENCE_IDENTITY_ONLY",
      "account_identity_policy": "SID_WHEN_PRESENT_NO_DOWNGRADE",
      "source_duplicate_policy": "SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY",
      "mitre_ids": [
        "T1110.001",
        "T1078"
      ],
      "tags": [
        "related:DET-002"
      ],
      "references": [],
      "created_at": "2026-10-24T00:00:00Z",
      "updated_at": "2026-10-24T00:00:00Z"
    },
    "production_active": false,
    "warnings": [
      "STATELESS_SIMULATION_ONLY",
      "CLAIMED_SOURCE_IDENTITY",
      "HISTORICAL_CONTINUITY_UNPROVEN"
    ]
  },
  "result": {
    "version": "cdrc-v2",
    "scope": "DISPOSABLE_SIMULATION",
    "status": "COMPLETE",
    "outcome": "MATCH",
    "rule_version": "0265a87342b65eadc0dce1575a5ca9ae4aa83b10e2ef7b2b44db846af483e5df",
    "findings": [
      {
        "finding_id": "SF-2a78cc1b74b0a05d5715a3732b90b3924ca160d1c9fca6654f12013a649dddae",
        "rule_id": "SHADOW-WINDOWS-AUTH",
        "rule_version": "0265a87342b65eadc0dce1575a5ca9ae4aa83b10e2ef7b2b44db846af483e5df",
        "evidence_manifest_sha256": "c3d685ea8437731041b14371c3bbf3f461c854abc8d4fbdd318621cacc99bf7a",
        "rule_snapshot": {
          "contract": "cdrc-v2",
          "rule_id": "SHADOW-WINDOWS-AUTH",
          "title": "Potential suspicious Windows authentication sequence",
          "description": "Three failures followed by a success in the same claimed endpoint/account/source scope; requires analyst validation.",
          "author": "CyberQalqon M30",
          "status": "SHADOW_ONLY",
          "severity": 8,
          "confidence": 40,
          "minimum_confidence": 0,
          "source_families": [
            "WINDOWS_EVENTCHANNEL"
          ],
          "required_fields": [
            "host.name",
            "user.name",
            "source.ip"
          ],
          "steps": [
            {
              "query": "event.code = \"4625\" AND event.outcome = \"failure\"",
              "threshold": 3,
              "process_basename_equals": null,
              "parent_basename_equals": null
            },
            {
              "query": "event.code = \"4624\" AND event.outcome = \"success\"",
              "threshold": 1,
              "process_basename_equals": null,
              "parent_basename_equals": null
            }
          ],
          "group_by": [
            "user.name",
            "source.ip"
          ],
          "window_seconds": 600,
          "allowed_lateness": 60,
          "suppression_policy": "EVIDENCE_IDENTITY_ONLY",
          "account_identity_policy": "SID_WHEN_PRESENT_NO_DOWNGRADE",
          "source_duplicate_policy": "SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY",
          "mitre_ids": [
            "T1110.001",
            "T1078"
          ],
          "tags": [
            "related:DET-002"
          ],
          "references": [],
          "created_at": "2026-10-24T00:00:00Z",
          "updated_at": "2026-10-24T00:00:00Z"
        },
        "evaluation_version": "m30-shadow-v1",
        "status": "SHADOW_ONLY",
        "severity": 8,
        "confidence": 40,
        "identity_confidence": "CLAIMED_ENDPOINT_SCOPED",
        "window_start": "2026-10-24T18:35:48Z",
        "window_end": "2026-10-24T18:36:18Z",
        "completeness": "UNPROVEN",
        "group": {
          "user.name": "SYNTHETIC\\analyst",
          "source.ip": "192.0.2.30",
          "account_identity_basis": "SCOPED_NAME_ONLY_OR_NOT_USED"
        },
        "explanation": "Observed ordered rule predicates in one claimed endpoint scope. Potential suspicious activity; requires analyst validation.",
        "uncertainty": [
          "Endpoint/account ownership is not independently verified.",
          "No global source watermark; window/historical continuity UNPROVEN.",
          "Benign retries or approved administration may explain this activity.",
          "Evidence is not pinned; recheck availability on drill-down."
        ],
        "evidence": [
          {
            "event_id": "EVT-F7191EB07ED3973748636FEC",
            "event_time": "2026-10-24T18:35:48Z",
            "ingestion_time": "2026-10-24T18:55:49.363730Z",
            "source_family": "WINDOWS_EVENTCHANNEL",
            "host": "SYNTH-M30-WINDOWS",
            "user": "SYNTHETIC\\analyst",
            "user_sid": null,
            "process": "C:\\Synthetic\\example.exe",
            "event_code": "4625",
            "process_guid": null,
            "stored_envelope_sha256": "f7191eb07ed3973748636fec6c149bcebd14f14d0f6aebb5535d4dc0039cc165",
            "source_identity_sha256": "9b8aa1acefc61e70d7b11cde984003a778fe8e6c1ab2969e9b8dc8de00adc5c7",
            "source_record_key_sha256": "cf3225a58944a6050b0aece934ed924f2d6eedc7c9262028460370fdc81941fb",
            "provenance": "PARTIAL"
          },
          {
            "event_id": "EVT-E77DA74B91B3B62CCF6C7F96",
            "event_time": "2026-10-24T18:35:58Z",
            "ingestion_time": "2026-10-24T18:55:49.404858Z",
            "source_family": "WINDOWS_EVENTCHANNEL",
            "host": "SYNTH-M30-WINDOWS",
            "user": "SYNTHETIC\\analyst",
            "user_sid": null,
            "process": "C:\\Synthetic\\example.exe",
            "event_code": "4625",
            "process_guid": null,
            "stored_envelope_sha256": "e77da74b91b3b62ccf6c7f9649e703be1ff1a3ef93bc72ec44c20a122fcc7dba",
            "source_identity_sha256": "9b8aa1acefc61e70d7b11cde984003a778fe8e6c1ab2969e9b8dc8de00adc5c7",
            "source_record_key_sha256": "2eb4dc39a6d78502d5862bff6454bdc50547976ef38ddb84aacdfdd5472ebce7",
            "provenance": "PARTIAL"
          },
          {
            "event_id": "EVT-3DDA9A82B00B358E65C7FA79",
            "event_time": "2026-10-24T18:36:08Z",
            "ingestion_time": "2026-10-24T18:55:49.455218Z",
            "source_family": "WINDOWS_EVENTCHANNEL",
            "host": "SYNTH-M30-WINDOWS",
            "user": "SYNTHETIC\\analyst",
            "user_sid": null,
            "process": "C:\\Synthetic\\example.exe",
            "event_code": "4625",
            "process_guid": null,
            "stored_envelope_sha256": "3dda9a82b00b358e65c7fa79bd614e1f38801bb816e938b3dfef750ebd8e2778",
            "source_identity_sha256": "9b8aa1acefc61e70d7b11cde984003a778fe8e6c1ab2969e9b8dc8de00adc5c7",
            "source_record_key_sha256": "9a04717e2e67fa07e800f95e8d326019ce765d59e43d06af0bd5d67ad40fb16b",
            "provenance": "PARTIAL"
          },
          {
            "event_id": "EVT-7AF8ABDA0F3D777E939E142E",
            "event_time": "2026-10-24T18:36:18Z",
            "ingestion_time": "2026-10-24T18:55:49.501857Z",
            "source_family": "WINDOWS_EVENTCHANNEL",
            "host": "SYNTH-M30-WINDOWS",
            "user": "SYNTHETIC\\analyst",
            "user_sid": null,
            "process": "C:\\Synthetic\\example.exe",
            "event_code": "4624",
            "process_guid": null,
            "stored_envelope_sha256": "7af8abda0f3d777e939e142e7527a0c0ea8e220e16442a21c23770a79d2639ee",
            "source_identity_sha256": "9b8aa1acefc61e70d7b11cde984003a778fe8e6c1ab2969e9b8dc8de00adc5c7",
            "source_record_key_sha256": "8a09db79b3627d2766364b40af181df7de9c4c6abfb8980100a7535221d20541",
            "provenance": "PARTIAL"
          }
        ],
        "mitre": [
          {
            "technique_id": "T1110.001",
            "name": "Password Guessing",
            "tactic": "Credential Access",
            "evidence_strength": "RULE_TAGGED_TECHNIQUE"
          },
          {
            "technique_id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
            "evidence_strength": "RULE_TAGGED_TECHNIQUE"
          }
        ]
      }
    ],
    "graph_edges": [
      {
        "source": "SF-2a78cc1b74b0a05d5715a3732b90b3924ca160d1c9fca6654f12013a649dddae",
        "target": "EVT-F7191EB07ED3973748636FEC",
        "relationship": "FINDING_SUPPORTED_BY_EVENT",
        "causal_claim": false
      },
      {
        "source": "SF-2a78cc1b74b0a05d5715a3732b90b3924ca160d1c9fca6654f12013a649dddae",
        "target": "EVT-E77DA74B91B3B62CCF6C7F96",
        "relationship": "FINDING_SUPPORTED_BY_EVENT",
        "causal_claim": false
      },
      {
        "source": "EVT-F7191EB07ED3973748636FEC",
        "target": "EVT-E77DA74B91B3B62CCF6C7F96",
        "relationship": "OBSERVED_BEFORE",
        "causal_claim": false
      },
      {
        "source": "SF-2a78cc1b74b0a05d5715a3732b90b3924ca160d1c9fca6654f12013a649dddae",
        "target": "EVT-3DDA9A82B00B358E65C7FA79",
        "relationship": "FINDING_SUPPORTED_BY_EVENT",
        "causal_claim": false
      },
      {
        "source": "EVT-E77DA74B91B3B62CCF6C7F96",
        "target": "EVT-3DDA9A82B00B358E65C7FA79",
        "relationship": "OBSERVED_BEFORE",
        "causal_claim": false
      },
      {
        "source": "SF-2a78cc1b74b0a05d5715a3732b90b3924ca160d1c9fca6654f12013a649dddae",
        "target": "EVT-7AF8ABDA0F3D777E939E142E",
        "relationship": "FINDING_SUPPORTED_BY_EVENT",
        "causal_claim": false
      },
      {
        "source": "EVT-3DDA9A82B00B358E65C7FA79",
        "target": "EVT-7AF8ABDA0F3D777E939E142E",
        "relationship": "OBSERVED_BEFORE",
        "causal_claim": false
      }
    ],
    "diagnostics": {
      "CANDIDATE_ROWS": 4,
      "ON_TIME": 4
    },
    "candidate_truncated": false,
    "coverage": "BOUNDED_CANDIDATE_SLICE",
    "historical_continuity": "UNPROVEN",
    "window_completeness": "UNPROVEN",
    "evidence_retention": "NOT_PINNED_RECHECK_ON_DRILLDOWN",
    "persistence": "STATELESS_CONTENT_ADDRESSED_OUTPUT",
    "side_effects": false,
    "execution_ms": 8.624
  }
} as const;
