// Actual SYNTHETIC M31 reviewed backend API capture; no auth values or invented findings.
export const M31_API_CONTRACT = {
  "history_status": {
    "enabled": true,
    "scope": "DISPOSABLE_DURABLE_SHADOW",
    "production_active": false,
    "schema_version": 1,
    "resource_state": {
      "inflight": 0,
      "queue_depth": 0,
      "workers": 1,
      "queue_capacity": 4,
      "wait_ms_total": 0.017,
      "queue_peak": 0,
      "admitted": 2,
      "released": 2
    },
    "recovery_runs": []
  },
  "durable_run": {
    "run_id": "RUN-dd615d97d1034e0cb8092366178ef2d8",
    "status": "COMPLETED",
    "attempts": 1,
    "error_code": null,
    "checkpoint": "SEALED",
    "snapshot_sha256": "5aac2101d4e689ce8055d9b219f4ef133046278f89698380aae6936ac80228e4",
    "result": {
      "finding_ids": [
        "DSF-b8646b0e6e3f05ce8b75169498ff912029f99a848112f052a372a87b001c0be1"
      ],
      "diagnostics": {
        "CANDIDATE_ROWS": 4,
        "ON_TIME": 4
      },
      "coverage": "BOUNDED_CANDIDATE_SLICE",
      "identity_rejected": 0,
      "candidate_count": 1,
      "historical_continuity": "UNPROVEN",
      "window_completeness": "UNPROVEN",
      "evaluation_version": "m31-shadow-v1",
      "graph_edges": [
        {
          "source": "DSF-b8646b0e6e3f05ce8b75169498ff912029f99a848112f052a372a87b001c0be1",
          "target": "EVT-D7AC6BEBCE51B584CF5946B1",
          "relationship": "FINDING_SUPPORTED_BY_EVENT",
          "causal_claim": false
        },
        {
          "source": "DSF-b8646b0e6e3f05ce8b75169498ff912029f99a848112f052a372a87b001c0be1",
          "target": "EVT-94AE15C274AE49628B1AAC08",
          "relationship": "FINDING_SUPPORTED_BY_EVENT",
          "causal_claim": false
        },
        {
          "source": "EVT-D7AC6BEBCE51B584CF5946B1",
          "target": "EVT-94AE15C274AE49628B1AAC08",
          "relationship": "OBSERVED_BEFORE",
          "causal_claim": false
        },
        {
          "source": "DSF-b8646b0e6e3f05ce8b75169498ff912029f99a848112f052a372a87b001c0be1",
          "target": "EVT-C12F5F9588727FA3BBCC4606",
          "relationship": "FINDING_SUPPORTED_BY_EVENT",
          "causal_claim": false
        },
        {
          "source": "EVT-94AE15C274AE49628B1AAC08",
          "target": "EVT-C12F5F9588727FA3BBCC4606",
          "relationship": "OBSERVED_BEFORE",
          "causal_claim": false
        },
        {
          "source": "DSF-b8646b0e6e3f05ce8b75169498ff912029f99a848112f052a372a87b001c0be1",
          "target": "EVT-0A0CD665CCC3092C38AFB2F4",
          "relationship": "FINDING_SUPPORTED_BY_EVENT",
          "causal_claim": false
        },
        {
          "source": "EVT-C12F5F9588727FA3BBCC4606",
          "target": "EVT-0A0CD665CCC3092C38AFB2F4",
          "relationship": "OBSERVED_BEFORE",
          "causal_claim": false
        }
      ]
    },
    "recovery_state": "NOT_REQUIRED",
    "production_active": false,
    "scope": "DISPOSABLE_DURABLE_SHADOW",
    "historical_continuity": "UNPROVEN"
  },
  "history_page": {
    "items": [
      {
        "finding_id": "DSF-b8646b0e6e3f05ce8b75169498ff912029f99a848112f052a372a87b001c0be1",
        "matching_id": "SF-9101e04fd97a635a25e25fd3edd3c51e8156c49c1681c13cf85181c22eca99b8",
        "rule_version": "0265a87342b65eadc0dce1575a5ca9ae4aa83b10e2ef7b2b44db846af483e5df",
        "policy_sha": "b2ae98dca860525f1e4d08bbf2006038070b9a969c290e6a3ec69af4907ea88f",
        "current_revision": 1,
        "state": "SHADOW_CANDIDATE",
        "created_at": "2026-10-25T06:33:47.397691Z",
        "last_observed_at": "2026-10-25T06:33:47.397691Z"
      }
    ],
    "next_cursor": null,
    "scope": "DISPOSABLE_DURABLE_SHADOW",
    "production_active": false
  },
  "history_detail": {
    "finding_id": "DSF-b8646b0e6e3f05ce8b75169498ff912029f99a848112f052a372a87b001c0be1",
    "matching_id": "SF-9101e04fd97a635a25e25fd3edd3c51e8156c49c1681c13cf85181c22eca99b8",
    "rule_version": "0265a87342b65eadc0dce1575a5ca9ae4aa83b10e2ef7b2b44db846af483e5df",
    "policy_sha": "b2ae98dca860525f1e4d08bbf2006038070b9a969c290e6a3ec69af4907ea88f",
    "current_revision": 1,
    "state": "SHADOW_CANDIDATE",
    "created_at": "2026-10-25T06:33:47.397691Z",
    "last_observed_at": "2026-10-25T06:33:47.397691Z",
    "revision": 1,
    "matching_evidence": {
      "finding_id": "SF-9101e04fd97a635a25e25fd3edd3c51e8156c49c1681c13cf85181c22eca99b8",
      "rule_id": "SHADOW-WINDOWS-AUTH",
      "rule_version": "0265a87342b65eadc0dce1575a5ca9ae4aa83b10e2ef7b2b44db846af483e5df",
      "evidence_manifest_sha256": "479ecc108bc9165e5ef7dbae928ae247e6af696b7523aa58b3ce18e0caed7596",
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
      "window_start": "2026-10-25T06:13:46Z",
      "window_end": "2026-10-25T06:14:16Z",
      "completeness": "UNPROVEN",
      "group": {
        "account_identity_basis": "SCOPED_NAME_ONLY_OR_NOT_USED",
        "source.ip": "192.0.2.30",
        "user.name": "SYNTHETIC\\analyst"
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
          "event_id": "EVT-D7AC6BEBCE51B584CF5946B1",
          "event_time": "2026-10-25T06:13:46Z",
          "ingestion_time": "2026-10-25T06:33:47.186708Z",
          "source_family": "WINDOWS_EVENTCHANNEL",
          "host": "SYNTH-M30-WINDOWS",
          "user": "SYNTHETIC\\analyst",
          "user_sid": null,
          "process": "C:\\Synthetic\\example.exe",
          "event_code": "4625",
          "process_guid": null,
          "stored_envelope_sha256": "d7ac6bebce51b584cf5946b16573d23cc0155a28902fcd3322f97fe744be6bda",
          "source_identity_sha256": "9b8aa1acefc61e70d7b11cde984003a778fe8e6c1ab2969e9b8dc8de00adc5c7",
          "source_record_key_sha256": "e9adbf5830c231b3a81d3ff45d799185205a1d10eaf12b05290e6ccf78007147",
          "provenance": "PARTIAL"
        },
        {
          "event_id": "EVT-94AE15C274AE49628B1AAC08",
          "event_time": "2026-10-25T06:13:56Z",
          "ingestion_time": "2026-10-25T06:33:47.209717Z",
          "source_family": "WINDOWS_EVENTCHANNEL",
          "host": "SYNTH-M30-WINDOWS",
          "user": "SYNTHETIC\\analyst",
          "user_sid": null,
          "process": "C:\\Synthetic\\example.exe",
          "event_code": "4625",
          "process_guid": null,
          "stored_envelope_sha256": "94ae15c274ae49628b1aac08e36bc78b305a6ec00eb09461f6e20e892207e55d",
          "source_identity_sha256": "9b8aa1acefc61e70d7b11cde984003a778fe8e6c1ab2969e9b8dc8de00adc5c7",
          "source_record_key_sha256": "52604b6c7759f15e609efa2032bea8675c577a3ee6b9ce567a7a157f3782392a",
          "provenance": "PARTIAL"
        },
        {
          "event_id": "EVT-C12F5F9588727FA3BBCC4606",
          "event_time": "2026-10-25T06:14:06Z",
          "ingestion_time": "2026-10-25T06:33:47.232727Z",
          "source_family": "WINDOWS_EVENTCHANNEL",
          "host": "SYNTH-M30-WINDOWS",
          "user": "SYNTHETIC\\analyst",
          "user_sid": null,
          "process": "C:\\Synthetic\\example.exe",
          "event_code": "4625",
          "process_guid": null,
          "stored_envelope_sha256": "c12f5f9588727fa3bbcc4606b89a78311b5df2e55c8c0574d6b9b4f6ce644d71",
          "source_identity_sha256": "9b8aa1acefc61e70d7b11cde984003a778fe8e6c1ab2969e9b8dc8de00adc5c7",
          "source_record_key_sha256": "e9e291b4a7cbfa7066b16df19537bc81ba393b75046f7566b389cc10b0adfcc9",
          "provenance": "PARTIAL"
        },
        {
          "event_id": "EVT-0A0CD665CCC3092C38AFB2F4",
          "event_time": "2026-10-25T06:14:16Z",
          "ingestion_time": "2026-10-25T06:33:47.265691Z",
          "source_family": "WINDOWS_EVENTCHANNEL",
          "host": "SYNTH-M30-WINDOWS",
          "user": "SYNTHETIC\\analyst",
          "user_sid": null,
          "process": "C:\\Synthetic\\example.exe",
          "event_code": "4624",
          "process_guid": null,
          "stored_envelope_sha256": "0a0cd665ccc3092c38afb2f434316eb4a9182995f8725ceea1138fe01476bb4d",
          "source_identity_sha256": "9b8aa1acefc61e70d7b11cde984003a778fe8e6c1ab2969e9b8dc8de00adc5c7",
          "source_record_key_sha256": "a8236ae05aed1bac826231bba1ad0b2948fa05addc3f66457e312b60b6c56e0d",
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
    },
    "identity": {
      "version": "m31-identity-v1",
      "policy": {
        "version": "identity-policy-v1",
        "minimum": "PARTIAL"
      },
      "satisfied": true,
      "entities": [
        {
          "kind": "HOST",
          "status": "PARTIAL",
          "entity_id": "ENTITY-f1900bb3693f31b7ab189979a909da964a4124cac87e26aa47c04174f0157121",
          "scope_sha256": "4073cdbb9ff9588f578179e52a890b3a6e8addeeeac30c1a9b8e1d7b32113723",
          "reason": "CLAIMED_SOURCE_SCOPE_ONLY",
          "evidence_ids": [
            "EVT-D7AC6BEBCE51B584CF5946B1",
            "EVT-94AE15C274AE49628B1AAC08",
            "EVT-C12F5F9588727FA3BBCC4606",
            "EVT-0A0CD665CCC3092C38AFB2F4"
          ],
          "authority_sha256": null
        },
        {
          "kind": "ACCOUNT",
          "status": "PARTIAL",
          "entity_id": "ENTITY-5401337de14f2e26d196dde82991249b25fd81548c192a3e68e12c2b0640b73e",
          "scope_sha256": "4073cdbb9ff9588f578179e52a890b3a6e8addeeeac30c1a9b8e1d7b32113723",
          "reason": "CLAIMED_SOURCE_SCOPE_ONLY",
          "evidence_ids": [
            "EVT-D7AC6BEBCE51B584CF5946B1",
            "EVT-94AE15C274AE49628B1AAC08",
            "EVT-C12F5F9588727FA3BBCC4606",
            "EVT-0A0CD665CCC3092C38AFB2F4"
          ],
          "authority_sha256": null
        },
        {
          "kind": "PROCESS",
          "status": "UNVERIFIED",
          "entity_id": null,
          "scope_sha256": "4073cdbb9ff9588f578179e52a890b3a6e8addeeeac30c1a9b8e1d7b32113723",
          "reason": "MISSING_IDENTITY",
          "evidence_ids": [
            "EVT-D7AC6BEBCE51B584CF5946B1",
            "EVT-94AE15C274AE49628B1AAC08",
            "EVT-C12F5F9588727FA3BBCC4606",
            "EVT-0A0CD665CCC3092C38AFB2F4"
          ],
          "authority_sha256": null
        },
        {
          "kind": "NETWORK_ENDPOINT",
          "status": "UNVERIFIED",
          "entity_id": null,
          "scope_sha256": "4073cdbb9ff9588f578179e52a890b3a6e8addeeeac30c1a9b8e1d7b32113723",
          "reason": "MISSING_IDENTITY",
          "evidence_ids": [
            "EVT-D7AC6BEBCE51B584CF5946B1",
            "EVT-94AE15C274AE49628B1AAC08",
            "EVT-C12F5F9588727FA3BBCC4606",
            "EVT-0A0CD665CCC3092C38AFB2F4"
          ],
          "authority_sha256": null
        },
        {
          "kind": "SESSION",
          "status": "UNVERIFIED",
          "entity_id": null,
          "scope_sha256": "4073cdbb9ff9588f578179e52a890b3a6e8addeeeac30c1a9b8e1d7b32113723",
          "reason": "MISSING_IDENTITY",
          "evidence_ids": [
            "EVT-D7AC6BEBCE51B584CF5946B1",
            "EVT-94AE15C274AE49628B1AAC08",
            "EVT-C12F5F9588727FA3BBCC4606",
            "EVT-0A0CD665CCC3092C38AFB2F4"
          ],
          "authority_sha256": null
        },
        {
          "kind": "AGENT",
          "status": "PARTIAL",
          "entity_id": "ENTITY-cf9de1588aff6aa276d98f1e88fe5eb6a2e6d8ece20247238c143dbaca178554",
          "scope_sha256": "4073cdbb9ff9588f578179e52a890b3a6e8addeeeac30c1a9b8e1d7b32113723",
          "reason": "CLAIMED_SOURCE_SCOPE_ONLY",
          "evidence_ids": [
            "EVT-D7AC6BEBCE51B584CF5946B1",
            "EVT-94AE15C274AE49628B1AAC08",
            "EVT-C12F5F9588727FA3BBCC4606",
            "EVT-0A0CD665CCC3092C38AFB2F4"
          ],
          "authority_sha256": null
        },
        {
          "kind": "COLLECTOR",
          "status": "PARTIAL",
          "entity_id": "ENTITY-ed9cf83979c0c2f1ef425b8b8d15a5adaf7f3a74071777090f58bd90f514f152",
          "scope_sha256": "4073cdbb9ff9588f578179e52a890b3a6e8addeeeac30c1a9b8e1d7b32113723",
          "reason": "CLAIMED_SOURCE_SCOPE_ONLY",
          "evidence_ids": [
            "EVT-D7AC6BEBCE51B584CF5946B1",
            "EVT-94AE15C274AE49628B1AAC08",
            "EVT-C12F5F9588727FA3BBCC4606",
            "EVT-0A0CD665CCC3092C38AFB2F4"
          ],
          "authority_sha256": null
        }
      ],
      "required_kinds": [
        "HOST",
        "ACCOUNT"
      ],
      "historical_continuity": "UNPROVEN",
      "causal_claim": false
    },
    "authority_documents": [],
    "first_observed_at": "2026-10-25T06:33:47.397691Z",
    "evidence_references": [
      {
        "event_id": "EVT-0A0CD665CCC3092C38AFB2F4",
        "envelope_sha": "0a0cd665ccc3092c38afb2f434316eb4a9182995f8725ceea1138fe01476bb4d",
        "row_sha": "c8f200a7eb6424c77dfefc2362f362268272b1f2fb590c74135bd8f901803e3a"
      },
      {
        "event_id": "EVT-94AE15C274AE49628B1AAC08",
        "envelope_sha": "94ae15c274ae49628b1aac08e36bc78b305a6ec00eb09461f6e20e892207e55d",
        "row_sha": "7dc989d672793fa58b21306ffc6d101c13c27531d427010a260b28d104ef6f31"
      },
      {
        "event_id": "EVT-C12F5F9588727FA3BBCC4606",
        "envelope_sha": "c12f5f9588727fa3bbcc4606b89a78311b5df2e55c8c0574d6b9b4f6ce644d71",
        "row_sha": "4a0ea4f3dc2dcbbf54c3c7497350bfff6bfcedb86ac97f89f7eb883e6cd7d91f"
      },
      {
        "event_id": "EVT-D7AC6BEBCE51B584CF5946B1",
        "envelope_sha": "d7ac6bebce51b584cf5946b16573d23cc0155a28902fcd3322f97fe744be6bda",
        "row_sha": "186ead136ae5dfe4a12b8711c82b6b7c75ddaf554d837be4df34f8f8f631db9d"
      }
    ],
    "history": [
      {
        "sequence": 1,
        "finding_id": "DSF-b8646b0e6e3f05ce8b75169498ff912029f99a848112f052a372a87b001c0be1",
        "revision": 1,
        "previous_state": null,
        "target_state": "SHADOW_CANDIDATE",
        "reason": "INITIAL_MATCH",
        "actor": "SYNTHETIC M30 (m30-synthetic)",
        "occurred_at": "2026-10-25T06:33:47.397691Z",
        "superseded_by": null
      }
    ],
    "history_truncated": false,
    "historical_continuity": "UNPROVEN",
    "production_active": false,
    "scope": "DISPOSABLE_DURABLE_SHADOW",
    "evidence_retention": "REFERENCES_NOT_AUTOMATIC_PINS",
    "current_evidence_availability": {
      "EVT-0A0CD665CCC3092C38AFB2F4": "AVAILABLE",
      "EVT-94AE15C274AE49628B1AAC08": "AVAILABLE",
      "EVT-C12F5F9588727FA3BBCC4606": "AVAILABLE",
      "EVT-D7AC6BEBCE51B584CF5946B1": "AVAILABLE"
    },
    "identity_context": "AT_ORIGINAL_EVALUATION_NOT_CURRENT_SOURCE_ATTESTATION"
  }
} as const;
