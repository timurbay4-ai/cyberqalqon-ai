// Captured from the actual authenticated disposable CLI API; SYNTHETIC evidence only.
export const M32_RECONCILIATION = {
  "version": "m32-reconciliation-v1",
  "scope": "READ_ONLY_POINT_IN_TIME_PER_PAGE",
  "source_binding": "5675259524ae122017c06c90aa2031e5a3e75717d3f5b69af96c6e10c6f1cec9",
  "store_id": "2fae9c735a9c477da5aaabe736180972",
  "observed_at": "2026-10-25T07:09:13.778629Z",
  "revisions": [
    {
      "finding_id": "DSF-a6dea236c888f8cd67f9f618f6902cc6ce3585084ad6e4615d418b074014523d",
      "revision": 1,
      "availability": {
        "EVT-4E81DF62A4D8B510CE15F56D": "AVAILABLE",
        "EVT-92FAD42B4537DB67B5A26BEF": "AVAILABLE",
        "EVT-ACB4FB4646D4DCC73C78AB29": "AVAILABLE",
        "EVT-DA6586A472640BA80E6D85F4": "AVAILABLE"
      },
      "reference_sha256": "0bdab78cd6f124a87fd216acd719ce5f7d9ae0f255b1bddacb3b70afbeb72512"
    }
  ],
  "counts": {
    "AVAILABLE": 4
  },
  "next_cursor": null,
  "history_modified": false,
  "automatic_evidence_pins": false,
  "cross_database_atomic": false,
  "historical_continuity": "UNPROVEN"
} as const;
