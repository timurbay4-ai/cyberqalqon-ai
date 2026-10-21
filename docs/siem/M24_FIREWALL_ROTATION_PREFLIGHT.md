# M24 scoped firewall repair and rotation preflight

Captured 2026-10-21 11:11:53 +05:00. This operation changed only the existing
Windows firewall rule's interface binding. Archive, checkpoint, approval,
legacy state, SQLite, backend/frontend services, portproxy, Hyper-V firewall,
and forward-service state were not modified.

## Decision

- Firewall repair: **PASS (independently verified)**.
- Rotation inspection: **PASS READ-ONLY**.
- Forward activation: **BLOCKED** by expired approval and rotated source.
- Historical continuity: **UNPROVEN** and unchanged.

The first elevated helper invocation recorded a false-negative result after
Windows normalized the new interface binding from a GUID to the adapter name
`vEthernet (WSL (Hyper-V firewall))`. Its rollback attempt could not resolve
the retired old GUID, so the authorized new binding remained in effect. The
original result is retained for audit. A subsequent read-only verification
resolved the adapter name to `{20F93549-3239-4548-9B64-5B5980670EC1}`, proved
that every non-interface security field was unchanged, and repeated both TCP
path probes successfully.

## Firewall evidence

| Field | Before | After |
| --- | --- | --- |
| Interface | `{A1126C45-79ED-4355-A7D7-C18E73BA0CB0}` | `vEthernet (WSL (Hyper-V firewall))` → `{20F93549-3239-4548-9B64-5B5980670EC1}` |
| Enabled / direction / action | True / Inbound / Allow | unchanged |
| Profile | Any | unchanged |
| Protocol / local port | TCP / 16000 | unchanged |
| Local address | `172.19.240.1` | unchanged |
| Remote address | `172.19.254.115` | unchanged |
| Remote port / application / service | Any / Any / Any | unchanged |
| Portproxy | `172.19.240.1:16000 → 127.0.0.1:8000` | unchanged |
| Hyper-V rule | existing scoped rule | unchanged |

The protected backup remains under `%PROGRAMDATA%\CyberQalqon\backups`; its
exact runtime directory name is intentionally excluded from source control.

- SHA-256 manifest: `267ef690f644c5a5afafc1d71031b8ccbd100c51c6649f9d969301eefd2ac626`
- ACL snapshot SHA-256: `c9e45658793de1efe4a957382db48f57e532b81008d1950358fce19a78d80981`
- All ten manifest entries rehashed successfully.
- ACL inheritance is disabled; only LocalSystem, local Administrators, and the
  current Windows user have explicit FullControl.

Because no backend listener existed, the connectivity proof used a temporary
exclusive loopback TCP listener on port 8000 without changing service state.
Windows-to-portproxy TCP 16000 and WSL-to-gateway TCP 16000 both passed.
Backend HTTP and gateway HTTP failed because `127.0.0.1:8000` is not listening.
The WSL relay service is active, but its HTTP request returns no response while
the Windows upstream is absent. Frontend `127.0.0.1:5173` is also not listening;
it was not restarted because this approval explicitly prohibited deployment or
restart.

## Rotation and provenance

The old checkpoint is unchanged:

- generation: `e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a`
- state SHA-256: `2aae98473426a3ea7b49ee67021caf24cc6ec8fd413e3f0b20782422d42bc9ae`
- registered source: device/inode `2096/33582586`
- start offset: `688001817`
- durable cursor: `1143132931`
- records: 88,144; accepted: 46,054; duplicates: 0; filtered: 41,987;
  malformed: 103

At 00:00:01 +05 the forward service detected a source-identity change and
failed closed. Wazuh logged its daily rotation at 00:00:10, wrote the checksum
at 00:00:16, and completed gzip output at 00:00:46. The old source is now:

`/var/ossec/logs/archives/2026/Oct/ossec-archive-20.json.gz`

The built-in `verify_rotated_candidate` check proved its approved start-prefix
and processed record-chain through cursor `1143132931`. Its stored SHA-256 is
`2b98740f7214fab9cfff045469803f832d830da03cfb058769a5c8be604f026f`.
The decoded stream is 1,361,044,025 bytes and hashes to
`cca89f80ce2543c03d7ff19d49e46e2820c42ff0ad24dc056ec85101435295b1`,
exactly matching Wazuh's `.sum` file.

The preserved unread tail contains 42,019 complete records and 217,911,094
bytes. Its payload-free digest is
`336b9831635309e639eae31c071e210f5b4e80e68c52e1fdc3795d325205aae8`.
The last durable acknowledgement ends at cursor `1143132931`. Event, agent and
record-digest identifiers remain only in the ignored runtime diagnostic
artifact; no raw event content was written to source-controlled documentation.

The active archive is device/inode `2112/33582581` and is the same inode as
`ossec-archive-21.json`. WSL boot history shows the previous instance ended at
10:32:54 and the current instance began at 10:47:31, explaining the later
filesystem device change from 2096 to 2112. Device/inode identity alone cannot
bridge that remount; the cryptographic prefix and record-chain proof above
establishes the old candidate's provenance.

## Integrity and policy gates

- Legacy cursor/SHA remain `93438552` /
  `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`.
- Approval is expired at 2026-10-21 04:17:44.797758 +05:00; its SHA-256 remains
  `e521d7dff23df5029fb55d5f3201667edd372eaffcf0d29762a09e5fa219abb8`.
- Forward service is `inactive/dead`; no restart or activation occurred.
- SQLite is schema 17 with `quick_check=ok` and zero foreign-key violations.
- Passive validator did not complete: `agent_control -lc` timed out after its
  unchanged 30-second limit.
- `AI_ENABLED=false`; DET-001 through DET-009 remain
  `DISABLED_BY_POLICY/SHADOW_ONLY`.
- No schema migration, replay, retention change, browser UAT, commit, or push
  occurred.

## Separate approval gate required

Recovery must not be automatic. A future operator approval must explicitly
choose between two isolated operations:

1. Preserve and drain the 42,019-record old-generation tail by first creating
   a protected immutable copy of the gzip and `.sum`, rechecking gzip/SHA,
   start-prefix, record-chain, exact cursor, legacy inventory, and then
   authorizing the tested atomic `rebind-rotated` operation for that exact
   candidate. Because the checkpoint SHA changes during rebind and the old
   approval is expired, a new bounded manifest and a separate service-start
   approval are also required.
2. Enroll the active day-21 archive as a new generation only after selecting an
   explicit non-overlapping start boundary and proving how it joins the old
   tail. This requires its own generation ID, checkpoint, immutable backup,
   bounded approval manifest, expiry, and safe-stop conditions.

Neither operation may reset the cursor, discard the old tail, replay already
acknowledged bytes, or upgrade `historical_continuity=UNPROVEN`. The old gzip
is intact now, but remains exposed to normal Wazuh archive-retention cleanup;
a protected copy is therefore a mandatory gate before any recovery.
