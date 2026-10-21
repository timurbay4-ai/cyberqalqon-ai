# M20 archive provenance final assessment

Date: 2026-10-20
Scope: read-only production forensics plus isolated disposable tests
Final decision: **UNPROVEN_REQUIRES_EXPLICIT_RISK_DECISION**

No production recovery, replay, cursor edit, inode substitution, archive edit,
database write, service restart, schema change, batch activation, AI/detection
activation, browser UAT, Git commit, or Git push was performed.

## 1. Evidence inventory

### 1.1 Cryptographic content-integrity evidence

The available hashes establish content equality, but none of their containing
records is signed, externally timestamped, or held in an immutable store. They
are therefore cryptographic content bindings, not independently authenticated
chain-of-custody records.

| Evidence | Result | Limitation |
|---|---|---|
| Historical M17 preflight | While archive device/inode was `2096/33582396`, the root-only preflight recorded archive size `59,462,466` and `archive_prefix_sha256=9480a82b0f302b728355dbbb99ab1047c290afb21271f3709b9998a27ac734b9`. The decoded day-15 candidate prefix of exactly `59,462,466` bytes has the same SHA-256. | The preflight JSON is mode `0600 root:root` and predates rotation, but is unsigned and not immutably anchored. It does not hash the later exact cursor at `93,438,552`. |
| Day-15 Wazuh sidecar | Decoded content SHA-256 `6a1f029362bd2a12cfd2ff4f7a1020e220e68ea09e9f4ad6588f4d2b28ac05b7` matches the Wazuh `.sum`; gzip CRC/end-of-stream validation passed. | The sidecar is unsigned and does not preserve the deleted source inode. |
| Day-17 Wazuh sidecar | Decoded SHA-256 `fa5aba253cc6c833d2323803dac8e3e5e647e2e41722895bf36da86149753387` matches. | Same unsigned-sidecar limitation. |
| Day-18 Wazuh sidecar | Decoded SHA-256 `20da3941a6cb0c5b2b6300d0eafde85464db00713f162c3eca46ebe1a8cd51d1` matches. | Same unsigned-sidecar limitation. |
| Day-16 and day-19 hashes | Bounded streaming produced stable SHA-256 values for the files currently present. | No retained Wazuh sidecar or historical hash authenticates either file. |
| Backend identity export | A read-only export contains 100,000 retained canonical event fingerprints and 83,178 source IDs; artifact SHA-256 is `5195987ccbab17cb00eca33e68bade00c049bdda1d1e4b7033d0d18f6d4984cf`. | The live SQLite database is mutable and retention-capped; the export is reconciliation evidence, not an immutable acknowledgement log. |

The historical preflight itself is
`/var/lib/cyberqalqon-sender/state-backups/m17/event-shipper-v3-preflight-20261015T034057Z.json`,
with current SHA-256
`fda7ed648adcc8f5dc9236df86c0db3388b3987281c58c5069765b321d4294c7`.
The prefix comparison is recorded without raw payload in
`artifacts/runtime/m20-original-generation-prefix-binding.json`.

### 1.2 Independent corroborating evidence

- Root-only state backups establish the same day-15 inode and monotonic cursors
  `3,258,960 -> 36,366,272 -> 42,723,427 -> 44,749,863 -> 93,438,552`.
- The decoded candidate prefix ending at `93,438,552` contains exactly 17,183
  records. The durable ledger also accounts for exactly 17,183 processed
  records: 7,355 successful acknowledgements, 9,820 filtered and 8 malformed.
- The retained backend contains 7,355 exact canonical fingerprints from the
  cursor prefix. The final 1,000 eligible records before the cursor all match;
  the first 1,000 after it all do not match. The retained database's maximum
  occurred time is the last eligible record before the cursor.
- Wazuh/systemd journal timing supports the day ordering, the day-16 to day-17
  downtime, and the day-19 shutdown at the zero-tail boundary.
- Day-15 rotation timing is consistent: state last write at 23:59:05, first
  identity mismatch at 00:00:05, gzip creation at 00:00:17 and completion at
  00:00:35.

### 1.3 Circumstantial evidence

- Date-based filenames, birth/mtime data, first/last record timestamps, decoded
  lengths and newline boundaries are mutually consistent.
- All expected date-named files for days 15 through 19 exist.
- The candidate day-15 gzip is long enough to contain the cursor, and the
  cursor is exactly on a record boundary.

These properties support the sequence but do not independently prove identity
or completeness.

### 1.4 Unverifiable assumptions

- The unsigned historical preflight was not altered after capture.
- The original Wazuh archive remained append-only between the 59,462,466-byte
  historical hash and the 93,438,552-byte final cursor.
- Uncollected telemetry during WSL/Wazuh downtime did not exist elsewhere.
- The 305 NUL bytes at the end of day 19 contain no recoverable source event.
- Current hashes for the unsigned day-16/day-19 files represent their original
  post-rotation content.

## 2. Original inode provenance assessment

The earlier conclusion that there was no content binding at all is superseded
by the M17 preflight record. It names the original `2096/33582396` archive and
stores a SHA-256 over the archive's then-current 59,462,466 bytes. Recomputing
the SHA-256 over the first 59,462,466 **decoded** bytes of
`ossec-archive-15.json.gz` produces the exact same value. Compressed offsets
were never compared with uncompressed cursor offsets.

This is positive historical evidence that the candidate gzip contains the
original inode's byte stream through 59,462,466. It materially upgrades the
candidate from filename/timeline inference to a historically recorded content
match.

It is still not complete cryptographic provenance through the final cursor:

1. the historical prefix ends 33,976,086 bytes before cursor `93,438,552`;
2. no signed or immutable hash exists at the exact final cursor or final EOF;
3. the original uncompressed inode was deleted and later reused;
4. the preflight record itself is root-restricted but unsigned.

Assessment: **original-generation identity is strongly corroborated and
cryptographically bound for an early prefix, but final-cursor ancestry is not
fully authenticated**.

## 3. Checkpoint-to-content validation

All offsets below are in the decoded/uncompressed byte representation.

| Check | Result |
|---|---|
| Cursor | `93,438,552` |
| Candidate decoded-prefix SHA-256 at cursor | `fefc860f3dfce3ce35d446c147682d3d334ea7413434859e51ee7beb61a71739` |
| Record boundary | PASS; does not cross a record |
| Prefix inventory | 17,183 records: 7,356 eligible, 9,819 filtered, 8 invalid UTF-8, 0 invalid JSON/oversized/partial |
| Durable ledger inventory | 17,183 records: 7,355 acknowledged, 9,820 filtered, 8 malformed |
| Acknowledgement calculation | `7,007 accepted + 79 duplicate + 269 legacy successful = 7,355` |
| Backend exact fingerprints in prefix | 7,355 |
| Backend source-ID matches in prefix | 7,356, but source ID is not unique enough to be authoritative |
| Last 1,000 eligible records before cursor | 1,000 fingerprint matches and 1,000 source-ID matches |
| First 1,000 eligible records after cursor | 0 fingerprint matches and 0 source-ID matches |
| Eligible suffix after cursor | 85,771; zero retained backend matches |

The total record ledger reconciles exactly. There is one category discrepancy:
the current selector classifies one rule-less record at offsets
`1,753,430..1,757,160` as eligible, while the historical ledger is consistent
with treating one additional record as filtered. That record's source ID is
present in the backend but its canonical fingerprint is not. Because source
IDs repeat extensively, this is not proof of the same event. The discrepancy
does not move the byte boundary, but it prevents claiming perfect historical
selector equivalence.

The last eligible record before the cursor ends at `93,435,710` with timestamp
`2026-10-15T09:02:35.393+05:00`. The first eligible record at the cursor starts
at `93,438,552` with timestamp `2026-10-15T09:02:36.561+05:00`. These results,
the exact total ledger and the retained fingerprint split provide strong
independent support for the checkpoint. They are not a substitute for a signed
hash at the exact cursor.

## 4. Day-15 through day-19 continuity matrix

The scan was streaming and line-bounded at 1 MiB. Raw payloads were not written
to the report.

| Day | Form and integrity | Records: eligible / filtered / malformed | First -> last valid record | Boundary and continuity finding |
|---|---|---:|---|---|
| 15 | Gzip; stored `29,762,778` bytes, SHA-256 `8c379d3e4352407f3a052f58301bfa910dbb311e778f2632bc9a36c93bfd1cb1`; decoded `1,167,573,927` bytes; Wazuh sum PASS | `93,127 / 116,951 / 50` | `2026-10-15 08:02:25.816` -> `2026-10-16 00:00:00.573` | Original prefix binding found; final-cursor ancestry remains unsigned. Day15->16 event-ID gap `0.197522311 s`. |
| 16 | Plain JSON; `933,199,640` bytes; current SHA-256 `69500d816651dd382b7ba56bd79bff0a57814c8ce9b3383bd98ae7e12edf83d4`; no Wazuh sidecar | `91,808 / 91,713 / 120` | `2026-10-16 00:00:01.689` -> `2026-10-16 23:31:10.937` | File exists and parses. Day16->17 event-ID gap `39,354.364456469 s`; journal shows the intervening WSL boot and Wazuh start at 10:26–10:27 on day 17. |
| 17 | Gzip; stored `31,528,939` bytes; decoded `1,072,217,120`; Wazuh sum PASS | `109,133 / 105,206 / 66` | `2026-10-17 10:27:05.456` -> `2026-10-18 00:00:00.713` | Start aligns with Wazuh restart. Day17->18 event-ID gap `0.273145636 s`. |
| 18 | Gzip; stored `39,304,254` bytes; decoded `1,428,500,847`; Wazuh sum PASS | `142,880 / 135,421 / 164` | `2026-10-18 00:00:01.069` -> `2026-10-19 00:00:01.106` | Day18->19 event IDs regress `0.985444856 s`, while timestamps still move forward about 0.55 s; no exact cross-generation fingerprint duplicate was found. |
| 19 | Plain JSON; `163,373,056` bytes; current SHA-256 `920932131e089c7f7acd40a2de9e74186a70b6a09d69aad1f92ae03b4c8a972d`; no Wazuh sidecar | `28,173 / 19,194 / 1` | `2026-10-19 00:00:01.656` -> `2026-10-19 22:24:33.269` | One terminal 305-byte NUL segment follows the last valid newline. Manager stopped at 22:24:35; file mtime is the same second. |

Aggregate inventory: 934,007 physical record segments, 933,606 valid JSON
objects, 465,121 eligible, 468,485 filtered, 395 invalid UTF-8, 5 invalid
JSON and 1 partial terminal segment.

No day filename is missing and no exact fingerprint or source-ID duplicate was
found across generation boundaries. There are 109 exact fingerprint repeats
within individual generations. Source ID alone is unsuitable as a unique key:
507,429 within-generation repeats were observed. Exact canonical fingerprints
are the authoritative duplicate signal here.

The archive files are ordered consistently, but telemetry continuity is not
gap-free. The day16->17 gap corresponds to WSL/Wazuh downtime. Day 19 also has
a roughly 9.57-hour internal event-ID gap; journal evidence shows the manager
was stopped at 01:38 and restarted at 11:12. These are collection-availability
gaps, not missing date-named files, and cannot be recovered from the archives.

## 5. Incomplete day-19 record analysis

The terminal region is precisely:

- start offset: `163,372,751`;
- end offset: `163,373,056`;
- length: `305` bytes;
- SHA-256: `c25637e3fff1c6cb348c91ab797b1312c55107b3482544bd41d9119f707e84bb`;
- content: 305 NUL bytes, no newline, no JSON opening object, no `id` or
  `timestamp` key;
- preceding complete record: offsets `163,372,130..163,372,751`, timestamp
  `2026-10-19T22:24:33.269+05:00`;
- day-20 first record starts a new JSON object; appending it to the NUL tail is
  still invalid JSON.

The bytes are fully allocated file content rather than a recoverable JSON
fragment. The file mtime `22:24:35` coincides with the recorded Wazuh manager
stop at `22:24:35`, strongly supporting a collection/shutdown write artifact.
The exact writer-level cause cannot be proven retrospectively.

This is not a parser boundary spanning day 19 and day 20. It must not be
silently repaired, synthesized, or counted as delivered. A future approved
replay may inventory it as one terminal malformed/partial artifact and stop at
the verified last complete record. Because no event identity or payload is
recoverable from the NUL region, lossless source-event recovery cannot be
claimed.

## 6. Identified missing evidence

1. A signed, immutable or externally timestamped hash of inode `33582396` at
   cursor `93,438,552` or at final pre-rotation EOF.
2. A retained offset-to-fingerprint acknowledgement log covering every record;
   the durable state has counters, not per-record provenance.
3. Wazuh checksum sidecars or earlier trusted hashes for day 16 and day 19.
4. Independent telemetry that could reconstruct events while WSL/Wazuh was
   stopped.
5. Backend reconciliation for days 16–19; the fail-closed shipper never
   ingested them and the database is retention-capped.
6. A deployed, reviewed operator workflow that imports the historical
   checkpoint, replays immutable generations in order and atomically cuts over
   to a snapshotted active generation without skipping concurrent writes.
7. An immutable proof that the one selector-classification discrepancy is only
   historical policy drift and not content divergence.

Missing historical provenance cannot be recreated by repeating scans. More
hashes calculated today would only identify today's files.

## 7. Duplicate and loss risk assessment

- **Wrong checkpoint risk:** greatly reduced by the historical prefix hash,
  exact 17,183-record ledger and backend fingerprint split, but not eliminated
  because there is no authenticated exact-cursor hash.
- **Duplicate risk:** 109 exact repeats already exist within the archives.
  Backend canonical fingerprint idempotency can acknowledge repeats, but the
  100,000-row retention cap means old idempotency rows are not a permanent
  exactly-once ledger.
- **Source-ID risk:** source IDs repeat too often to drive reconciliation or
  deduplication alone.
- **Selector drift risk:** one cursor-prefix record changes the eligible versus
  filtered allocation under the current selector. A recovery must freeze and
  document the exact selector version used.
- **Gap risk:** the WSL/Wazuh downtime intervals are genuine collection gaps.
  Replaying preserved files cannot reconstruct uncollected events.
- **Day-19 risk:** the 305 NUL bytes cannot be delivered or reconstructed as an
  event and must remain an explicit malformed audit item.
- **Cutover risk:** the active day-20 archive continues growing. Catch-up
  without an immutable snapshot and atomic handoff can create another skip or
  overlap.
- **Retention risk:** large replay can evict unrelated retained events unless
  its effect is separately measured and approved.

Consequently neither lossless recovery nor production exactly-once recovery is
demonstrated.

## 8. Newly executed tests and analyses

Only results executed for this final assessment are listed here:

- `m20_archive_continuity_forensics.py --self-test`: **PASS**. The disposable
  case validates a positive record boundary, prefix/suffix reconciliation,
  cross-generation duplicate detection, invalid JSON, invalid UTF-8 and a
  terminal partial record.
- `wazuh/tests/test_archive_recovery.py`: **14/14 PASS in 0.86 s**. These
  isolated tests cover bounded checkpoint validation, digest mutation,
  pause/restart/idempotency, duplicate acknowledgement, malformed/partial
  handling and safe failure paths.
- Production day15–19 read-only streaming scan: **PASS** across 934,007 record
  segments; no raw payload was written to artifacts.
- Exact cursor-prefix read-only scan: **PASS** across 17,183 record segments.

The prior 59/59, 163/163, 279/279 and 1/1 results remain historical baseline
evidence and were not reported as newly executed here.

New payload-free artifacts:

| Artifact | SHA-256 |
|---|---|
| `artifacts/runtime/m20-archive-continuity-analysis.json` | `c66992c19967ff12337327acc2d0cbcd2cd5066e0f07f3cfb1cbd3ff53d48858` |
| `artifacts/runtime/m20-checkpoint-prefix-analysis.json` | `634af670cd7aa47e8f3858de16269af918c9d8cbc16933e5139c003985c53c8d` |
| `artifacts/runtime/m20-original-generation-prefix-binding.json` | `eb5f260421dfa979c5d131f563076e3920547458344e71d367f2abb187402e6f` |
| `artifacts/runtime/m20-backend-wazuh-identity-export.tsv.gz` | `5195987ccbab17cb00eca33e68bade00c049bdda1d1e4b7033d0d18f6d4984cf` |
| `artifacts/runtime/m20_archive_continuity_forensics.py` | `787d755a09a0734fbe268e967805c5c3f16ca62ee8ce9a5acc7c0b8d01134477` |

## 9. Safe recovery options and prerequisites

No option was executed.

### Option A — continuation from the original checkpoint

Technically plausible, but **not presently lossless-proven**. It requires a
separate explicit risk decision accepting the unsigned interval from the
historical 59,462,466-byte prefix hash to cursor `93,438,552` and the known
collection gaps.

Prerequisites:

1. approve the residual provenance/gap risk explicitly;
2. gracefully stop only the fail-closed shipper and capture a new immutable
   state checksum without changing the cursor;
3. copy/snapshot every required generation and active boundary, then verify all
   digests before any delivery;
4. deploy and review an operator-gated checkpoint-import/cutover mechanism;
5. freeze the exact selector and canonical fingerprint implementation;
6. replay the day-15 suffix, then days 16–19, with a separate durable replay
   state, bounded rate and explicit malformed audit;
7. treat the day-19 NUL tail as non-delivered evidence;
8. atomically cut over to a frozen active-generation boundary while preserving
   every newer acknowledgement.

### Option B — controlled identity reconciliation

Possible only as a **risk-acceptance proposal**, not exactly-once recovery.
Build a durable reconciliation catalog from immutable archive fingerprints and
the retained backend export, dry-run it outside production, then submit only
unmatched eligible fingerprints in ordered bounded batches. Preserve 200
duplicate versus 201 insertion accounting separately.

This option still cannot prove records evicted by retention, restore uncollected
events, authenticate day16/day19 origin, or recover the NUL tail. It also needs
a separately approved retention-impact plan.

### Option C — remain fail-closed

This is the only zero-new-risk production choice now. It preserves the current
cursor and all archive evidence while the operator decides whether to accept
the documented residual risks or require stronger external evidence.

## 10. Exact remaining blockers

1. No authenticated final hash binds original inode `33582396` to the exact
   `93,438,552` cursor; only the earlier 59,462,466-byte prefix is historically
   hash-bound.
2. Day16/day19 origin integrity is not backed by Wazuh sidecars or immutable
   historical hashes.
3. Manager downtime created source-collection gaps that archive replay cannot
   fill.
4. The day-19 terminal NUL artifact is unrecoverable as an event.
5. One prefix record has a current-selector versus historical-ledger category
   discrepancy.
6. Retention-capped backend identities do not form a permanent exactly-once
   ledger.
7. The hardened recovery implementation remains local and undeployed; no
   reviewed active-generation cutover command is available in production.
8. The current service process is active but operationally fail-closed. Any
   stop, package deployment, registration, replay or cutover remains a separate
   live operation requiring explicit approval.

## 11. Explicit production mutation verification

Post-analysis verification found:

- durable state SHA-256 remains
  `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`;
- cursor remains `93,438,552`, device/inode remains `2096/33582396`;
- shipper remains `active/running`, `NRestarts=0`, and has not advanced state;
- active archive remains device/inode `2096/33582586`; its size changed only
  through normal Wazuh collection while this read-only investigation ran;
- backend and frontend returned HTTP 200; WSL gateway relay returned HTTP 200;
- Git HEAD remains `f6a59a923cc58cb768c1e4dd748bb529e5c01a43` and the pre-existing dirty tree
  remains uncommitted;
- all SQLite forensic access used `mode=ro` plus `PRAGMA query_only=ON`; no
  synthetic event or database mutation was performed; the final read-only
  query observed schema 17, 100,000 events, 40 alerts and a 0-byte WAL;
- schema remains 17, batch ingestion remains disabled, `AI_ENABLED=false`, and
  DET-001–DET-009 remain `DISABLED_BY_POLICY / SHADOW_ONLY`;
- browser UAT, schema 18, historical replay, cursor reset, archive cleanup,
  commit and push were not performed.

## Yakuniy xulosa

- **Isbotlangan:** original inode'ning dastlabki 59,462,466 bayti day-15 gzip
  decoded streamiga tarixiy SHA-256 bilan mos; final cursor record boundaryda;
  17,183-record ledger va 7,355 backend fingerprint acknowledgement bilan
  kuchli reconciliation mavjud; barcha day15–19 fayllari topildi va streaming
  inventarizatsiya qilindi.
- **Isbotlanmagan:** exact final-cursor uchun signed/immutable hash, day16/day19
  tarixiy origin autentikatsiyasi va uzluksiz source telemetry.
- **Gaplar:** fayl nomi bo'yicha generation yo'qolmagan, lekin WSL/Wazuh o'chiq
  davrlarida real collection gaplari bor.
- **305 bayt tail:** bu 305 ta NUL bayt; JSON event emas, day20 bilan ulanmaydi,
  tiklab bo'lmaydi. Faqat malformed evidence sifatida audit qilinishi mumkin.
- **Lossless recovery:** qo'llab-quvvatlanmaydi; preserved valid archive
  recordlarini risk bilan nazoratli tiklash texnik jihatdan mumkin.
- **Keyingi qaror:** fail-closed holatda qolish yoki hujjatlashtirilgan
  provenance/gap/retention risklarini alohida va aniq qabul qilib, bounded
  recovery uchun yangi live approval berish kerak.

Final decision: **UNPROVEN_REQUIRES_EXPLICIT_RISK_DECISION**
