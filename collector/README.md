# M35 Go JSONL collector — disposable synthetic scope

This standard-library-only module implements the previously blocked collector
vertical slice. It accepts **only explicit synthetic lab roots and literal loopback
destinations**. It installs no service and does not enroll production sensors.
See `docs/siem/M35_GO_IMPLEMENTATION.md` and `M35_GO_RACE_RESULTS.md` for historical
implementation and executed Windows race evidence. M36 reconstruction and current
validation are recorded in `docs/release/M36_BUILD_REPRODUCIBILITY.md` and
`M36_MULTILANGUAGE_VALIDATION.md`.

## Build and isolated acceptance

From the repository root in PowerShell:

```powershell
$env:Path = 'C:\Program Files\Go\bin;' + $env:Path
$env:GOTOOLCHAIN = 'local'
$env:GOTELEMETRY = 'off'
$env:GOPROXY = 'off'
$env:GOMAXPROCS = '2'
go -C collector test -p 1 ./...
go -C collector vet ./...
$env:CGO_ENABLED = '0' # Ordinary binary needs no C compiler.
go -C collector build -p 1 -trimpath -buildvcs=false -o ../artifacts/runtime/m35-go-collector.exe ./cmd/cq-collector
```

`backend/tests/test_m35_go_collector.py` uses the Python interpreter's SQLite;
the optional M32 candidate bootstrap is an explicit separate environment. The fixture builds a real executable,
creates new private temporary roots, starts an owned FastAPI TCP listener on an
ephemeral loopback port, uses random local credentials, and shuts down that
listener. No existing backend/DB/collection configuration is accepted by the
fixture. `scripts/m35_go_synthetic.py --output <new-report.json>` runs the owned
functional scenario and saves sanitized actual responses. It is a functional test,
not the deferred M33 performance acceptance.

The test helper discovers Go on the process PATH or through `CYBERQALQON_GO`;
no workstation-specific path is
required. `cq-collector --help` and subcommand `--help` return static JSON usage
without opening a root, config, checkpoint or credential. Windows/amd64 is locally
executed; Linux CI is prepared but remote execution and other-platform runtime
acceptance remain unverified. Race tests need cgo and a supported C compiler,
supplied separately through process-only CC/PATH. The compiler and its archive
are excluded from the source release.

## CLI and configuration

`init-lab --root <new-empty-directory>` creates the protected lab marker and an
explicit random lab ID. An empty root argument or nonempty directory is rejected.
The returned lab ID is configuration identity, not a credential. Source JSONL,
ingest-key file, distinct source-key file, optional CA file and state directory
must all remain inside that root. Each key file contains 32–512 printable ASCII
characters. Never pass a key value as a CLI argument or put it in source control.
Use only the synthetic application constructor's scoped source registration.

The JSON configuration has these required fields:

```json
{
  "scope": "SYNTHETIC_DISPOSABLE_ONLY",
  "lab_id": "<ID returned by init-lab>",
  "lab_root": "<absolute private synthetic root>",
  "source": "<root>/input.jsonl",
  "state_dir": "<root>/spool",
  "source_id": "synthetic-zeek",
  "source_type": "ZEEK_JSON",
  "collector_id": "synthetic-collector",
  "source_generation": "synthetic-generation-1",
  "stream": "dns",
  "endpoint": "https://127.0.0.1:18443/api/v1/collection/events",
  "ingest_key_file": "<root>/ingest.key",
  "source_key_file": "<root>/source.key",
  "ca_file": "<root>/synthetic-ca.pem"
}
```

Paths are illustrative placeholders; `lab_root` and its children must be actual
absolute native paths. A Zeek file has one explicit stream: conn/dns/http/ssl.
Suricata uses `source_type=SURICATA_EVE` and a fixed stream or `stream=auto`, with
alert/dns/http/tls/flow events. Only a private disposable loopback HTTP test may
set `allow_loopback_http=true`. HTTPS otherwise remains mandatory; certificate
verification is never disabled, environment proxies are ignored and redirects
are never followed.

Commands after creating the synthetic source/config/key files:

```text
cq-collector init --config <config.json>
cq-collector spool --config <config.json> --max-steps 8
cq-collector status --config <config.json>
cq-collector run --config <config.json> --once --max-steps 256
```

`init` refuses an existing checkpoint. `spool` only durably queues complete lines.
`run` drains queued records in order before reading more; `--once` returns at EOF,
partial input or backpressure. Without `--once`, bounded polling is cancellable by
Ctrl+C. Every invocation still has a finite 1–4096 action budget. A new invocation
may retry the unchanged head after an external transient failure; it cannot discard
or skip it. Configuration/key changes break the immutable binding and require
explicit reviewed reconciliation rather than a flag override.

`status` reads one atomic published snapshot without taking the writer lease,
changing ACLs, reconciling `.next`, altering an in-flight flag or sending HTTP.
Its `state_body_sha256` is the body checksum, **not** the complete file checksum.
A source mismatch returns a static error plus the existing checkpoint observation
when available. Status snapshots are local observations, not server/global counts.

## Source, spool and ACK invariants

- Windows file identity is volume serial plus file index; POSIX code uses device
  plus inode. Path, source registration, generation and configuration are bound.
  Regular files only; symlinks/reparse paths, hardlink aliases, UNC roots and NTFS
  alternate streams are rejected. Renaming/replacing/truncating the active source
  or changing a consumed prefix fails closed. No generation is automatically rebound.
- Read offset advances only with the complete immutable envelope in a flushed
  checkpoint. A partial final line advances nothing. A malformed/oversized record
  blocks at its original boundary, increments its fingerprint's malformed count
  once, and keeps earlier queued records and the original source bytes. There is
  no oldest-first eviction, automatic quarantine deletion or silent filtering.
- A single checksummed JSON checkpoint contains the ordered spool, read/ACK offsets,
  source witness and counters. `checkpoint.next` is uncommitted until flushed and
  atomically published. A stale candidate cannot override a valid published state.
  Corrupt published state requires reconciliation; a backup is never auto-restored.
- An exclusive OS lease allows one writer. Each publication checks the preceding
  checksum/sequence, writes and syncs the candidate, closes it, then publishes it.
  Windows uses `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`; POSIX syncs the containing
  directory after rename. Windows hard power-loss/filesystem/controller guarantees
  have not been certified by these process-crash tests.
- Stable original record ID uses start/end offsets and a raw-line digest. Delivery
  and checkpoint IDs remain identical across retries/restarts. Equal content at
  different offsets is a different source record. Generation uniqueness is an
  operator registration responsibility; no global content deduplication is claimed.
- The HTTP client sends both ingest and source-scoped credentials and the existing
  `cq-collection-v1` envelope. JSON fingerprinting matches Python's sorted UTF-8
  profile (not RFC8785). Bounded complexity, duplicate keys, invalid Unicode,
  non-finite numbers and control characters are rejected before submission.
- An ACK must bind committed=true, canonical event ID, original record ID, delivery
  ID, checkpoint ID and payload fingerprint. Only 201/new or 200/duplicate, with
  consistent boolean/status fields, permits an atomic queue pop and ACK advancement.
  A socket success by itself never grants progress.
- In-flight state commits before the HTTP attempt. Restart after an uncertain
  outcome retries the same source identity. Durable counters record locally observed
  insert/duplicate ACKs and uncertainty; they cannot recover an unseen 201 or count
  global unique storage. Idempotency relies on the server retaining the event;
  retention expiry/protected evidence remain separate unchanged server policies.

## Budgets and failure handling

| Budget | Default | Allowed range |
|---|---:|---:|
| Complete JSONL line bytes, including terminator | 65,536 | 128–65,536 |
| Queued records | 8 | 1–32 |
| Encoded queued-record bytes | 1,048,576 | 4,096–2,097,152 |
| Synthetic source file bytes | 4,194,304 | 1–16,777,216 |
| HTTP timeout | 1,000 ms | 100–5,000 ms |
| Attempts per delivery action | 3 | 1–5 |
| Initial retry delay | 100 ms | 10–1,000 ms |

State publication has at most the published file and one candidate, each capped
at `max_spool_bytes + 262144` bytes; the tighter body limit is `+131072`. There is
one fixed-size lock file and a small marker/config/key set. These are logical
file-length limits, not an NTFS allocation quota or a hard process RSS/CPU limit.
The owned input file is capped separately. Prefix rehashing is intentionally
conservative within that small finite input budget; high-throughput live tailing
is not accepted by this slice. One worker/HTTP connection; no adaptive/batch mode.

401/403, record conflict, permanent input rejection, bad ACK and TLS validation
failure stop delivery while retaining the head. 429/5xx and unknown network
outcomes use bounded cancellable backoff (at most 5 seconds between attempts).
Exhaustion returns a static error and retained work. No response body, source text,
credential or full endpoint URL is logged by the executable.

`--crash-at` accepts only the named synthetic failure points in the CLI. Test
exit code 27 means an intentional hard exit; ordinary failures return 2. There is
no service installer, replay, reset, restore, skip, discard or rebind command.

Production remains NOT_AUTHORIZED. Race instrumentation needs a supported C
compiler/cgo environment; Windows Go execution and ordinary concurrent tests do
not substitute for a successful `go test -race`. Linux runtime acceptance and
power-cut certification remain future work. Historical continuity stays UNPROVEN.
