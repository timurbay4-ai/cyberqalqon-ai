# M22 validation report

| Suite | Result |
|---|---:|
| Backend | 281/281 PASS |
| Wazuh sender/shipper | 208/208 PASS |
| M21 + M22 focused | 45/45 PASS |
| Frontend | 120/120 PASS |
| Deployment/validator | 27/27 PASS |
| Operations API focused | 14/14 PASS |
| TypeScript / production build | PASS / PASS |
| `git diff --check` | PASS; line-ending notices only |
| systemd unit static verification | PASS for unit; distro alias warnings only |
| Disposable 100k retention | PASS |

`artifacts/runtime/m22-passive-validation.json` reports 11 PASS, 1 WARNING
(retention at 100,000), 1 FAIL (legacy inode mismatch), and 1
`DEFERRED_BY_USER` (browser UAT). Overall remains **FAIL**; thresholds were not
relaxed and the blocker was not hidden.

Forward engine, guarded CLI, approval validation, checkpoint lock, audit,
systemd template, observability API/UI, and disposable acceptance are prepared.
Legacy state remains unchanged. No live forward event, synthetic live DB event,
historical replay, schema migration, detection/AI activation, firewall change,
browser UAT, commit, or push occurred. Deployment remains blocked pending the
separate explicit approval.

## Machine-readable evidence

- Boundary/gap manifest SHA-256:
  `3A2CC73C51A09F0E6D12F7F619432CD9AD37105F4B8074CB588F7581A64D3353`.
- Disposable 100k retention result SHA-256:
  `7C0AE511FD92862E94C518E0667DC54EB7A4C65CD259C320416BB38047A28AC5`.
- Passive validator result SHA-256:
  `178B814C2CD7B099C039B82B4F9E234717EC85221839BF727647F7172D53D618`.
- Staged forward checkpoint SHA-256:
  `17AABE42098EAD5C22B404BACC7125E0ED36278221B30F722F450E4C36FE5295`.

The final read-only runtime audit still found HTTP 200 for backend, frontend,
WSL relay and Windows gateway. Wazuh manager, sender and the legacy shipper
were active; the forward shipper was inactive and its live state directory was
absent. The legacy state SHA-256 remained
`ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`.
The live database remained schema 17 with 100,000 events, `quick_check=ok`,
zero foreign-key violations and a zero-byte WAL.

Two disposable synthetic test directories remain outside the repository
because host policy rejected their recursive removal. They are not live data,
archives or protected evidence, and each contains 293,048,320 bytes:

- `%TEMP%\cyberqalqon-m22-retention-<random-id>-1`
- `%TEMP%\cyberqalqon-m22-retention-<random-id>-2`

The separately approved conditional live deployment and bounded acceptance are
recorded in `M22_LIVE_FORWARD_INGESTION_VALIDATION.md` and
`artifacts/runtime/m22-live-forward-validation.json`.
