# CyberQalqon SIEM v0.9.1 performance diagnostics

Status: **PASS** for diagnosis; no durability or database-safety setting was
weakened.

## End-to-end bounded benchmark

Measured on 2026-10-11 with 75 application samples, 1,500 normalization
samples, and 9 WSL samples after shipper recovery:

| Measurement | p50 | p95 | State |
| --- | ---: | ---: | --- |
| Agent inventory | 72.045 ms | 117.080 ms | AVAILABLE |
| Agent detail | 159.988 ms | 270.086 ms | AVAILABLE |
| Operations overview | 63.882 ms | 88.215 ms | healthy |
| Windows normalization | 0.108 ms | 0.438 ms | about 9,259 events/s from p50 |
| Sender queue lookup | 548.033 ms | 829.810 ms | HEALTHY |
| Shipper lag calculation | 362.899 ms | 436.879 ms | HEALTHY |

The first run found shipper `DEGRADED`: WSL had restarted, but the Windows
backend existed only on 8000 while the documented shipper relay required the
WSL-gateway listener on 18000. The correct private WSL-gateway binding was
restored, the shipper caught up to zero lag, and the healthy figures above were
then recorded.

## Separation of costs

| Component | p50 | p95 |
| --- | ---: | ---: |
| Persistent SQLite `count(*)` | 0.0144 ms | 0.0173 ms |
| SQLite connect plus `count(*)` | 2.2142 ms | 7.2186 ms |
| JSON serialization, 50 items | 0.0206 ms | 0.0246 ms |
| Windows Python process startup | 106.892 ms | 150.319 ms |
| Windows-to-Ubuntu `wsl.exe` startup | 208.513 ms | 235.956 ms |
| WSL startup plus relay health request | 186.211 ms | 231.028 ms |

Raw SQLite and serialization are not the sender/shipper latency source. Sender
observation launches two WSL commands; shipper observation launches one WSL
command that also starts Python and checks the backend. Cross-process/WSL
startup therefore dominates. The current one-shot collector is acceptable for
bounded diagnostics, but a future optimization should batch manager, sender,
and shipper reads into one WSL invocation or use a long-lived local collector.
It must retain queue durability and fail-closed behavior.

The production frontend contains 22 files totaling 576,193 bytes (0.55 MiB).
Observed backend processes used about 56 and 66 MiB private memory for the
frontend/API and WSL-gateway API listeners respectively.
