# M22 retention safety

Live policy remains schema 17, 30 days, maximum 100,000 events. No live row or
policy was changed.

The disposable schema-17 acceptance created 100,000 synthetic normalized
events, protected three oldest events through a case, then performed 101 unique
and 100 duplicate single-event repository operations:

| Check | Result |
|---|---:|
| Before / after rows | 100,000 / 100,000 |
| Deleted ordinary rows | 101 cumulative |
| Protected case events | 3 expected / 3 preserved |
| Unique / duplicate acknowledgements | 101 / 100 |
| `quick_check` / FK errors | `ok` / 0 |
| WAL at measurement | 4,532,032 bytes |

Result: **PASS**. Evidence:
`artifacts/runtime/m22-retention-100k-validation.json`.

This proves the current deletion/protection contract in a disposable schema,
not future live resource headroom. At the live cap, each unique forward insert
may delete an old unprotected event. Protected rows can cause an honest
over-limit state and must not be force-deleted to maintain the numeric cap.
