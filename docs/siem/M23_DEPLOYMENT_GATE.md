# M23 live deployment gate

Engineering readiness: **PASS**. Production rollout: **BLOCKED pending explicit approval**.

Before deployment:

1. revalidate current approval, generation, source device/inode, checkpoint chain, and unchanged legacy SHA/cursor;
2. take verified database and forward-checkpoint backups without rewinding the active cursor;
3. snapshot the currently deployed backend and forward-service source for rollback;
4. confirm schema 17, 100,000 retention, single-event mode, AI/detection gates, and no required network change;
5. deploy only reviewed M23 source files;
6. restart components one at a time only where required;
7. validate health, authentication, ingestion contract, retention, checkpoint progress, latency, and zero delivery errors;
8. stop/rollback on source mismatch, cursor regression, repeated 5xx, protocol/rejection errors, SQLite integrity failure, or unexplained duplicates;
9. if the v3 checkpoint advances, never restore an older checkpoint blindly.

Approval required:

> CyberQalqon M23 optimized forward-ingestion va Operations improvements'ni cheklangan live rollout rejimida deploy qilishga ruxsat berasizmi?

Approval renewal, archive rotation/rebind, schema migration, historical replay, and batch activation are separate gates and are not included.
