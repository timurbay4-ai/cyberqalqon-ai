# M22 live deployment gate

Current decision: **BLOCKED PENDING SEPARATE EXPLICIT APPROVAL**.

- Generation: `e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a`
- Source/device/inode: `/var/ossec/logs/archives/archives.json`, `2096/33582586`
- Start offset: `688,001,817`
- Prefix SHA-256: `bd3d1ea52d7ae7ca42943e9710fcec50fd2121f3fb0666eaf50126429f26ccab`
- Planned state: `/var/lib/cyberqalqon-forward/m22-forward/e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a.json`
- Legacy SHA/cursor: `ef116265…60dde` / `93,438,552`

Before live work, recheck health, source identity/prefix, legacy hash/cursor,
schema/integrity, RAM/disk, and retention. Any change invalidates the proposal.

## Approved-phase command plan

This is a reviewed plan, not authorization to run now:

```bash
install -d -o wazuh -g wazuh -m 0750 /var/lib/cyberqalqon-forward/m22-forward
install -d -o wazuh -g wazuh -m 0750 /var/log/cyberqalqon
/opt/cyberqalqon-sender/.venv/bin/cyberqalqon-sender forward prepare \
  --source /var/ossec/logs/archives/archives.json \
  --state-directory /var/lib/cyberqalqon-forward \
  --namespace m22-forward --start-offset 688001817 \
  --legacy-state /var/lib/cyberqalqon-sender/event-shipper-state.json
/opt/cyberqalqon-sender/.venv/bin/cyberqalqon-sender forward validate --deep \
  --state /var/lib/cyberqalqon-forward/m22-forward/e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a.json
# Only after separate approval and exact root-owned approval/env/unit setup:
systemctl start cyberqalqon-forward-ingestion.service
```

The manifest is intentionally manual: source code cannot manufacture user
approval. It must be root-owned, expire within 24 hours, bind the exact live
state and deny replay/legacy mutation. Stop by stopping the unit, preserving
state/audit, and moving approval to a root-only evidence backup. Never restore
an initial state after an acknowledgement.

Required question:

> Yangi archive generation uchun independent forward ingestion'ni belgilangan boundary'dan live ishga tushirishga, eski tarixiy uzluksizlik UNPROVEN bo‘lib qolishini va eski loglar alohida recovery jarayoniga qoldirilishini tushungan holda ruxsat berasizmi?
