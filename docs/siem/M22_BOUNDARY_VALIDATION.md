# M22 forward start-boundary validation

Status: **PASS for preparation; live start not approved**.

| Field | Value |
|---|---|
| Source | `/var/ossec/logs/archives/archives.json` |
| Device / inode | `2096 / 33582586` |
| Boundary | `688,001,817` |
| Prefix SHA-256 | `bd3d1ea52d7ae7ca42943e9710fcec50fd2121f3fb0666eaf50126429f26ccab` |
| Bytes around boundary | `0a 7b` — newline then JSON object start |
| Last excluded record | `2026-10-20T16:32:01.560+0500` |
| Partial tail at captured boundary | 0 bytes |

The staged generation ID is
`e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a`.
It is stable while the same inode appends because its identity is bound to
namespace, device, inode, start offset, and verified prefix—not mutable size or
ctime.

Forward delivery deliberately begins after the verified boundary. It does not
claim earlier delivery: the legacy unread suffix is `UNKNOWN / UNPROVEN`; days
15–19 contain 465,121 observed eligible archive records with unknown delivery;
day-20 bytes `[0, 688001817)` are excluded; source-offline intervals cannot be
replayed from archives.

Machine-readable evidence is in
`artifacts/runtime/m22-boundary-and-gap-manifest.json`; it contains no raw event
payloads.
