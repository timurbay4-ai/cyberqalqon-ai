# M15 Windows/WSL relay diagnostics

## Root cause

The failure is compound rather than a single stale address:

1. The backend listens only on Windows loopback TCP 8000, which is the intended
   safe binding.
2. Ubuntu listens locally on TCP 18000 and dynamically resolves the current WSL
   default gateway, but forwards to that gateway on TCP 18000.
3. Windows has no listener or port proxy on TCP 18000. Both IPv4 and IPv6 report
   18000 inside the excluded range 18008-18107 boundary set (the adjacent range
   17908-18007 also makes choosing a nearby value unsafe).
4. A bounded diagnostic listener bound specifically to the WSL adapter address
   on otherwise-free TCP 16000, yet the WSL connection still timed out.
5. The WSL Hyper-V firewall VM setting has default inbound `Block`; this explains
   why merely choosing a non-excluded port is insufficient.

The current gateway address was `172.19.240.1` and the distro address was
`172.19.254.115` during inspection. These are observations, not constants. The
relay already discovers the gateway dynamically, so the destination port and
the narrowly scoped inbound path are the required changes.

## Selected design

Candidate TCP 16000 was outside the observed IPv4 and IPv6 exclusions and had no
listener after the diagnostic probe. The final preflight must prove both facts
again. Windows remains bound to `127.0.0.1:8000`; an exact adapter-address port
proxy forwards TCP 16000 to loopback 8000. A Hyper-V rule allows inbound TCP
16000 only for the WSL VM. The WSL-facing application endpoint remains
`127.0.0.1:18000`, avoiding sender, shipper and secret changes.

Affected live state: Windows port proxy, one scoped Hyper-V firewall rule,
Ubuntu `/usr/local/libexec/cyberqalqon-backend-relay`, and the backend-relay
systemd service. Administrator PowerShell and Ubuntu root are required. No broad
interface binding, firewall disablement, excluded-range mutation or backend
public exposure is permitted.

## Validation and rollback

Validation requires: exact Windows listener inventory; WSL TCP/HTTP success;
loopback backend HTTP 200; relay HTTP 200; sender queue/dead-letter unchanged;
cursor identity unchanged before delivery; then bounded cursor progress and
database ingestion with duplicate-safe acknowledgments.

On any failure, remove only the named rule and exact port proxy, restore the
relay backup, restart only the relay and verify backend loopback health. Cursor,
queue, archive and database data must not be edited.

## Live result

Live state is **PASS** as of 2026-10-14:

- exact port proxy: `172.19.240.1:16000 -> 127.0.0.1:8000`;
- backend remains loopback-only on `127.0.0.1:8000`;
- Ubuntu relay remains loopback-only on `127.0.0.1:18000` and targets gateway
  TCP 16000;
- Hyper-V rule `CyberQalqon-M15-WSL-Relay-TCP16000` is exact to the WSL VM,
  gateway, port and distro address;
- host rule `CyberQalqon-M15-WSL-Relay-TCP16000-Host` is exact to the current
  WSL interface, gateway, port and distro address;
- WSL direct gateway health and local relay health both return HTTP 200.

Protected backups remain in the ACL-restricted CyberQalqon backup directories
under `%PROGRAMDATA%\CyberQalqon\backups` and the manager's root-only backup
area. Exact runtime paths are intentionally excluded from source control.
After a host/WSL restart, the Windows port-proxy listener had to be rebound and
the host firewall rule's stale adapter GUID had to be replaced with the current
WSL adapter. Both repairs preserved the exact approved scope and left shipper
state untouched.
