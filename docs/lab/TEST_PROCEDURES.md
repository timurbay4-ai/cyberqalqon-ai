# CyberQalqon Local Lab Test Procedures

## Safety prerequisites

1. Run only from the authorized Windows host.
2. Confirm the repository path and inspect `git status` before changes.
3. Confirm the Kali target is loopback; do not substitute a LAN or public address.
4. Confirm Ubuntu Wazuh Manager and Kali Agent are active.
5. Never place credentials in command arguments, reports, or Git.

## Automated validator

Passive health checks:

```powershell
backend\.venv\Scripts\python.exe scripts\validate_local_lab.py
```

Bounded active checks:

```powershell
backend\.venv\Scripts\python.exe scripts\validate_local_lab.py --active --wait-seconds 45
```

The script refuses non-loopback targets. Active mode runs one 8-port TCP connect scan, a 12-entry Gobuster wordlist, and one harmless `/.env` request. It waits for new CyberQalqon records for rules `100101`, `100111`, and `100120`. The JSON result is written to the Git-ignored `artifacts/lab-validation/latest.json`.

## Manual network test

```bash
nmap -sT -Pn -p22,23,25,53,80,110,443,445 127.0.0.1
```

Expected result: Wazuh rule `100111`, level 10, Agent `cyberqalqon-test-web`, MITRE `T1046`, and one CyberQalqon database record.

Single-port false-positive control:

```bash
nmap -sT -Pn -p23 127.0.0.1
```

Expected result: level-1 seed telemetry only; no new `100111`.

Slow-scan control:

```bash
timeout 55s nmap -sT -Pn --scan-delay 7s -p22,23,25,53,110,443 127.0.0.1
```

Expected result: six seed events outside the 30-second correlation window; no new `100111`.

## Manual web tests

Directory enumeration regression:

```bash
timeout 20s gobuster dir --url http://127.0.0.1/ \
  --wordlist /root/cyberqalqon-gobuster-lab-wordlist.txt \
  --threads 1 --timeout 2s --no-error --no-progress
```

Sensitive-path test:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1/.env
```

Expected results are rules `100101` and `100120`, respectively. A single `curl http://127.0.0.1/` request is the benign control.

## Realtime FIM test

Install the initial fixture into `/etc/cyberqalqon-lab/validation.conf`, wait for `100130`, replace it with the modified fixture, and wait for `100131`. Remove only that exact test file afterward. Do not modify `/etc/passwd`, SSH configuration, or administrator files.

## Synthetic SSH test

Feed eight clearly labeled invalid-user fixture lines from `127.0.0.1` into `wazuh-logtest`. Expected rules are `5710` for individual attempts and `5712` on attempt eight. Do not enable an externally reachable password-based SSH service for this test.

## Configuration deployment and rollback

Before applying a repository patch or installing a file:

1. copy the target beside itself with a unique `pre-codex` or `pre-cq-*` suffix;
2. use `patch --dry-run` where applicable;
3. validate with `nft -c`, `systemd-analyze verify`, `wazuh-analysisd -t`, or `wazuh-syscheckd -t`;
4. restart only the affected service;
5. confirm health and agent state.

If validation fails, restore the newest exact backup, validate again, and restart only the affected service. The nftables service can be disabled safely; its `ExecStop` removes only table `inet cyberqalqon_lab`.

## Expected cleanup

- Test HTTP requests require no filesystem cleanup.
- The FIM test removes `/etc/cyberqalqon-lab/validation.conf` but leaves the empty monitored directory.
- Nmap and Gobuster create no target-side files.
- JSON reports remain under the Git-ignored artifact directory.
