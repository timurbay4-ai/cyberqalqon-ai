# Windows Detection Coverage

Wazuh 4.14.8 built-ins already cover the requested semantics, so no custom Windows rule was added.
Rule references below were verified against the installed manager ruleset.

| Event | Built-in rule | Level | MITRE supplied by Wazuh | Status |
|---|---:|---:|---|---|
| 4624 successful logon | 60106 / granular children | 3 | T1078 on base success | Available after enrollment |
| 4625 bad user/password | 60122 | 5 | T1531 | Available after enrollment |
| 4634 logoff | built-in Windows chain | varies | upstream-dependent | Collection/normalization prepared; no new live sample claimed |
| 4648 explicit credentials | built-in Windows chain | varies | upstream-dependent | Collection/normalization prepared; no new live sample claimed |
| 4672 privileged logon | built-in Windows chain | varies | upstream-dependent | Collection/normalization prepared; no new live sample claimed |
| 4688 process creation | built-in Windows chain | varies | upstream-dependent | Fixture parser PASS; live audit-policy evidence absent |
| Repeated failed logons, same source | 60204 | 10 | T1110 | 8 matches / 240 seconds |
| 4720 account created/enabled | 60109 | 8 | T1098 | Available after enrollment |
| 4726 account deleted/disabled | 60111 | 8 | T1098, T1531 | Available after enrollment |
| 4732 local group membership changed | 60113 | 5 | T1484 | Available after enrollment |
| 1102 audit log cleared | 60117 | 9 | T1070.004 | Synthetic/live destructive test prohibited |
| 7045 service installed | 61138 | 5 | T1543.003 | Historical host event + synthetic fixture; delivery blocked |
| 4104 harmless `Get-Process` block | 91815 | 4 | T1057 | Historical host event + fixture; delivery blocked |
| 4103 PowerShell module logging | built-in Windows chain | varies | upstream-dependent | Collection/normalization prepared; live policy evidence absent |
| Defender 1116 detection | 62123 | 12 | none in installed rule | Historical host event + synthetic fixture; delivery blocked |
| Defender 1117 remediation | 62124 | 3 | none in installed rule | Historical host event; delivery blocked |
| Defender protection-state changes | built-in Windows chain | varies | upstream-dependent | IDs 5000/5001/5004/5007 are allowlisted; no new live acceptance claimed |

The upstream 4625 rule's T1531 mapping is preserved rather than locally rewritten. CyberQalqon
does not invent MITRE mappings. No high-severity custom rule is applied to normal 4624 events.

`wazuh-logtest` in this installed version decodes standalone EventChannel JSON fixtures as `json`,
not `windows_eventchannel`; rule 60000 therefore does not chain in the test tool. Live manager
rules were not edited to work around that limitation. Runtime built-in detection remains blocked
until the Windows agent is enrolled, while rule definitions and fixture field/provider/channel
contracts are covered by automated tests.
