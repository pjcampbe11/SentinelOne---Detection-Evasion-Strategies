# MITRE ATT&CK Mapping & Detection Coverage

This table maps the EDR-evasion technique categories covered in this repo to MITRE
ATT&CK (Enterprise v15+) techniques, the telemetry that surfaces each one, and the
current detection coverage in `/detections`.

Coverage legend: ✅ rule shipped · 🟡 partial / tuning required · ⬜ telemetry only (no packaged rule yet)

| # | Evasion technique | ATT&CK ID | Tactic | Primary telemetry | Coverage | Rule |
|---|-------------------|-----------|--------|-------------------|----------|------|
| 1 | LSASS dump via comsvcs MiniDump | T1003.001 | Credential Access | Process creation, cmdline; LSASS handle access (Sysmon EID 10) | ✅ | `lsass_comsvcs_minidump.yml` |
| 2 | Bring-Your-Own-Vulnerable-Driver | T1068, T1562.001 | Priv-Esc / Defense Evasion | Driver load (Sysmon EID 6), Code Integrity (EID 3033/3077) | ✅ | `byovd_vulnerable_driver_load.yml` |
| 3 | AMSI bypass (in-memory patch / reflection) | T1562.001, T1059.001 | Defense Evasion / Execution | PowerShell Script Block Logging (EID 4104) | ✅ | `amsi_bypass_powershell.yml` |
| 4 | Parent PID spoofing | T1134.004 | Priv-Esc / Defense Evasion | Process creation w/ parent PID + integrity level | ✅ | `parent_pid_spoofing.yml` |
| 5 | EDR/agent service stop or disable | T1562.001 | Defense Evasion | Process creation (sc/net/reg), Service control (EID 7036/7040) | ✅ | `edr_service_tamper.yml` |
| 6 | ETW provider patching / blinding | T1562.006 | Defense Evasion | Loss of expected ETW telemetry; image-load of ntdll w/ RWX | 🟡 | tuning required |
| 7 | API unhooking (fresh ntdll mapping) | T1562.001 | Defense Evasion | Image load of ntdll.dll from non-standard path; EDR self-telemetry | 🟡 | tuning required |
| 8 | Direct / indirect syscalls | T1106 | Execution | Stack-walk anomalies; calls to Nt* from non-ntdll memory | ⬜ | telemetry only |
| 9 | Process injection (hollowing/APC/thread hijack) | T1055, T1055.012, T1055.004 | Defense Evasion / Priv-Esc | CreateRemoteThread (EID 8), RWX alloc, cross-process write | 🟡 | tuning required |
| 10 | Reflective / in-memory DLL loading | T1620 | Defense Evasion | RWX private memory w/ PE header; no backing file on disk | ⬜ | telemetry only |
| 11 | DLL sideloading / search-order hijack | T1574.002 | Persistence / Defense Evasion | Image load of unsigned DLL from app dir | 🟡 | tuning required |
| 12 | Sleep obfuscation / encrypted beacon | T1027 | Defense Evasion | Periodic RW→RX memory permission flips; network beaconing | ⬜ | telemetry only |
| 13 | Service-based driver/persistence install | T1543.003 | Persistence | Service creation (EID 7045), registry Services key | 🟡 | tuning required |
| 14 | Scheduled task persistence | T1053.005 | Persistence / Execution | Task registration (EID 4698), schtasks cmdline | 🟡 | tuning required |
| 15 | Event log clearing | T1070.001 | Defense Evasion | Security log cleared (EID 1102), System log (EID 104) | ⬜ | telemetry only |
| 16 | LOLBIN signed-binary proxy execution | T1218 | Defense Evasion | Process creation for rundll32/regsvr32/mshta + network | 🟡 | tuning required |

## Notes on detecting "EDR blinding" (rows 6–8)
The hardest evasion families remove or corrupt the very telemetry you'd use to catch
them. The durable detection strategy is **absence-of-signal monitoring**: alert when an
endpoint that normally emits a steady stream of EDR/ETW events suddenly goes quiet, when
the agent's heartbeat to the console lapses while the host is still online, or when
expected kernel callbacks stop firing. SentinelOne's own tamper and agent-health
telemetry (forwarded to your SIEM) is a first-class detection source for these.

## Maintenance
- Sync row 2's driver list against the Microsoft Vulnerable Driver Blocklist and loldrivers.io.
- Re-validate ATT&CK IDs each ATT&CK release; sub-technique numbering occasionally shifts.
