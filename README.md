# Detecting EDR Evasion: A Blue-Team Coverage Guide for SentinelOne

> Telemetry, Sigma detections, and hardening for common endpoint evasion techniques.

A detection-engineering reference for defenders. It catalogs the evasion techniques that
adversaries use against endpoint detection and response (EDR) agents — using SentinelOne
as the running example — and, for each one, documents **what telemetry surfaces it**,
**how to detect it**, and **how to harden against it**. The goal is coverage: turning
"attackers can do X" into "here is the data source, the rule, and the config that catches X."

This repository is written entirely from the defender's perspective. It does not contain
working offensive tooling or step-by-step bypass instructions; behaviors are described
only at the level needed to detect and mitigate them.

---

## Who this is for

SOC analysts, detection engineers, threat hunters, and incident responders who operate
SentinelOne (or any modern EDR) and want to measure and close gaps in evasion coverage.
Purple teams can use the ATT&CK mapping to plan adversary-emulation exercises and confirm
that each emulated technique produces an alert.

## How to use this repo

1. Read the **Threat model** below to understand the categories of evasion.
2. Open [`ATTACK-Mapping.md`](./ATTACK-Mapping.md) to see every technique mapped to a
   MITRE ATT&CK ID, the telemetry that reveals it, and current detection coverage.
3. Deploy the rules in [`detections/`](./detections) into your SIEM/EDR (they are written
   in [Sigma](https://github.com/SigmaHQ/sigma) and convert to most query languages).
4. Apply the **Hardening checklist** to reduce the attack surface before relying on detection.
5. Use the **Validation** section to safely confirm coverage in a lab.

```
SentinelOne---Detection-Evasion-Strategies/
├── README.md             # You are here
├── REPO_METADATA.md      # Repo name, description, topics, licensing
├── ATTACK-Mapping.md     # Technique → ATT&CK ID → telemetry → coverage
└── detections/           # Sigma detection rules
    ├── lsass_comsvcs_minidump.yml
    ├── byovd_vulnerable_driver_load.yml
    ├── amsi_bypass_powershell.yml
    ├── parent_pid_spoofing.yml
    └── edr_service_tamper.yml
```

---

## Threat model: how EDR evasion works (defender's view)

Modern EDR agents observe the endpoint from several vantage points at once — user-mode
API hooks, kernel callbacks (process/thread/image/registry notify routines), ETW
consumers, a minifilter for the filesystem, and AMSI for script content. Evasion is the
attacker's attempt to remove, blind, or avoid one or more of those vantage points. The
techniques fall into a handful of recurring families, and each family fails against a
different, durable data source.

**Blinding the sensor in user mode.** Unhooking (restoring a clean copy of `ntdll`),
patching AMSI in memory, and patching ETW providers all neutralize *user-mode* visibility.
The durable detections do not depend on the patched component: AMSI tampering shows up in
PowerShell Script Block Logging, and unhooking shows up as an image-load of `ntdll` from a
non-standard path or anomalous memory permissions. The strongest signal of all is the
**absence of signal** — an endpoint that normally streams telemetry suddenly going quiet.

**Blinding the sensor from the kernel.** Bring-Your-Own-Vulnerable-Driver (BYOVD) loads a
legitimately signed but vulnerable driver to obtain kernel execution, then strips EDR
kernel callbacks or terminates the agent. This is the most powerful family and is caught
at the moment of **driver load** (Sysmon Event ID 6 / Code Integrity events), well before
the agent is touched, by maintaining and alerting on a known-vulnerable-driver list.

**Avoiding the sensor entirely.** Direct and indirect syscalls, reflective/in-memory DLL
loading, and process injection avoid the hooked functions rather than removing the hooks.
These are caught by memory-centric telemetry: private RWX regions containing a PE header,
cross-process writes, and unexpected `CreateRemoteThread` activity.

**Hiding in trusted execution.** Parent PID spoofing, DLL sideloading, and signed-binary
proxy execution (LOLBINs) make malicious activity descend from, or run inside, trusted
processes. These are caught by baselining parent-child relationships and image-load
provenance rather than by reputation alone.

**Disabling the agent directly.** Stopping, deleting, or misconfiguring the agent service.
SentinelOne's anti-tamper blocks most of these, but the *attempt* is high-signal telemetry
and should alert even when it fails.

A fuller, per-technique breakdown with ATT&CK IDs is in
[`ATTACK-Mapping.md`](./ATTACK-Mapping.md).

---

## Telemetry sources that matter

Detection quality is bounded by the data you collect. Prioritize, at minimum:

- **EDR/agent telemetry forwarded to the SIEM** — process, file, network, and especially
  **agent-health and tamper events**. Treat agent heartbeat loss on a live host as an alert.
- **Sysmon** (or equivalent) for process creation with full command line and parent PID
  (EID 1), driver load (EID 6), image load (EID 7), remote thread creation (EID 8), and
  process access / LSASS handle requests (EID 10).
- **PowerShell Script Block Logging** (EID 4104) and module logging — essential for AMSI,
  obfuscation, and reflection detection.
- **Windows Security/System logs** — service install (EID 7045), service state change
  (EID 7036/7040), scheduled task registration (EID 4698), and log-clear (EID 1102 / 104).
- **Windows Defender Application Control / Code Integrity** events for driver and image
  integrity (EID 3033/3077).

If a data source above is not being collected, that is itself a coverage gap — fix it
before tuning rules.

---

## Detection rules

The [`detections/`](./detections) folder ships Sigma rules for the highest-signal
techniques. Sigma is vendor-neutral and converts to SentinelOne Deep Visibility / STAR,
Splunk SPL, Microsoft Sentinel KQL, Elastic, and others via `sigma convert`.

| Rule | Catches | ATT&CK |
|------|---------|--------|
| `lsass_comsvcs_minidump.yml` | LSASS dumping via the comsvcs LOLBIN | T1003.001 |
| `byovd_vulnerable_driver_load.yml` | Loading a known vulnerable driver | T1068 / T1562.001 |
| `amsi_bypass_powershell.yml` | In-memory AMSI tampering in PowerShell | T1562.001 / T1059.001 |
| `parent_pid_spoofing.yml` | Anomalous parent-child process lineage | T1134.004 |
| `edr_service_tamper.yml` | Stopping/disabling the security agent | T1562.001 |

Every rule is `status: experimental` — **baseline and tune against your environment
before alerting in production**, and review the `falsepositives` field in each file.

### Converting a rule

```bash
pip install sigma-cli
# Microsoft Sentinel (KQL)
sigma convert -t kusto detections/lsass_comsvcs_minidump.yml
# Splunk
sigma convert -t splunk detections/lsass_comsvcs_minidump.yml
```

---

## Hardening checklist (reduce attack surface before relying on detection)

- **Enable the Microsoft Vulnerable Driver Blocklist** and WDAC/HVCI so BYOVD drivers fail
  to load in the first place. This is the single highest-impact control against the
  strongest evasion family.
- **Turn on SentinelOne anti-tamper / tamper protection** and require console-side
  approval for agent uninstall or downgrade. Forward tamper events to the SIEM.
- **Enforce PowerShell Constrained Language Mode** where feasible, and enable Script Block
  and module logging everywhere.
- **Restrict LOLBINs** (rundll32, regsvr32, mshta, etc.) via application control where the
  business allows, and alert on the rest.
- **Protect LSASS** with Credential Guard / RunAsPPL (`RunAsPPL=1`) to raise the cost of
  credential dumping.
- **Monitor agent health centrally** — alert when an endpoint stops reporting while it is
  still reachable on the network.
- **Keep least privilege** — most kernel-level evasion requires local admin; reducing
  standing admin rights removes the precondition.

---

## Validation (safely confirm your coverage)

Validate detections with sanctioned, authorized testing only, in a lab or a change-managed
purple-team window:

- **Atomic Red Team** has atomics for many of the ATT&CK techniques mapped here (e.g.,
  T1003.001, T1562.001, T1134.004). Run the atomic, confirm the expected telemetry arrives,
  and confirm the rule fires.
- **SentinelOne's own testing/verification guidance** and the EICAR test string validate
  that the agent and pipeline are alive end to end.
- Track results as a coverage matrix: technique → telemetry present? → rule fired? → MTTD.

Do not run evasion tooling against production systems or systems you are not authorized to
test.

---

## Scope and intent

This project documents **defense**. It deliberately omits working bypass code, payloads,
and operational tradecraft. Techniques are described only to the depth required to detect,
validate, and mitigate them. Contributions should preserve that boundary: detection logic,
telemetry analysis, hardening, and ATT&CK mapping are welcome; offensive tooling is not.

## References

- MITRE ATT&CK — https://attack.mitre.org/
- SigmaHQ — https://github.com/SigmaHQ/sigma
- LOLBAS Project — https://lolbas-project.github.io/
- LOLDrivers — https://www.loldrivers.io/
- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
- Microsoft recommended driver block rules — https://learn.microsoft.com/windows/security/application-security/application-control/

## License

See [`REPO_METADATA.md`](./REPO_METADATA.md) for licensing suggestions. Detection content
is commonly shared under the Detection Rule License (DRL-1.1).
