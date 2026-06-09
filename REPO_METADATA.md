# Repository Metadata

## Proposed repository name
`sentinelone-evasion-detection`

Alternatives:
- `edr-evasion-detection-engineering`
- `s1-blue-team-coverage`

## Short description (GitHub "About" field)
> Defensive detection-engineering reference for common EDR evasion techniques — telemetry sources, Sigma rules, MITRE ATT&CK mapping, and SentinelOne hardening guidance for blue teams.

## New document / project title
**From:** *Red Team Guide ~ Bypassing SentinelOne — Detection & Evasion Strategies*
**To:** **Detecting EDR Evasion: A Blue-Team Coverage Guide for SentinelOne**

Subtitle: *Telemetry, Sigma detections, and hardening for common endpoint evasion techniques.*

## Suggested GitHub topics / tags
```
detection-engineering, blue-team, edr, sentinelone, sigma-rules,
mitre-attack, threat-detection, defensive-security, soc, dfir,
endpoint-security, security-monitoring
```

## Suggested license
MIT or Apache-2.0 for the repository. Detection rules are commonly shared under the
Detection Rule License (DRL-1.1) — consider it for the `/detections` folder.

## Repository layout
```
sentinelone-evasion-detection/
├── README.md                 # Main coverage guide
├── REPO_METADATA.md          # This file
├── ATTACK-Mapping.md         # Technique → ATT&CK ID → coverage table
└── detections/               # Sigma detection rules
    ├── lsass_comsvcs_minidump.yml
    ├── byovd_vulnerable_driver_load.yml
    ├── amsi_bypass_powershell.yml
    ├── parent_pid_spoofing.yml
    └── edr_service_tamper.yml
```
