# Case 08 — Cisco ASA/FTD SSL-VPN DoS Zero-Day (CVE-2026-76418)

## Snapshot

| Field | Value |
|---|---|
| CVE | **CVE-2026-76418** — CVSS **8.6** (High) |
| Advisory | `cisco-sa-asaftd-tunnel-dos-s6mgkb75` (bug CSCwx26625), published **28 October 2026** |
| Effect | **Unauthenticated remote DoS** — crafted request **reloads** the device; no successful VPN login required |
| Root cause | Logic errors when **secondary authentication** is configured on a tunnel group |
| Exploitation | Cisco PSIRT aware of **active exploitation in October 2026**; **CISA KEV 29 Oct** |
| Context | **Second** ASA/FTD VPN DoS zero-day since August 2026 (after CVE-2026-20349) |
| Workaround | **None complete** — upgrade is required |

## What happened

Cisco disclosed **CVE-2026-76418** on **28 October 2026**: a logic error in the **Remote Access SSL VPN** service of Secure Firewall ASA and FTD lets an **unauthenticated** attacker send a crafted request to the SSL-VPN login endpoint and force the device to **reload** — a denial of service that knocks remote access offline. A successful login is **not** needed. Cisco confirmed active exploitation and shipped fixed releases; CISA added it to KEV on 29 Oct.

### Exposure conditions (all must hold)

1. A **vulnerable** ASA or FTD release, **and**
2. A **reachable** SSL remote-access VPN login service (config contains the `webvpn` keyword; SSL VPN enabled on ≥1 interface), **and**
3. **Secondary authentication** configured on an applicable tunnel group.

Devices **without SSL VPN enabled on any interface are not exposed.**

### Fixed releases (from Cisco's advisory)

| Software | Branch | First fixed |
|---|---|---|
| ASA | 9.18 | 9.18.4.96 |
| ASA | 9.20 | 9.20.4.50 |
| ASA | 9.22 | 9.22.3.200 |
| FTD | 7.0 and earlier | 7.0.11 |
| FTD | 7.2 | 7.2.13 |
| FTD | 7.4 | 7.4.9 |
| FTD | 7.6 | 7.6.7 |
| FTD | 7.7 | 7.7.14 |
| FTD | 10.0 | 10.0.3 |
| FTD | 10.1 | 10.1.1 |

## Attack chain → MITRE ATT&CK

| Phase | Technique | ID |
|---|---|---|
| Recon | Identify internet-facing ASA/FTD SSL-VPN | T1595.002 |
| Impact | Endpoint DoS via crafted request → device reload | T1499.004 |

(Impact-only: no RCE or credential theft indicated per CISA.)

## Why it worked

- **Pre-auth reachability** of the SSL-VPN login endpoint from the internet.
- A **logic error in the secondary-auth path** reachable before authentication completes.
- VPN appliances are, by design, internet-facing — the attack surface is the product's purpose.

## Indicators / hunting

- No IOCs (threat actors, targets, incident counts) publicly disclosed as of late Oct.
- Operationally: **unexpected device reloads** correlated with inbound SSL-VPN login traffic; watch ASA/FTD syslog for crash/traceback + reload events and unusual pre-auth request patterns to the VPN endpoint.
- Suricata: alert on anomalous volume to the SSL-VPN login path (template in `05_detections/suricata/black-october.rules`).

## Mitigation

1. **Upgrade** to the fixed release for your branch (table above) — there is **no complete workaround**.
2. If you can't patch immediately, reduce exposure: restrict which source IPs can reach the SSL-VPN login endpoint; consider temporarily disabling SSL VPN / secondary-auth on affected tunnel groups if operationally acceptable (validate against Cisco's advisory).
3. Monitor for reloads and set up alerting on unexpected failovers.
4. Reassess whether the SSL-VPN admin/login plane needs to be internet-wide or can be geofenced/ZTNA-fronted.

## PoC / exploit status

KEV-listed, actively exploited; Cisco withheld detailed exploit specifics and no public IOCs/PoC were broadly available as of late Oct. This package does **not** provide a DoS exploit. Verify fixed-version status with `kevcheck` (Cisco ruleset) rather than crash-testing production.

## Red team takeaway

DoS on the VPN concentrator is an availability attack on your entire remote workforce. The engagement value is **exposure + patch SLA + resilience**: is the SSL-VPN login endpoint internet-wide, are you on a fixed train, and do you have a tested failover if the concentrator is forced to reload?

## Sources

See `08_references.md` → "Case 08." Primary: Cisco advisory `cisco-sa-asaftd-tunnel-dos-s6mgkb75` (28 Oct); BleepingComputer (29 Oct); SOC Prime; SecPod; CISA KEV.
