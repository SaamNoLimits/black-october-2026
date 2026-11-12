# Case 02 — FortiBleed: the Firewall Credential Dragnet

## Snapshot

| Field | Value |
|---|---|
| Public re-warning | FBI + US Secret Service joint advisory, **6–7 October 2026** (IC3 CSA 261006) |
| Scale | **86,644** FortiGate/SSL-VPN device credentials, 194 countries |
| Active since | At least **February 2026** (dataset first surfaced June 2026) |
| Attribution | Russian-speaking Initial Access Broker (IAB) group |
| Product CVE | **None for the core vector** — this is credentials, not a software flaw |
| Downstream | Access brokered to ransomware (INC, Lynx; ≥12 deployments traced) |
| Status | **Still active** as of late October 2026; sniffer deployments ongoing |

> FortiBleed is the defender's nightmare precisely because it is *boring*: no zero-day, no cleverness — just reused/leaked credentials, GPU hash-cracking, and internet-exposed management planes.

## What happened

"FortiBleed" is the name researchers (Kevin Beaumont, Hudson Rock, Bitsight, Arctic Wolf, SOCRadar) gave to a sprawling operation that harvested working administrator and VPN credentials from internet-facing Fortinet FortiGate firewalls and SSL-VPN gateways.

The FBI/USSS re-upped the warning on **6–7 October 2026**: the campaign is still running and can even **lock legitimate admins out** of their own firewalls. Mechanics, per the advisories and Recorded Future:

- **Reconnaissance (T1595):** enumerate internet-facing FortiGate SSL-VPN / management surfaces.
- **Credential access (T1110):** credential stuffing (T1110.004) and password spraying using **earlier Fortinet leak dumps and infostealer logs**; ~1.16 billion credential attempts against 320,000+ FortiGate targets (and ~2.1B against 163,650 MSSQL hosts in parallel).
- **Offline recovery:** the dataset likely originated from **exported FortiGate configuration files**, enabling offline credential recovery (legacy SHA-256 password storage in older FortiOS builds) **without ongoing access**.
- **Persistence (T1136):** attackers create **rogue local administrator/backdoor accounts** and deploy **packet sniffers** on compromised devices.
- **Monetization:** access auctioned to ransomware operators.

Context: this sits alongside real Fortinet CVEs attackers abused in 2026 — e.g., **CVE-2026-24858** (FortiCloud SSO auth bypass, CVSS 9.4, used to create rogue admins on *patched* devices) and the Unit 42 "CL-STA-0954" activity chaining **CVE-2024-47575** (FortiManager) and **CVE-2025-61624** (FortiOS), stealing data tied to 500+ firewalls and deploying **PEERSTITCH**. The related **k0t campaign** (disclosed 21 Oct by Group-IB/NyxLab) extended the same credential-theft playbook to FortiWeb and Palo Alto GlobalProtect.

## Attack chain → MITRE ATT&CK

| Phase | Technique | ID |
|---|---|---|
| Recon | Scan internet-facing FortiGate SSL-VPN/mgmt | T1595.002 |
| Credential access | Password spraying | T1110.003 |
| Credential access | Credential stuffing (leak dumps, stealer logs) | T1110.004 |
| Credential access | Offline cred recovery from exported config | T1003 / T1552.001 |
| Initial access | Valid accounts on VPN | T1078 |
| Persistence | Create rogue local admin / backdoor account | T1136.001 |
| Collection | Deploy on-box packet sniffer | T1040 |
| Impact (downstream) | Hand-off to ransomware | T1657 |

## Why it worked

- **Management and SSL-VPN interfaces exposed to the internet.**
- **Password reuse** across devices and over time; credentials leaked years earlier still valid.
- **Legacy FortiOS password hashing** made exported configs crackable offline.
- **No/weak MFA** on VPN and admin access.

## Indicators of compromise

Behavioral > atomic here (it's a credential campaign). Hunt for:

- **FortiGate configuration export** by an admin over the GUI from an unexpected IP. Sophos ships named detections: `PD-FORTINET-FORTIGATE-SYSTEM-CONFIG-DOWNLOAD-EXTERNAL-IP-1` and the XDR `...config-file-has-been-downloaded-by-user-name-via-guiipaddress`.
- New/unknown **local admin accounts** on FortiGate.
- Unexpected **sniffer** processes / diagnostic captures.
- High-volume failed SSL-VPN auths from distributed IPs (spray) followed by a single success.
- See `05_detections/sigma/fortigate_config_export.yml` and `05_detections/suricata/black-october.rules`.

## Mitigation (the advisory's whole point: no patch fixes this)

1. **Remove management interfaces from direct internet exposure.** Admin plane behind VPN/ZTNA only.
2. **Rotate ALL credentials** on exposed FortiGate — local admins, VPN users, and any shared secrets — assume exposure.
3. **Enforce MFA** on SSL-VPN and admin logons.
4. **Audit local accounts** and remove anything you didn't create; review config for unexpected sniffers/scripts.
5. Upgrade FortiOS to builds with modern password storage; patch FortiCloud SSO (CVE-2026-24858) and FortiManager/FortiOS CVEs.
6. Geofence / rate-limit VPN; alert on config exports.

## PoC / exploit status

No single-CVE PoC applies (there is no core CVE). For the adjacent Fortinet CVEs, use the **vendor PSIRT advisories** and your licensed VA scanner's authenticated checks in a lab. The defensive tooling in this package (`kevcheck` for the adjacent CVEs; `logtriage` for config-export URIs) is the reusable artifact.

## Red team takeaway

An authorized engagement here is a **credential-exposure and exposure-surface audit**: enumerate your own internet-facing Fortinet estate, check it against known leak/stealer corpora you are licensed to use, and prove whether MFA and management-plane isolation actually hold. The finding is almost never "we need a patch" — it's "our admin plane is on the internet with reused passwords."

## Sources

See `08_references.md` → "Case 02." Primary: FBI/USSS Joint CSA (IC3, 6 Oct 2026); Recorded Future; Sophos advisory; Trend Micro KA-0023852; Unit 42 (CL-STA-0954); Group-IB/NyxLab (k0t).
