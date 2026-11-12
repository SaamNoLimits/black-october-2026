# Case 06 — Windows Shell MotW Zero-Day (CVE-2026-96951) + October Patch Tuesday

## Snapshot

| Field | Value |
|---|---|
| Patch Tuesday | **13/14 October 2026** — **1,413** Microsoft CVEs (record), 78 Critical, 65 Critical RCE |
| Exploited zero-day | **CVE-2026-96951** — Windows Shell **Security Feature Bypass**, CVSS **8.8** |
| Effect | Bypasses **Mark-of-the-Web (MotW)**, stripping the "downloaded file" security warning |
| Status | Actively exploited pre-patch; **CISA KEV**, BOD 22-01 federal due date **16 Oct 2026** |
| Context | **Third** Windows Shell MotW zero-day exploited in 2026 (per Tenable's Satnam Narang) |
| Also public pre-patch | **CVE-2026-108398** (.NET Framework) — disclosed, details public, no confirmed exploitation yet |

## What happened

October's Patch Tuesday broke the CVE record **again** at ~1,413 fixes. The one under active attack was **CVE-2026-96951**, a Windows Shell flaw that **undermines Mark-of-the-Web**. MotW is the tag Windows applies to files from the internet; it's what makes Office open in Protected View and SmartScreen warn you. Bypassing it means a downloaded/attached malicious file runs with **no warning** — the attack requires only that a user open a crafted file or visit a crafted site, which maps directly onto the most common phishing delivery chain.

It was the **third** MotW Shell zero-day of 2026 — attackers clearly treat MotW bypass as a reliable delivery primitive. CISA set a **16 October** federal remediation deadline.

### Other October Patch Tuesday CVEs worth prioritizing

| CVE(s) | Component | Why it matters |
|---|---|---|
| **CVE-2026-96951** | Windows Shell | **Exploited.** MotW bypass; patch first. |
| CVE-2026-108398 | .NET Framework | Publicly disclosed pre-patch; PoC tends to follow fast. |
| CVE-2026-102866 | SharePoint Server | Critical EoP, unauthenticated, publicly disclosed. |
| CVE-2026-70571 / 70279 | Exchange Server | Critical RCE / "exploitation more likely," internet-exposed. |
| CVE-2026-70229 | Active Directory Domain Services | RCE targeting the DC. |
| CVE-2026-69802 | NDES | RCE. |
| CVE-2026-96934, -88117, -88119, -88120, -88171 | Windows DHCP Server | Critical RCE cluster. |
| CVE-2026-100202, -108460 | Message Queuing (MSMQ) | Critical RCE where MSMQ enabled. |
| CVE-2026-105016, -100219 | Microsoft QUIC | Critical RCE for QUIC-facing services. |
| CVE-2026-70571 | Exchange | (dup) prioritize on exposed Exchange. |
| CVE-2026-88174 | Windows Deployment Services | Critical RCE. |

## Attack chain → MITRE ATT&CK (CVE-2026-96951)

| Phase | Technique | ID |
|---|---|---|
| Delivery | Phishing attachment / malicious download | T1566.001 / T1566.002 |
| Defense evasion | **Bypass Mark-of-the-Web** | T1553.005 |
| Execution | User opens crafted file | T1204.002 |
| (Follow-on) | Loader/stealer/ransomware per actor | — |

## Why it worked

- **MotW is a security *feature*, and bypassing it is quiet** — the user sees no warning, EDR sees a "user opened a file."
- **Delivery-stage evasion** multiplies the value of every phishing email.

## Detection & hunting

- Hunt files written by browsers/mail clients that **lack the `Zone.Identifier` ADS** but originate from internet paths (MotW stripped).
- Office/SmartScreen telemetry: internet-origin documents opening **without** Protected View.
- Correlate "file opened from Downloads/temp → child process spawns (script host, LOLBIN)."
- `05_detections/sigma/windows_shell_motw_bypass.yml` provides a starting rule (missing/zero `Zone.Identifier` + suspicious child process).

## Mitigation

1. **Deploy the October 2026 cumulative update** — CVE-2026-96951 **first**, on all affected Windows.
2. Keep **SmartScreen / Protected View / ASR rules** enforced (defense-in-depth even against MotW bypass).
3. Prioritize the rest in the table — especially internet-exposed **Exchange, SharePoint, DHCP, MSMQ, QUIC** and the **AD DS**/**NDES** RCEs.
4. User-awareness on opening attachments — but treat it as backup to patching, not primary.

## PoC / exploit status

Exploited in the wild, KEV-listed. Microsoft's **MSRC advisory** is the authoritative reference; detailed exploitation mechanics for an in-the-wild MotW bypass are not reproduced here. For CVE-2026-108398 (.NET) and CVE-2026-102866 (SharePoint), public details exist and PoCs are expected quickly — track via your VA vendor and detonate only in a lab. `kevcheck` flags unpatched builds without needing an exploit.

## Red team takeaway

For an authorized phishing-simulation program, MotW-bypass delivery is the realistic 2026 lure. Measure **detection at the "file opened, no warning" moment**, not just at the email gateway. Patch cadence on a 1,413-CVE month is itself a finding: can your org actually absorb that in the KEV window?

## Sources

See `08_references.md` → "Case 06." Primary: Microsoft MSRC (Oct 2026); CISA KEV; Tenable (Narang); Splashtop / SecPod / TechTimes / Shattered.io Patch Tuesday breakdowns.
