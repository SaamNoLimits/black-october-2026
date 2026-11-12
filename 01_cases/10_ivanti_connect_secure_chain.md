# Case 10 — Ivanti Connect Secure zero-day chain (UTA0576)

## Snapshot

| Field | Value |
|---|---|
| Lead CVE | **CVE-2026-104935** — CVSS **8.6**, **unauthenticated command execution** |
| Chained with | **CVE-2026-111357** and a third flaw (two more added to **CISA KEV 30 October**) |
| Actor cluster | tracked as **UTA0576** |
| Fixed | upgrade to **25.1.1.3** or **22.8R2.6** |
| Status | actively exploited; multiple flaws in the chain KEV-listed late October |

## What happened

Ivanti Connect Secure — an SSL-VPN / remote-access gateway — was hit by a **zero-day exploit chain** attributed to activity tracked as **UTA0576**. The lead flaw, **CVE-2026-104935** (CVSS 8.6), is an **unauthenticated command execution** bug; it was **chained with two more** vulnerabilities (incl. **CVE-2026-111357**) that CISA added to KEV on **30 October**. Edge VPN appliances remained one of 2026's most-targeted categories, and Ivanti Connect Secure in particular has a multi-year history of exploited edge bugs.

## Attack chain → MITRE ATT&CK

| Phase | Technique | ID |
|---|---|---|
| Recon | Identify internet-facing Ivanti Connect Secure | T1595.002 |
| Initial access | Exploit public-facing appliance (unauth cmd exec) | T1190 |
| Execution | Command execution on the gateway | T1059 |
| Persistence (typical for this class) | Webshell / implant on appliance | T1505.003 |
| Credential access (follow-on) | Harvest VPN session/creds | T1556 / T1040 |

## Why it worked

- **Pre-auth command execution** on an internet-facing appliance.
- **Chaining** multiple flaws to reach full compromise.
- Appliances are **opaque** — limited native EDR, hard to inspect, trusted at the perimeter.

## Indicators / hunting

- Pull **UTA0576 IOCs** from the disclosing researchers' advisory (reference section).
- Run Ivanti's **Integrity Checker Tool (ICT)**; inspect for unexpected files/processes and config changes on the appliance.
- Gateway logs: anomalous unauthenticated requests to admin/CGI endpoints; unexpected outbound.
- Review VPN auth logs for session anomalies post-compromise.

## Mitigation

1. **Upgrade** to **25.1.1.3** or **22.8R2.6** (or later).
2. Run the **ICT** and Ivanti's forensic guidance; if compromise is suspected, **factory reset + rebuild** per vendor IR guidance (in-place patching may not evict an implant).
3. **Rotate** all secrets/certs the appliance held; reset VPN user credentials.
4. Restrict management plane exposure; front remote access with ZTNA where feasible.

## PoC / exploit status

KEV-listed and actively exploited. Use Ivanti's **security advisory** and the researchers' write-up as authoritative references; validate version with `kevcheck`. No exploit code included — pre-auth appliance RCE is maximum uplift.

## Red team takeaway

Edge VPN appliances are the perennial front door. The exercise: inventory every internet-facing Ivanti gateway, confirm it's on a fixed train, run the ICT, and rehearse the **"assume the appliance is implanted"** rebuild — patching alone rarely evicts an edge implant.

## Sources

See `08_references.md` → "Case 10." Primary: Ivanti security advisory; CISA KEV (30 Oct); PlayCISO Black October roundup (CVE-2026-111357 chain); ceos3c patch list.
