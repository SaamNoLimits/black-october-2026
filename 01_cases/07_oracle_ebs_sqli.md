# Case 07 — Oracle E-Business Suite unauth SQLi→RCE (CVE-2026-101767)

## Snapshot

| Field | Value |
|---|---|
| CVE | **CVE-2026-101767** — CVSS **9.8** (Critical) |
| Component | Oracle **Application Object Library (Core)** in E-Business Suite |
| Affected | EBS **12.2.3 – 12.2.15** |
| Type | **Unauthenticated SQL injection → remote code execution** over HTTP (no login) |
| Fixed | Oracle **October 2026 Critical Patch Update, 20 October** (My Oracle Support note **KA923**; patch 39800355) |
| Exploitation | Decoys (Defused) recorded **exploratory attempts 27 October**; public PoC repo appeared **26 Oct**; **not** in CISA KEV / no confirmed breach as of late Oct |
| Discoverer | Horizon3.ai (reported to Oracle 24 Jul 2026; 88-day fix) |

## What happened

Oracle's October 2026 CPU patched **CVE-2026-101767**, an **unauthenticated SQL injection** in the EBS Application Object Library reachable **remotely over HTTP without authentication**, leading to RCE and full takeover of the Application Object Library. Notably, the vulnerable servlet sits **behind a path the product's own default URL firewall allows** — so default hardening doesn't save you.

Pattern-wise this rhymes with 2025, when **Cl0p** exploited EBS/Oracle zero-days for mass extortion. **Important nuance:** as of late October, reporting explicitly said **nothing links CVE-2026-101767 to Cl0p**, and exploitation was **probing against honeypots**, not confirmed in-the-wild compromise. Horizon3.ai's advisory listed IOCs on 20 Oct; a public PoC repo appeared 26 Oct; first decoy hits 27 Oct. Given EBS's history, treat the fix-to-exploitation gap as **days-to-weeks**.

## Attack chain → MITRE ATT&CK

| Phase | Technique | ID |
|---|---|---|
| Recon | Identify internet-facing EBS | T1595 |
| Initial access | Exploit public-facing app (SQLi) | T1190 |
| Execution | SQLi → RCE on Application Object Library | T1059 |
| (2025 precedent) | Mass data theft / extortion (Cl0p-style) | T1657 |

## Why it worked

- **Unauthenticated + default-allowed servlet path** = internet-reachable with no creds.
- **ERP systems hold HR, payroll, and financial data** — high extortion value, slow to patch.
- **Public PoC within days** of disclosure compresses the defender window.

## Indicators / hunting

- Horizon3.ai published **IOCs** on 20 Oct — pull from their advisory.
- Hunt EBS web/access logs for requests to the **Application Object Library servlet** paths with SQL-injection patterns (quotes, `UNION`, stacked queries, time-based payloads) from unauthenticated sessions.
- DB-tier: anomalous queries from the EBS app account; unexpected procedure execution.
- `logtriage` includes a heuristic for EBS servlet paths + SQLi markers.

## Mitigation

1. **Apply the October 2026 CPU** to EBS **12.2.3–12.2.15** (My Oracle Support note **KA923**); also apply the CPU to the underlying **Oracle Database and Fusion Middleware** components of EBS.
2. **Remove EBS web tiers from direct internet exposure** where possible; put behind VPN/WAF.
3. **Assume-breach hunt** any internet-facing EBS exposed after 20 Oct; review logs back to disclosure.
4. Verify your **URL firewall** config doesn't allow the vulnerable servlet beyond what's required.

## PoC / exploit status

A public PoC repo appeared on 26 Oct (not reviewed/validated here), and OffSeq noted no Metasploit/Exploit-DB/nuclei weaponization indexed as of 28 Oct. This package does **not** include EBS exploit code. Validate remediation with authenticated version checks (`kevcheck` ships an Oracle-EBS ruleset keyed to the October CPU) or detonate the vendor-referenced PoC only in an isolated lab.

## Red team takeaway

ERP is a classic "unauthenticated internet-facing + crown-jewel data" target and a repeat Cl0p favorite. The engagement value is **exposure discovery + patch SLA**: find every EBS web tier, confirm it's patched to the October CPU, and verify it isn't reachable unauthenticated from the internet.

## Sources

See `08_references.md` → "Case 07." Primary: Oracle Critical Patch Update Advisory (Oct 2026); Horizon3.ai advisory; SecurityWeek (28 Oct); Rescana; Tuskira; R3KONX (servlet/URL-firewall analysis).
