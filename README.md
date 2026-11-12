# Black October 2026 — Red Team Threat Intelligence Package

**Author:** AI Red Team Lead
**Compiled:** 12 November 2026
**Classification:** TLP:CLEAR (built entirely from public reporting — safe to share)
**Reporting window:** 1–31 October 2026

---

## What this is

October 2026 was bad enough that the security press settled on a name for it: **"Black October."**
A record Patch Tuesday (1,413 Microsoft CVEs), the largest crypto heist in history, a credential
dragnet against tens of thousands of firewalls, three separate open-source supply-chain poisonings,
and a cluster of unauthenticated-RCE "2Shell" flaws all landed in the same four weeks.

This package is the write-up I wish I'd had on my desk on 1 November: every major case, the CVEs,
the MITRE ATT&CK mapping, indicators of compromise, ready-to-tune detection rules, a defensive
Rust toolkit, and a prioritized mitigation playbook — in one structured folder.

## Scope and ethics (read this first)

This is a **blue-leaning red-team** package. It is built to help defenders and authorized red teams
**understand, detect, hunt for, and remediate** the October 2026 activity.

- It describes how each attack worked at the level a detection engineer or IR lead needs.
- It maps techniques to MITRE ATT&CK and ships detection content and hunting tooling.
- For each vulnerability it points to the **official vendor advisory** and notes where public
  proof-of-concept code exists, so your team can retrieve and detonate it **in a lab you control**.
- It deliberately **does not** reproduce weaponized exploit code, stealer payloads, or
  attack scripts. For a KEV-listed, actively-exploited flaw, publishing a drop-in exploit helps
  the people spraying the internet more than it helps the people trying to survive it. The reference
  sections tell you exactly where the vendor PoC and PoC-tracking live if you need them.

The Rust tooling under `06_rust_tooling/` is strictly defensive: an inventory-vs-fixed-version
checker, an IOC matcher, and a log-triage helper. Nothing in it attacks anything.

## Folder map

```
black-october-2026/
├── README.md                     ← you are here
├── 00_executive_summary.md       ← one-page brief for leadership
├── 01_cases/                     ← deep dive per incident (the core of the package)
│   ├── 01_binance_traertraitor_heist.md
│   ├── 02_fortibleed_campaign.md
│   ├── 03_connectwise_cloud_backup.md
│   ├── 04_litellm_supply_chain.md
│   ├── 05_php2shell_rce.md
│   ├── 06_windows_shell_motw_zeroday.md
│   ├── 07_oracle_ebs_sqli.md
│   ├── 08_cisco_asa_ftd_dos.md
│   ├── 09_gitlab_cicd_rce.md
│   ├── 10_ivanti_connect_secure_chain.md
│   └── 11_black_october_vuln_wave.md
├── 02_cve_catalog.md             ← every CVE in one triage table
├── 03_attack_mapping_mitre.md    ← ATT&CK technique matrix across all cases
├── 04_iocs/                      ← machine-readable indicators
│   ├── iocs.csv
│   └── README.md
├── 05_detections/                ← Sigma, YARA, Suricata
│   ├── sigma/
│   ├── yara/
│   └── suricata/
├── 06_rust_tooling/              ← defensive Cargo workspace (kevcheck, iocmatch, logtriage)
├── 07_mitigations_playbook.md    ← prioritized actions, by role
└── 08_references.md              ← every source, per case
```

## How to use it

1. **Leadership / 20 minutes:** read `00_executive_summary.md`, skim the CVE catalog.
2. **IR / detection engineers:** work the cases you're exposed to in `01_cases/`, load the matching
   rules from `05_detections/`, feed `04_iocs/iocs.csv` into your SIEM/EDR.
3. **Vuln management:** run `kevcheck` against your asset inventory (see `06_rust_tooling/README.md`),
   then drive the `07_mitigations_playbook.md` patch order.
4. **Threat hunters:** run `iocmatch` and `logtriage` over retained logs for the exposure windows
   listed in each case file.

## A note on the numbers

Every figure, CVE, date and indicator in this package is attributed in `08_references.md`. Where
reporting disagreed (dollar amounts, device counts, exact timestamps), I kept the vendor/primary
number and flagged the spread. Several of these cases were still moving as of early November 2026 —
treat attribution as "as reported," re-check KEV before you deprioritize anything.
