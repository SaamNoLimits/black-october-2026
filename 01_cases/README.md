# 🔍 Case Studies

<p align="center">
  <img src="https://img.shields.io/badge/cases-11-e5534b?style=flat-square" alt="11 cases">
  <img src="https://img.shields.io/badge/each-ATT%26CK%20mapped-8957e5?style=flat-square" alt="ATT&CK mapped">
  <img src="https://img.shields.io/badge/each-detections%20%2B%20mitigations-1f6feb?style=flat-square" alt="detections + mitigations">
</p>

The core of the package: one deep-dive per incident. Every case file follows the same structure — **Snapshot → What happened → ATT&CK chain → Why it worked → IOCs → Detection & hunting → Mitigation → PoC/exploit status → Red-team takeaway → Sources** — so you can jump straight to the section you need.

---

## 📇 Index

| # | Case | Severity | Identifier | One-line |
|---|------|----------|------------|----------|
| 01 | [Binance / TraderTraitor heist](01_binance_traertraitor_heist.md) | 🔴 Critical | _no CVE_ | $6.34B via a dev laptop, an abused internal **AI tool**, and a standing deploy token (DPRK) |
| 02 | [FortiBleed](02_fortibleed_campaign.md) | 🔴 Critical | _no CVE_ | 86,644 firewall creds; reused passwords + exposed mgmt planes — no patch fixes it |
| 03 | [ConnectWise Cloud Backup](03_connectwise_cloud_backup.md) | 🔴 Critical | _app-key abuse_ | one stolen vendor OAuth key → app-only sign-in to 173+ M365 tenants |
| 04 | [LiteLLM 1.107.0 supply chain](04_litellm_supply_chain.md) | 🔴 Critical | _PyPI + Docker_ | stealer running from a Python `.pth` hook **before any import** |
| 05 | [PHP2Shell](05_php2shell_rce.md) | 🔴 9.2 | CVE-2026-109618/109619 | pre-auth RCE in the PHP runtime; exploited **before** the fix |
| 06 | [Windows Shell MotW 0-day](06_windows_shell_motw_zeroday.md) | 🟠 8.8 | CVE-2026-96951 | Mark-of-the-Web bypass; lone exploited 0-day in a 1,413-CVE Patch Tuesday |
| 07 | [Oracle E-Business Suite](07_oracle_ebs_sqli.md) | 🔴 9.8 | CVE-2026-101767 | unauth SQLi → RCE behind a default-allowed servlet; probed within a week |
| 08 | [Cisco ASA/FTD SSL-VPN](08_cisco_asa_ftd_dos.md) | 🟠 8.6 | CVE-2026-76418 | unauth DoS reload of the VPN concentrator; no full workaround |
| 09 | [GitLab CI/CD RCE](09_gitlab_cicd_rce.md) | 🔴 KEV | CVE-2026-97229 | unauth RCE in the software supply-chain control plane |
| 10 | [Ivanti Connect Secure](10_ivanti_connect_secure_chain.md) | 🟠 8.6 | CVE-2026-104935 | UTA0576 unauth command-exec chain on the edge gateway |
| 11 | [The wider vuln & breach wave](11_black_october_vuln_wave.md) | 🟠 mixed | _many_ | Plex2Shell, Arista, Citrix, PAN-OS, Brotli, EDK II, eMudhra, the big breaches |

🔴 Critical · 🟠 High &nbsp;|&nbsp; _no CVE_ = credential/identity/supply-chain, not a product flaw

---

## 🧭 Read by theme

- **&ldquo;Trust turned into a weapon&rdquo;** → [01 Binance](01_binance_traertraitor_heist.md) · [03 ConnectWise](03_connectwise_cloud_backup.md) · [04 LiteLLM](04_litellm_supply_chain.md)
- **Internet-facing unauth RCE** → [05 PHP2Shell](05_php2shell_rce.md) · [07 Oracle EBS](07_oracle_ebs_sqli.md) · [09 GitLab](09_gitlab_cicd_rce.md) · [10 Ivanti](10_ivanti_connect_secure_chain.md)
- **Edge appliances & delivery evasion** → [02 FortiBleed](02_fortibleed_campaign.md) · [06 Windows Shell MotW](06_windows_shell_motw_zeroday.md) · [08 Cisco ASA/FTD](08_cisco_asa_ftd_dos.md)

## 🔗 Related

- [`../02_cve_catalog.md`](../02_cve_catalog.md) — every CVE across these cases in one triage table
- [`../03_attack_mapping_mitre.md`](../03_attack_mapping_mitre.md) — the ATT&CK matrix spanning all cases
- [`../05_detections/`](../05_detections/) and [`../04_iocs/`](../04_iocs/) — detections & indicators per case
- [`../07_mitigations_playbook.md`](../07_mitigations_playbook.md) — what to do about all of it

---

<p align="center"><sub><a href="../README.md">&larr; back to repository root</a></sub></p>
