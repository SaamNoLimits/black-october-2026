# October 2026 CVE Catalog (triage table)

Prioritize by **Exploited (KEV) → CVSS → exposure**. "KEV" = on CISA Known Exploited Vulnerabilities catalog as of the dates reported in October 2026. Always re-check KEV before deprioritizing — this list reflects reporting through early November 2026.

| CVE | Product / component | Type | CVSS | Exploited? | Fixed version / action | Case |
|---|---|---|---|---|---|---|
| CVE-2026-96951 | Windows Shell | Security feature bypass (MotW) | 8.8 | **KEV** (fed due 16 Oct) | Oct 2026 cumulative update | 06 |
| CVE-2026-109618 | PHP runtime | Pre-auth RCE (multipart) | 9.2 | **KEV 26 Oct** | 8.5.12/8.4.27/8.3.36/8.2.35 + restart workers | 05 |
| CVE-2026-109619 | PHP runtime | Pre-auth RCE (stale global state) | 9.2 | **KEV 26 Oct** | 8.5.12/8.4.27/8.3.36/8.2.35 + restart workers | 05 |
| CVE-2026-46300 | PHP-adjacent (Fragnesia) | Priv-esc → root | — | Wave | Patch | 05/11 |
| CVE-2026-111497 | Runtime (Broccoli2Shell) | RCE | — | Wave | Vendor update | 11 |
| CVE-2026-101767 | Oracle EBS (App Object Library) | Unauth SQLi → RCE | 9.8 | Probed 27 Oct (not KEV late Oct) | Oct 2026 CPU (MOS KA923) | 07 |
| CVE-2026-101809 | Oracle EBS Workflow | Critical | — | — | Oct 2026 CPU | 07/11 |
| CVE-2026-76418 | Cisco ASA/FTD SSL VPN | Unauth DoS (reload) | 8.6 | **KEV 29 Oct** | See fixed-release table (Case 08) | 08 |
| CVE-2026-76519 | Cisco Secure Email Gateway | Root flaw | — | **KEV 14 Oct** | 15.5.5-014 / 16.5.0-780 | 11 |
| CVE-2026-97229 | GitLab | Unauth RCE (regex overflow) | — | **KEV 29 Oct** | 19.2.8/19.3.5/19.4.2 | 09 |
| CVE-2026-110264 | GitLab | RCE (companion) | — | — | 19.2.8/19.3.5/19.4.2 | 09 |
| CVE-2026-104935 | Ivanti Connect Secure | Unauth command exec | 8.6 | **KEV** (chain, 30 Oct) | 25.1.1.3 / 22.8R2.6 | 10 |
| CVE-2026-111357 | Ivanti Connect Secure | Chain component | — | **KEV 30 Oct** | 25.1.1.3 / 22.8R2.6 | 10 |
| CVE-2026-96652 | Plex Media Server (Plex2Shell) | RCE | — | **KEV 20 Oct** | Update Plex | 11 |
| CVE-2026-96654 | Plex Media Server (Plex2Shell) | RCE | — | **KEV 20 Oct** | Update Plex | 11 |
| CVE-2026-96655 | Plex Media Server (Plex2Shell) | RCE | 9.5 | **KEV 20 Oct** | Update Plex | 11 |
| CVE-2026-96656 | Plex Media Server (Plex2Shell) | RCE | — | **KEV 20 Oct** | Update Plex | 11 |
| CVE-2026-114625 | Arista VeloCloud Orchestrator | Zero-day | — | **Yes** (vendor); IPs published | 5.2.3.18 / 6.1.3.10 / 6.4.2.12 | 11 |
| CVE-2026-110447 | Collabora Online / Nextcloud CODE | RCE | — | **KEV 23 Oct** (since ~10 Sep) | Update CODE/Collabora | 11 |
| CVE-2026-88771 | Citrix NetScaler ADC/Gateway | Edge | — | **KEV 27 Sep/4 Oct** | 14.1-73.46 / 13.1-64.29+ | 11 |
| CVE-2026-88772 | Citrix NetScaler ADC/Gateway | Edge | — | **KEV** | 14.1-73.46 / 13.1-64.29+ | 11 |
| CVE-2026-88779 | Citrix NetScaler ADC/Gateway | Edge | — | **KEV** | 14.1-73.46 / 13.1-64.29+ | 11 |
| CVE-2026-0257 | Palo Alto PAN-OS | Edge (ransomware-linked) | — | **Yes** (Qilin/INC overlap) | PAN-OS fixed release | 11 |
| CVE-2026-0322 | Palo Alto PAN-OS | Edge | — | **KEV 14 Oct** | PAN-OS fixed release | 11 |
| CVE-2026-105133 | Ahsay AhsayCBS | Auth bypass (chained) | — | **KEV 14 Oct** | Vendor update | 11 |
| CVE-2026-105134 | Ahsay AhsayCBS | Chained critical | 10.0 | **KEV 14 Oct** | Vendor update | 11 |
| CVE-2026-106931 | SiteGuard | — | — | **KEV** | Vendor update | 11 |
| CVE-2026-110936 | Siemens Software Center | Local code exec (DLL search path) | 9.5 | **KEV 20 Oct** | Vendor update | 11 |
| CVE-2026-76302 | Splunk Enterprise | Critical | 9.9 | — | Splunk patch | 11 |
| CVE-2026-76531 | Splunk SOAR | Critical | 9.9 | — | Splunk patch | 11 |
| CVE-2026-97631 | EDK II (TianoCore) | PXE pre-boot code exec | Critical | Disclosed 22 Oct | Firmware update; restrict PXE | 11 |
| CVE-2026-108398 | .NET Framework | Disclosed pre-patch | — | Public details | Oct 2026 update | 06 |
| CVE-2026-102866 | SharePoint Server | Unauth EoP (critical) | — | Publicly disclosed | Oct 2026 update | 06 |
| CVE-2026-70571 | Exchange Server | Critical RCE | 8.1 | "Exploitation more likely" | Oct 2026 update | 06 |
| CVE-2026-70279 | Exchange Server | RCE | 9.3 | "Exploitation more likely" | Oct 2026 update | 06 |
| CVE-2026-70229 | Active Directory Domain Services | RCE (targets DC) | — | — | Oct 2026 update | 06 |
| CVE-2026-69802 | NDES | RCE | — | — | Oct 2026 update | 06 |
| CVE-2026-96934 / -88117 / -88119 / -88120 / -88171 | Windows DHCP Server | Critical RCE | — | — | Oct 2026 update | 06 |
| CVE-2026-100202 / -108460 | Message Queuing (MSMQ) | Critical RCE | — | — | Oct 2026 update | 06 |
| CVE-2026-105016 / -100219 | Microsoft QUIC | Critical RCE | — | — | Oct 2026 update | 06 |
| CVE-2026-88174 | Windows Deployment Services | Critical RCE | — | — | Oct 2026 update | 06 |
| CVE-2026-24858 | Fortinet FortiCloud SSO | Auth bypass (rogue admin) | 9.4 | 2026 abuse | Patch FortiCloud SSO | 02 |
| (Brotli OOB write) | Google Brotli library | Out-of-bounds write | — | Patched 21 Oct | Rebuild/patch dependents | 11 |
| (Linux kernel) | Linux kernel network stack | RCE | — | Public Oct | Patch kernels | 11 |
| (Node.js) | Node.js runtime | RCE + DNS/TLS validation | — | — | Supported security releases | 11 |

**Not a CVE but critical (campaigns / identity):** FortiBleed (Case 02), ConnectWise Cloud Backup (Case 03), LiteLLM 1.107.0 (Case 04), Binance/TraderTraitor (Case 01), OVHcloud CLI, Rank Math PRO, eMudhra weak CA keys.
