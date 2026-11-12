# References — Black October 2026

All sources are public (TLP:CLEAR). Primary/vendor sources are listed first per case. Retrieved 12 November 2026; several incidents were still developing — re-check vendor advisories and CISA KEV for updates. Where reporting disagreed on figures, the case files flag the spread.

## General / month roundups
- SOCRadar — "October 2026: Binance Heist, ConnectWise Breach, and More" — https://socradar.io/blog/major-cyber-attacks-october-2026/
- Loginsoft — "October 2026 Cyberattacks: 27 Major Breaches & Threats" — https://www.loginsoft.com/post/october-2026-cyberattacks-major-breaches-threats
- Unosecur — "Black October 2026: Cyberattacks, Breaches and Incidents" — https://www.unosecur.com/blog/october-2026-cybersecurity-incidents
- PlayCISO — "October 2026 Cyber Attacks & Data Breaches: Full List" — https://playciso.com/blog/october-2026-cybersecurity-breaches-roundup
- Secucenter — "Black October 2026: Biggest Cyberattacks List" — https://www.secucenter.com/blog/black-october-2026-biggest-cyberattacks-list/
- Cyberinfos — "Top 10 Cybersecurity Incidents in October 2026" — https://www.cyberinfos.in/top-10-cybersecurity-incidents-in-october-2026/
- Wikipedia — "Black October (information security)" — https://en.wikipedia.org/wiki/Black_October_(information_security)
- CISA KEV catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CVE Brief (24 Oct 2026) — https://cvebrief.com/archive/2026/10/24/
- FireCompass weekly (19–25 Oct 2026) — https://firecompass.com/weekly-report-new-hacking-techniques-and-critical-cves-19-oct-to-25-oct-2026/
- Valyu — "Actively Exploited Vulnerabilities: Oct 2026 Report" — https://www.valyu.ai/blogs/actively-exploited-vulnerabilities-report

## Case 01 — Binance / TraderTraitor
- Palo Alto Networks Unit 42 — "How a Developer Endpoint Became the Path to Binance's $6.3B Heist" — https://www.paloaltonetworks.com/blog/security-operations/how-a-developer-endpoint-became-the-path-to-binances-6-3b-heist/
- Security Boulevard — "The Binance Hack — The 6 Billion Dollar Man" — https://securityboulevard.com/2026/11/the-binance-hack-the-6-billion-dollar-man/
- brside — "How the Binance Hack Happened: From a Search Ad to $6.3 Billion" — https://www.brside.com/blog/how-binance-hack-happened-search-ad-to-6-3-billion
- Hackread — "Binance Probes DevOps Engineer's Hacked Laptop After $6.3B Theft" — https://hackread.com/binance-devops-engineer-hacked-laptop-billion-theft/
- CoinCentral — "How Attackers Spent Months Inside Wallet Engineers' Computers" — https://coincentral.com/binance-hack-how-attackers-spent-months-inside-wallet-engineers-computers-before-striking
- FBI/USSS/IRS-CI alert (31 Oct 2026) via IC3 — https://www.ic3.gov/
- Wikipedia — "2026 Binance hack" — https://en.wikipedia.org/wiki/Binance

## Case 02 — FortiBleed
- FBI/USSS Joint CSA (6 Oct 2026) — https://www.ic3.gov/CSA/2026/261006.pdf
- Recorded Future — "FortiBleed Campaign Exposing Credentials for 73,932 FortiGate Systems" — https://www.recordedfuture.com/blog/critical-fortibleed-campaign
- Sophos advisory — https://www.sophos.com/en-us/security-advisories/fortinet-fortibleed-credential-exposure-and-sophos-vpn-bruteforcing-campaign
- Trend Micro security alert (KA-0023852) — https://success.trendmicro.com/en-US/solution/KA-0023852
- Aviatrix Threat Research — FBI FortiBleed warning — https://aviatrix.ai/threat-research-center/fbi-warns-fortibleed-remains-active-2026/
- CyPro — "k0t Campaign Targets FortiGate and GlobalProtect" — https://cypro.co.uk/insights/cyber-bulletins/k0t-campaign-targets-fortigate-and-globalprotect/
- daily.dev — "October 2026 CVE Landscape" (Unit 42 CL-STA-0954, FortiManager/FortiOS) — https://daily.dev/posts/october-2026-cve-landscape-ktrcyt7c5

## Case 03 — ConnectWise Cloud Backup (SkyKick)
- ConnectWise Trust advisories — https://www.connectwise.com/company/trust/advisories
- BleepingComputer — "Hackers breach Microsoft 365 tenants via ConnectWise supply-chain attack" — https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/
- Huntress (via Dark Reading) — https://www.darkreading.com/identity-access-management-security/connectwise-disables-cloud-backups-downstream-msps
- SpecterOps — https://specterops.io/blog/2026/10/17/connectwise-skykick-breach-microsoft-365/
- Field Effect — https://fieldeffect.com/blog/connectwise-cloud-backup-identities
- Quisitive (app IDs, source IP) — https://quisitive.com/ (18 Oct 2026)
- WatchGuard Red Cell — https://www.watchguard.com/node/124336
- Rescana analysis — https://www.rescana.com/post/connectwise-cloud-backup-supply-chain-attack-analysis-of-microsoft-365-tenant-compromise-and-mitigation-strategies
- CSO Online — https://www.csoonline.com/article/4237087/connectwise-backup-credentials-exposed-multiple-microsoft-365-tenants.html

## Case 04 — LiteLLM 1.107.0
- LiteLLM postmortem (BerriAI/litellm issue #47826, 24 Oct) — https://github.com/BerriAI/litellm
- Datadog Security Labs — https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-docker/
- The Register (21 Oct) — https://www.theregister.com/security/2026/10/21/litellm-supply-chain-attack-hoovers-up-passwords-and-secrets/
- The Register (26 Oct, master-key root cause) — https://www.theregister.com/security/2026/10/26/litellm-supply-chain-attack-started-with-an-exposed-master-key/
- The Hacker News — https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html
- Help Net Security — https://www.helpnetsecurity.com/2026/10/22/litellm-compromised-supply-chain-attack-pypi-docker/
- Gurucul (hashes) — https://gurucul.com/blog/inside-the-litellm-supply-chain-attack-unmasking-the-credential-stealer/
- Kodem (IOCs / runbook) — https://www.kodemsecurity.com/resources/litellm-supply-chain-attack-litellm-1-107-0-affected-versions-iocs-and-first-hour-response-runbook
- Brandefense — https://brandefense.io/security-news/litellm-1-107-0-supply-chain-attack-what-to-do/

## Case 05 — PHP2Shell (CVE-2026-109618 / 109619)
- PHP Project security release (21 Oct 2026) — https://www.php.net/
- runZero — "Critical RCE vulnerability in PHP: Find impacted assets" — https://www.runzero.com/blog/php/
- ceos3c — "Critical Vulnerabilities October 2026" (Fragnesia, Broccoli2Shell) — https://www.ceos3c.com/security/critical-vulnerabilities-october-2026/
- CISA KEV (added 26 Oct 2026)

## Case 06 — Windows Shell MotW (CVE-2026-96951) + Patch Tuesday
- Microsoft MSRC Security Update Guide (Oct 2026) — https://msrc.microsoft.com/update-guide/
- Splashtop — "October 2026 Patch Tuesday breaks the CVE record again" — https://www.splashtop.com/blog/patch-tuesday-october-2026
- SecPod — https://www.secpod.com/learn/security-research/two-zero-days-1-407-microsoft-flaws-fixed-october-2026-patch-tuesday-delivers-a-massive-update
- TechTimes — https://www.techtimes.com/articles/329061/20261015/microsoft-patch-tuesday-october-2026-record-1413-cves-one-already-under-attack.htm
- Shattered.io — https://shattered.io/microsoft-patch-tuesday-october-2026-1413-cves/

## Case 07 — Oracle EBS (CVE-2026-101767)
- Oracle Critical Patch Update Advisory (Oct 2026); MOS note KA923 — https://www.oracle.com/security-alerts/
- SecurityWeek — "Hackers Start Probing Fresh Oracle EBS Vulnerability" — https://www.securityweek.com/hackers-start-probing-fresh-oracle-ebs-vulnerability/
- Horizon3.ai advisory (discoverer; IOCs) — https://www.horizon3.ai/
- Rescana — https://www.rescana.com/post/oracle-e-business-suite-cve-2026-101767-prepare-now
- Tuskira — https://www.tuskira.ai/advisories/cve-2026-101767
- R3KONX (servlet / URL-firewall analysis) — https://r3konx.asia/oracle-october-2026-cpu-ebs-cve-2026-101767-default-allowlisted-servlet/

## Case 08 — Cisco ASA/FTD (CVE-2026-76418)
- Cisco advisory `cisco-sa-asaftd-tunnel-dos-s6mgkb75` (28 Oct 2026) — https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tunnel-dos-s6mgkb75
- BleepingComputer — https://www.bleepingcomputer.com/news/security/cisco-warns-of-firewall-zero-day-exploited-to-crash-ssl-vpn-devices/
- SOC Prime — https://socprime.com/blog/cve-2026-76418-cisco-secure-firewall-zero-day/
- SecPod — https://www.secpod.com/learn/security-research/cisco-firewall-zero-day-under-attack-hackers-exploit-ssl-vpn-flaw-to-crash-asa-and-ftd-devices
- CISA KEV (added 29 Oct 2026)

## Case 09 — GitLab (CVE-2026-97229 / 110264)
- GitLab security release (12 Oct 2026) — https://about.gitlab.com/releases/
- ceos3c Black October patch list — https://www.ceos3c.com/security/critical-vulnerabilities-october-2026/
- CISA KEV (added 29 Oct 2026)

## Case 10 — Ivanti Connect Secure (CVE-2026-104935 chain / UTA0576)
- Ivanti security advisory — https://www.ivanti.com/blog/security-advisories
- PlayCISO (CVE-2026-111357 chain, KEV 30 Oct) — https://playciso.com/blog/october-2026-cybersecurity-breaches-roundup
- CISA KEV (added 30 Oct 2026)

## Case 11 — Vulnerability & breach wave
- CVE Brief (24 Oct) — Plex2Shell, Arista VeloCloud, Siemens Software Center, Splunk — https://cvebrief.com/archive/2026/10/24/
- FireCompass weekly (19–25 Oct) — Arista IPs, 8 KEV adds — https://firecompass.com/weekly-report-new-hacking-techniques-and-critical-cves-19-oct-to-25-oct-2026/
- Valyu actively-exploited report — Citrix, PAN-OS, AhsayCBS, Cisco ESG — https://www.valyu.ai/blogs/actively-exploited-vulnerabilities-report
- daily.dev CVE landscape — PAN-OS CVE-2026-0257 (Qilin/INC) — https://daily.dev/posts/october-2026-cve-landscape-ktrcyt7c5
- Wikipedia "Black October" — Brotli, EDK II CVE-2026-97631, Linux kernel, eMudhra — https://en.wikipedia.org/wiki/Black_October_(information_security)
- Secucenter / Cyberinfos — eMudhra, Operation FlashHole, OVHcloud CLI, Rank Math PRO — (see General)

---

### Citation discipline note
This package paraphrases and attributes; it does not reproduce source text. Vendor advisories are the authoritative record for versions, timelines, and IOCs — always prefer them over secondary reporting, and confirm KEV status before deprioritizing any item.
