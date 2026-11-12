# Case 11 — The Black October Vulnerability & Breach Wave (roundup)

The marquee cases have their own files. This roundup covers the rest of the month's technically significant activity so the package is complete. Treat it as a hunt/patch checklist; confirm KEV status before deprioritizing anything.

## 11.1 The rest of the "2Shell" / exploited-CVE cluster

| CVE(s) | Product | Type | Exploited? | Fixed / action |
|---|---|---|---|---|
| **CVE-2026-96652/96654/96655/96656** (Plex2Shell) | Plex Media Server | RCE cluster | **Yes** — Plex confirmed widespread exploitation 19 Oct; KEV 20 Oct | Update Plex Media Server |
| **CVE-2026-114625** | Arista VeloCloud Orchestrator | zero-day | **Yes** — vendor "actively exploited"; published attacker IPs `74.82.197.86`, `38.54.50.151` | 5.2.3.18 / 6.1.3.10 / 6.4.2.12 |
| **CVE-2026-110447** | Collabora Online / Nextcloud built-in CODE server | RCE | **Yes** — exploited since ~10 Sep; KEV 23 Oct | Update CODE/Collabora |
| **CVE-2026-88771/88772/88779** | Citrix NetScaler ADC & Gateway | edge | **Yes** — since early Sep; KEV 27 Sep & 4 Oct | 14.1-73.46 / 13.1-64.29+ (covers CVE-2026-107406) |
| **CVE-2026-0257** / **CVE-2026-0322** | Palo Alto PAN-OS | edge | **Yes** — CVE-2026-0257 linked to Qilin/Settra/Tarnished Scorpius (overlaps INC Ransom), BloodHound/SharpHound seen; 0322 KEV 14 Oct | PAN-OS fixed releases |
| **CVE-2026-105133 / CVE-2026-105134** | Ahsay AhsayCBS | auth bypass (10.0) chained | **Yes** — KEV 14 Oct | Vendor update |
| **CVE-2026-76519** | Cisco Secure Email Gateway | root flaw | **Yes** — KEV 14 Oct | 15.5.5-014 / 16.5.0-780; no workaround |
| **CVE-2026-106931** | SiteGuard | — | **Yes** — KEV | Vendor update |
| **CVE-2026-110936** | Siemens Software Center | local code exec via malicious DLL (search-path) | **Yes** — KEV 20 Oct | Vendor update |
| **CVE-2026-76302** / **CVE-2026-76531** | Splunk Enterprise / Splunk SOAR | CVSS 9.9 | Critical (monitoring infra at risk) | Splunk patches |
| **CVE-2026-101809** | Oracle EBS Workflow | critical | see also Case 07 | Oct CPU |
| **CVE-2026-46300** (Fragnesia) | PHP-adjacent | "PHP2Shell → root" priv-esc | wave | Patch (see Case 05) |
| **CVE-2026-111497** (Broccoli2Shell) | runtime | RCE | wave | Vendor update |

## 11.2 Foundational open-source flaws (patch broadly)

- **Brotli out-of-bounds write** — patched **21 Oct 2026** in Google's open-source Brotli compression library. Brotli is embedded *everywhere* (browsers, servers, language runtimes); an OOB write in a decompressor is a wide supply-chain exposure. Rebuild/patch anything vendoring Brotli.
- **EDK II PXE pre-boot code execution — CVE-2026-97631** — disclosed **22 Oct 2026** by TianoCore; critical flaw in the EDK II firmware network-boot (PXE) driver. Pre-boot/firmware code exec is below the OS and the security stack. Patch firmware; restrict/segment PXE.
- **Linux kernel network-stack RCE** — a remote code execution vuln in the Linux kernel network stack was made public in October 2026. Patch kernels on a priority track, especially for internet-facing Linux.
- **Node.js runtime security releases** — RCE and DNS/TLS-validation risks; install the supported security releases.

## 11.3 Trust-infrastructure failure

- **eMudhra weak intermediate CA keys** — on **17 Oct** a researcher found **eight intermediate CA certificates** operated by eMudhra had cryptographically weak private keys (poor randomness). Chrome and Firefox blocked the keys; eMudhra **exited the global TLS market on 22 Oct**. Risk: HTTPS impersonation / traffic interception if a weak key were factored. Action: ensure browser/OS trust-store updates are applied.

## 11.4 Other supply-chain / credential incidents

- **OVHcloud CLI** (advisory 20 Oct; attack 19 Oct): hijacked GitHub release binaries distributed through a trusted channel, exposing credentials on systems that ran the artifacts. Replace affected builds; revoke exposed creds.
- **Rank Math PRO** (15–16 Oct): malware in plugin downloads; remove affected files, investigate persistence.
- **TeamUpdraft / UpdraftCentral**: stolen management connection keys → unauthorized accounts / malicious plugins on connected sites. Revoke old keys; inspect sites.
- **GitHub credential-abuse campaign** (late Oct): widespread abuse of compromised developer credentials.
- **Tailscale**: fixes for vulnerabilities affecting access-control boundaries — update clients.
- **Warp**: security incident involving AI-agent telemetry.

## 11.5 Major data breaches / extortion (October 2026)

| Victim | What | Date |
|---|---|---|
| **Pentagon DMDC** | 3.05M records exposed | Oct |
| **Sony** | major customer data breach confirmed | late Oct |
| **Quest Diagnostics** | unauthorized access to patient records (Quanum Lab Services Manager); 8-K 21 Oct | Oct |
| **Denmark population register** | ~8.8M records accessed | Oct |
| **Nikkei** | stolen credentials → 1.83M records (cloud dev service, accessed 7 Oct) | Oct |
| **Ahold Delhaize** | retail sites/apps offline after intrusion (disclosed 12 Oct) | Oct |
| **Revolve** | saved payment card numbers/expiry possibly taken; 8-K 29 Oct | Oct |
| **ETS, Zeabur, Railway, Burger King Japan, GMO Onamae, SBI, India CBFC (e-Cinepramaan)** | assorted breaches / cloud intrusions | Oct |

**Ransomware tempo:** HackerFeeds counted **1,127** leak-site victims in October (**+25.8%** vs. September's 896). CISA/FBI/USSS issued a joint advisory on **SafePay** ransomware (20 Oct).

## 11.6 OT / espionage

- **French supermarket refrigeration sabotage** — Iran-linked remote tampering with supermarket refrigeration systems; an OT/ICS availability-and-safety attack on retail cold chains.
- **IDCF Cloud (Japan)** — ransomware disrupting a cloud platform's day-to-day operations.
- **Operation FlashHole** — Lazarus-linked cyber-espionage targeting South Korean organizations (phishing/malware/persistence).

## Cross-cutting hunting actions

1. Feed the published atomic IOCs (Arista IPs, ConnectWise/LiteLLM indicators) into SIEM/EDR — see `04_iocs/iocs.csv`.
2. Run `kevcheck` against your inventory for every CVE in §11.1 plus the marquee cases.
3. For OSS foundations (Brotli, Node.js, Linux kernel, EDK II), drive dependency/firmware patching — these don't show up as a single product in your asset DB.

## Sources

See `08_references.md` → "Case 11." Primary: CISA KEV; CVE Brief (24 Oct); FireCompass weekly (19–25 Oct); Valyu actively-exploited report; Wikipedia "Black October (information security)"; unosecur / loginsoft / secucenter / playciso roundups.
