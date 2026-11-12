# Executive Summary — Black October 2026

**Bottom line:** October 2026 was defined less by exotic zero-days than by **trust being turned into a weapon** — compromised developer laptops, poisoned software releases, stolen vendor API keys, and reused firewall passwords. The month's two biggest events (the Binance heist and the ConnectWise breach) involved **no product vulnerability at all**. The exploited vulnerabilities that did matter clustered around **internet-facing edge devices and unauthenticated web runtimes**.

## The month in numbers

| Metric | Value | Source |
|---|---|---|
| Stolen from Binance in one night | ~$6.34 billion (across 10 blockchains, ~20 min) | Palo Alto Networks / FBI |
| Fortinet devices with harvested credentials (FortiBleed) | 86,644 across 194 countries | FBI/USSS advisory |
| Microsoft CVEs fixed in October Patch Tuesday | 1,413 (78 critical, 1 exploited zero-day) | Microsoft / Splashtop |
| Microsoft 365 tenants hit via ConnectWise | 173+ (some reporting: 300+) | ConnectWise / Huntress |
| LiteLLM weekly downloads at time of poisoning | ~23 million | Datadog Security Labs |
| Ransomware leak-site victims in October | 1,127 (up 25.8% vs. September) | HackerFeeds |
| CISA KEV additions, 19–25 Oct alone | 8 (all confirmed exploited) | CISA / FireCompass |

## The five things that actually mattered

1. **The developer workstation is now production.** North Korea's TraderTraitor spent five months inside Binance wallet engineers' laptops — entering through a trojanized Homebrew-style install and a fake job interview — then abused an **internal AI tool** to pivot between machines and ride a standing container-deploy token into the wallet signing service. A laptop holding a production token *is* production.

2. **Your SaaS backup vendor has god-mode in your tenant.** A single stolen ConnectWise Cloud Backup (formerly SkyKick) application credential let attackers authenticate **as the app** into 173+ Microsoft 365 tenants and, in some, self-assign directory roles. No user password was phished; the OAuth consent was already granted.

3. **Supply-chain poisoning went for the AI toolchain.** LiteLLM 1.107.0 shipped to PyPI and Docker for ~2 hours carrying a credential stealer ("privcollect") that ran from a Python **startup hook** (`.pth`) — executing before any `import` and surviving package removal. OVHcloud CLI and Rank Math PRO were hit in the same window. Root cause: a master key committed to a public repo in May and never revoked.

4. **"2Shell" — unauthenticated RCE in the web runtime itself.** PHP2Shell (CVE-2026-109618/109619, CVSS 9.2) put pre-auth RCE in the PHP interpreter underneath ~70% of the web. Exploitation attempts preceded the fix; CISA added both to KEV. Plex2Shell, Broccoli2Shell and Fragnesia rode the same wave.

5. **Edge devices stayed the front line.** Microsoft's lone exploited zero-day was a **Windows Shell Mark-of-the-Web bypass** (CVE-2026-96951) — the third such MotW zero-day in 2026. Cisco ASA/FTD (CVE-2026-76418), Ivanti Connect Secure (CVE-2026-104935 chain), GitLab CI/CD (CVE-2026-97229), Oracle EBS (CVE-2026-101767), Arista VeloCloud and Citrix NetScaler all saw real-world exploitation.

## What I'd tell the board

- **Identity and the supply chain are the perimeter now.** Two of the three largest incidents bypassed every network control because the attacker arrived as a trusted app or a trusted employee. Short-lived, hardware-bound credentials would have blunted both the Binance and ConnectWise outcomes.
- **Patch velocity on edge/unauth bugs is non-negotiable.** Oracle EBS was probed within a week of the fix; PHP2Shell was hit *before* it. The gap between disclosure and mass exploitation is now measured in days.
- **Developer and CI/CD environments need production-grade monitoring.** The runners, the laptops, and the package registries are where October's worst days started.

## Top 10 priority actions (full detail in `07_mitigations_playbook.md`)

1. Patch **CVE-2026-96951** (Windows Shell MotW) everywhere — it leads phishing delivery.
2. Patch/restart PHP to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (**PHP2Shell**), restart workers after.
3. Audit every M365 tenant for the **ConnectWise Cloud Backup** app ID and any role grants since 13 Oct.
4. Rotate every secret any host that ran **LiteLLM 1.107.0** could read; purge the Docker tags.
5. Get internet-facing **FortiGate** management/SSL-VPN off the public internet; rotate all creds; enforce MFA.
6. Upgrade **Cisco ASA/FTD** to fixed releases (no full workaround for CVE-2026-76418).
7. Patch **GitLab** to 19.2.8 / 19.3.5 / 19.4.2 (KEV since 29 Oct).
8. Patch **Ivanti Connect Secure** to 25.1.1.3 / 22.8R2.6 (UTA0576 chain).
9. Apply **Oracle October CPU** to EBS 12.2.3–12.2.15 (unauth SQLi→RCE, CVSS 9.8).
10. Hunt the whole estate with `04_iocs/iocs.csv` + the Rust `iocmatch`/`logtriage` tools.
