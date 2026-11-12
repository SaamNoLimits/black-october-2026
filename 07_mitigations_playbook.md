# Black October 2026 — Mitigation & Hardening Playbook

Prioritized by exploitation status and blast radius. Work top-down. "KEV" = actively exploited.

## Tier 0 — do this week (actively exploited / internet-reachable)

| # | Action | Covers | Verify |
|---|---|---|---|
| 1 | Deploy Oct 2026 Windows cumulative update; **CVE-2026-96951** first | Case 06 | `kevcheck` Windows build; KEV cleared |
| 2 | Patch PHP → 8.5.12/8.4.27/8.3.36/8.2.35 **and restart workers** | Case 05 | `kevcheck` php-*; `php -v` on every host; workers restarted |
| 3 | Audit every M365 tenant for ConnectWise app IDs; strip rogue roles/secrets; hunt ≥13 Oct | Case 03 | Entra audit shows no app-only sign-ins / role grants by the app |
| 4 | Rotate all secrets on any host that ran **LiteLLM 1.107.0**; purge Docker tags | Case 04 | `iocmatch --scan`; registries clean; secrets rotated |
| 5 | Remove FortiGate mgmt/SSL-VPN from internet; rotate all creds; enforce MFA | Case 02 | No mgmt plane on internet; MFA on; local accounts audited |
| 6 | Upgrade Cisco ASA/FTD to fixed release (no full workaround) | Case 08 | `kevcheck` cisco-*; device on fixed train |
| 7 | Upgrade GitLab → 19.2.8/19.3.5/19.4.2; rotate CI secrets | Case 09 | `kevcheck` gitlab; tokens rotated |
| 8 | Upgrade Ivanti Connect Secure → 25.1.1.3/22.8R2.6; run ICT | Case 10 | ICT clean or appliance rebuilt |
| 9 | Apply Oracle Oct CPU to EBS 12.2.3–12.2.15 (MOS KA923) | Case 07 | `kevcheck` oracle-ebs; EBS web tier not internet-unauth |
| 10 | Patch Plex, Citrix NetScaler, PAN-OS, Collabora/Nextcloud CODE, Arista VeloCloud, AhsayCBS, Cisco ESG, Siemens Software Center | Case 11 | Each on fixed version; KEV cleared |

## Tier 1 — this month (high value, patch broadly)

- Internet-exposed **Exchange** (CVE-2026-70571/70279), **SharePoint** (CVE-2026-102866), **AD DS** (CVE-2026-70229), **NDES**, **DHCP**, **MSMQ**, **QUIC** — from the October Patch Tuesday set.
- **Splunk** Enterprise/SOAR (CVE-2026-76302/76531, CVSS 9.9) — your monitoring plane.
- OSS foundations that hide in dependency trees: **Brotli** OOB write, **Node.js** security releases, **Linux kernel** network-stack RCE, **EDK II** PXE (CVE-2026-97631, firmware). Drive via SBOM/dependency and firmware pipelines, not just the asset DB.
- Ensure browser/OS **trust-store updates** are applied (eMudhra weak-key revocations).

## Tier 2 — structural fixes the month argued for

These address the *root causes*, not individual CVEs. They're where the leverage is.

**Identity & credentials**
- Replace standing/long-lived deploy tokens with **short-lived, hardware-bound, per-action** credentials (WebAuthn/FIDO2, HSM-backed signing). *(Binance)*
- Require **out-of-band, transaction-bound human approval** for high-value actions (signing, mass withdrawal, mass deploy). *(Binance)*
- Inventory **all third-party enterprise apps** and their OAuth scopes; least-privilege and per-tenant registrations; alert on new service-principal credentials and privileged role grants. *(ConnectWise)*
- Enforce **MFA** on every VPN, admin, and remote-access surface; kill password reuse. *(FortiBleed)*

**Supply chain & developer environment**
- Treat **developer laptops and CI/CD as Tier-0**: PAWs/isolation, app allow-listing, no ad-hoc installs, production-grade monitoring. *(Binance, GitLab, LiteLLM)*
- Pin dependencies; require **signed releases / provenance** (PEP 740, Sigstore) where available; scan for **install-time execution** (`.pth`, `sitecustomize.py`) in CI and image builds. *(LiteLLM, OVHcloud CLI)*
- Never commit secrets; enforce secret scanning + **mandatory rotation on exposure** (the LiteLLM root cause was a 5-month-old committed master key). *(LiteLLM)*
- Policy: **never run interview/take-home code on corporate assets.** *(Binance "contagious interview")*

**Exposure surface**
- Get management planes and admin portals **off the public internet** (VPN/ZTNA front).
- Patch-velocity SLA for **unauth + internet-facing** CVEs measured in **days** — October's edge bugs were exploited within days of (or before) the fix.

## Authorized red-team exercises this month justifies

1. **Workstation-trust + social-engineering assessment** (contagious-interview lure; can a popped laptop's credentials reach production?). *(Binance)*
2. **Third-party app blast-radius review** (if one vendor service principal's secret leaks, what's exposed?). *(ConnectWise)*
3. **Supply-chain tabletop** (find a committed secret → could it reach a release pipeline? Can you detect install-time execution?). *(LiteLLM)*
4. **Edge exposure + patch-SLA drill** (enumerate internet-facing PHP/EBS/VPN/CI; prove patch velocity and management-plane isolation). *(Cases 05/07/08/09/10)*
5. **Phishing-simulation with MotW-bypass delivery**; measure detection at "file opened, no warning." *(Case 06)*

Run these with explicit written authorization and scope. None require the weaponized exploits this package omits.

## How the Rust tooling plugs in

- **kevcheck** → drives Tier 0/1 patch verification from your inventory (exit 3 gates CI).
- **iocmatch** → hunts the atomic IOCs across logs and collected file trees.
- **logtriage** → first-pass review of web/access logs for the exploitation patterns above.

See `06_rust_tooling/README.md`.
