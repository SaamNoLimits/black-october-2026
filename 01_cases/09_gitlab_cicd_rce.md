# Case 09 — GitLab CI/CD unauth RCE (CVE-2026-97229 / CVE-2026-110264)

## Snapshot

| Field | Value |
|---|---|
| CVEs | **CVE-2026-97229** (unauthenticated RCE via a **regex overflow**) + **CVE-2026-110264** |
| Affected | GitLab **19.2 – 19.4** (CVE-2026-97229) |
| Fixed | **19.2.8, 19.3.5, 19.4.2** (patch released **12 October**) |
| Exploitation | **CISA KEV since 29 October 2026** |
| Why it's nasty | RCE in the **CI/CD control plane** = pipeline, runners, secrets, and software supply chain |

## What happened

GitLab patched an **unauthenticated remote code execution** flaw (**CVE-2026-97229**) — reported as a **regex overflow** path — affecting 19.2–19.4, fixed 12 October in 19.2.8 / 19.3.5 / 19.4.2. A companion CVE (**CVE-2026-110264**) was patched in the same window. CISA added CVE-2026-97229 to KEV on **29 October**, confirming real-world exploitation.

The severity isn't just "a server" — GitLab is often the **center of the software supply chain**: it holds source, CI/CD pipelines, runner credentials, deploy keys, and registry tokens. RCE here is a direct path to poisoning builds (compare Case 04) and reaching production.

## Attack chain → MITRE ATT&CK

| Phase | Technique | ID |
|---|---|---|
| Recon | Identify internet-facing GitLab | T1595 |
| Initial access | Exploit public-facing app (unauth RCE) | T1190 |
| Execution | Code execution on GitLab host | T1059 |
| Credential access (follow-on) | Steal CI/CD secrets, runner tokens, deploy keys | T1552.001 / T1552.004 |
| Supply chain (follow-on) | Tamper pipelines / artifacts | T1195.002 |

## Why it worked

- **Unauthenticated** reachability of a self-managed GitLab web tier.
- **Regex/DoS-class parsing bug** escalated to code execution.
- CI/CD platforms are **high-trust and credential-dense**.

## Indicators / hunting

- GitLab/Rails logs: anomalous requests to the affected endpoint; worker crashes/timeouts consistent with catastrophic regex backtracking.
- Post-exploit: new/modified **CI/CD variables**, runner registrations, personal/project access tokens; unexpected pipeline edits; outbound from the GitLab host.
- Review runner hosts for tampering and secret exfiltration.

## Mitigation

1. **Upgrade** self-managed GitLab to **19.2.8 / 19.3.5 / 19.4.2** (or later).
2. **Rotate** CI/CD secrets, runner tokens, deploy keys, and registry credentials on any instance exposed while unpatched.
3. Put the GitLab web tier **behind SSO/VPN**; don't expose it to the whole internet.
4. Audit pipelines and artifacts for tampering; pin/verify dependencies.
5. Treat CI/CD as **Tier-0**: isolate runners, least-privilege tokens, short TTLs.

## PoC / exploit status

KEV-listed. Use GitLab's **security release advisory** as the authoritative source; validate with `kevcheck` (GitLab ruleset keyed to the fixed versions). No exploit code is included here — RCE in a CI/CD hub is high-uplift.

## Red team takeaway

Owning CI/CD is the modern "domain admin." The exercise: can an unauthenticated attacker reach your GitLab, and if a runner is popped, how far do its tokens reach into prod and the registry? Scope your blast radius before the adversary does.

## Sources

See `08_references.md` → "Case 09." Primary: GitLab security release (12 Oct); CISA KEV (29 Oct); ceos3c Black October patch list; FireCompass weekly (19–25 Oct).
