# Case 05 — PHP2Shell: pre-auth RCE in the PHP runtime (CVE-2026-109618 / 109619)

## Snapshot

| Field | Value |
|---|---|
| CVEs | **CVE-2026-109618**, **CVE-2026-109619** — both CVSS **9.2** (Critical) |
| Fixed | PHP security release **21 October 2026** |
| Fixed versions | **8.5.12, 8.4.27, 8.3.36, 8.2.35** (then **restart PHP workers**) |
| Exploitation | Attempts observed from **17 October** (Amazon), 4 days *before* the fix; CISA **KEV 26 Oct** |
| Exposure | Underneath an estimated ~70% of web servers; worst with Apache `mod_php` |
| Family | Lead flaw of October's "2Shell" wave (also Plex2Shell, Broccoli2Shell, Fragnesia) |

## What happened

PHP2Shell is two memory-safety bugs in the PHP interpreter that give an **unauthenticated, remote attacker arbitrary code execution** — i.e., the vulnerability is in the *runtime itself*, not in a given application:

- **CVE-2026-109618:** a crafted **multipart request** can trigger the condition; with Apache `mod_php` it can occur **before any application code runs** (pre-auth, pre-routing).
- **CVE-2026-109619:** PHP retains **global state** pointing to request-owned memory. If that state isn't reset before the request memory is freed, a **later request on the same worker** can use the **stale state** before normal init — a use-after-free/stale-pointer path to RCE.

Both are CVSS 9.2 and were emergency-patched on **21 October 2026**. runZero/Amazon reported **exploitation attempts from 17 October** (before the patch), and CISA added both to **KEV on 26 October**. Because the flaw is in the interpreter, it cuts across WordPress, Drupal, and the long tail of custom PHP apps. Several operators did **precautionary website shutdowns**.

> Related in the same window: **Fragnesia (CVE-2026-46300)** was described as a path "from PHP2Shell to root," and **Broccoli2Shell (CVE-2026-111497)** extended the "2Shell" naming to another runtime. **Plex2Shell** (four CVEs, below) hit Plex Media Server.

## Attack chain → MITRE ATT&CK

| Phase | Technique | ID |
|---|---|---|
| Recon | Identify internet-facing PHP/`mod_php` | T1595 |
| Initial access / execution | Exploit public-facing app runtime (pre-auth RCE) | T1190 / T1203 |
| Execution | Arbitrary code as the web worker | T1059 |
| Persistence (typical follow-on) | Web shell | T1505.003 |
| Priv-esc (chained) | Fragnesia CVE-2026-46300 → root | T1068 |

## Why it worked

- **Memory-unsafe global/request-state handling** in a long-lived worker model (state bleeds across requests on a reused worker).
- **`mod_php` executes in the request path before app auth**, so "require login" protects nothing.
- **Ubiquity** — patch coordination across every PHP host is slow; attackers moved first.

## Indicators / hunting signals

There is no clean atomic IOC for a memory-corruption RCE; hunt **effects and anomalies**:

- Unusual **multipart/form-data** requests to endpoints that don't expect uploads; malformed/oversized multipart boundaries.
- `php-fpm` / Apache worker **crashes, segfaults, or respawns** correlated with inbound requests (check `mod_php` error logs, `dmesg`, coredumps).
- New files in web roots after suspicious requests (**web-shell** drop) — look for recently-modified `.php` with base64/`eval`/`system` patterns.
- Outbound connections from the web-server user.
- Use `05_detections/sigma/php2shell_exploit_attempt.yml` and `logtriage` (flags multipart anomalies + new `.php` in webroot).

## Mitigation

1. **Patch now** to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 — **updating is the only complete mitigation.**
2. **Restart PHP workers** (`php-fpm`, Apache) after patching — CVE-2026-109619 lives in worker global state; an un-restarted worker stays vulnerable.
3. Inventory **every** PHP install (containers, appliances, bundled stacks) — not just your flagship app. Use `kevcheck` with the bundled PHP ruleset.
4. Interim hardening (not a fix): WAF rules for anomalous multipart; reduce worker reuse (`pm.max_requests`); isolate/segment PHP hosts; watch for web-shell drops.
5. After patching, **assume-breach hunt** any host exposed between ~17 and patch time.

## PoC / exploit status

Actively exploited and KEV-listed. The authoritative technical write-ups are the **PHP project security release notes** and runZero's asset-discovery guidance. This package does **not** ship a working PHP2Shell exploit — for a pre-auth RCE under ~70% of the web, a drop-in PoC is pure attacker uplift. If you need to validate remediation, use your licensed scanner's authenticated version check or detonate the **vendor-referenced** PoC in an isolated lab; `kevcheck` verifies you're at/above the fixed version without touching an exploit.

## Red team takeaway

Runtime-level pre-auth RCE resets your assumptions: "authenticated-only" endpoints are exposed, and WAF virtual-patching is a delay, not a cure. The transferable exercise is **patch-velocity and inventory completeness** — can you find and fix *every* PHP worker in the estate within the days you actually have?

## Sources

See `08_references.md` → "Case 05." Primary: PHP project security release (21 Oct); runZero; CISA KEV (26 Oct); Valyu/SecurityWeek exploitation timeline; ceos3c (Fragnesia/Broccoli2Shell naming).
