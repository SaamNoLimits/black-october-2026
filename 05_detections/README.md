# 🛡️ Detections

<p align="center">
  <img src="https://img.shields.io/badge/Sigma-6-8957e5?style=flat-square" alt="6 Sigma rules">
  <img src="https://img.shields.io/badge/YARA-1-8957e5?style=flat-square" alt="1 YARA rule">
  <img src="https://img.shields.io/badge/Suricata-1%20ruleset-8957e5?style=flat-square" alt="Suricata ruleset">
  <img src="https://img.shields.io/badge/status-tune%20before%20prod-e3b341?style=flat-square" alt="tune before prod">
</p>

Ready-to-tune detection content for the October 2026 cases. Everything here is **defensive** — it finds the activity; it doesn&rsquo;t perform it. Treat each rule as a **starting point**: validate in test mode, fit field names to your schema, and allow-list your known-good before you alert.

---

## 📁 `sigma/` — SIEM detections

| Rule | Case | Catches |
|---|:---:|---|
| [`connectwise_m365_app_signin.yml`](sigma/connectwise_m365_app_signin.yml) | 03 | ConnectWise/SkyKick app-only sign-ins + credential/role grants in Entra |
| [`litellm_python_startup_hook.yml`](sigma/litellm_python_startup_hook.yml) | 04 | `cook.pth`/`cook.py` + `/tmp` markers + `litellm.dev` egress |
| [`php2shell_exploit_attempt.yml`](sigma/php2shell_exploit_attempt.yml) | 05 | web-shell drops / worker crashes after PHP2Shell exploitation |
| [`windows_shell_motw_bypass.yml`](sigma/windows_shell_motw_bypass.yml) | 06 | internet-origin files executing without a `Zone.Identifier` (MotW bypass) |
| [`fortigate_config_export.yml`](sigma/fortigate_config_export.yml) | 02 | FortiGate config export from an external IP + rogue local admin creation |
| [`binance_deploy_token_from_interactive.yml`](sigma/binance_deploy_token_from_interactive.yml) | 01 | a deploy credential used from an interactive (non-CI) session |

## 📁 `yara/` — file/host hunting

| Rule file | Case | Catches |
|---|:---:|---|
| [`litellm_privcollect_stealer.yar`](yara/litellm_privcollect_stealer.yar) | 04 | LiteLLM `privcollect` artifacts: startup-hook loader, host markers, known-bad SHA-256s |

## 📁 `suricata/` — network detections

| Ruleset | Covers |
|---|---|
| [`black-october.rules`](suricata/black-october.rules) | `litellm.dev` exfil (DNS/HTTP/POST), ConnectWise source IP, Arista attacker IPs, heuristic PHP2Shell multipart + Oracle EBS `/OA_HTML/` SQLi patterns |

---

## 🚦 Deploying safely

> [!WARNING]
> - **Tune first.** Several rules (PHP2Shell, the Binance deploy-token behavioral rule, the Suricata multipart heuristic) are **high-FP by design** — they surface candidates for a human, gated by `threshold:` or baselining. Don&rsquo;t page on them unmodified.
> - **Verify field/log IDs.** FortiGate `logid` values, Entra operation names, and k8s audit fields vary by version/schema — confirm against your own data.
> - **Pair with IOCs + scoping.** Load [`../04_iocs/iocs.csv`](../04_iocs/iocs.csv) alongside these, and scope each hunt to the exposure window in the matching [case file](../01_cases/).

## 🔗 Related

- [`../04_iocs/`](../04_iocs/) — the atomic indicators these rules reference
- [`../06_rust_tooling/`](../06_rust_tooling/) — `iocmatch` / `logtriage` for offline hunting over the same patterns
- [`../03_attack_mapping_mitre.md`](../03_attack_mapping_mitre.md) — ATT&CK techniques each rule covers

---

<p align="center"><sub><a href="../README.md">&larr; back to repository root</a></sub></p>
