# 🧬 Indicators of Compromise

<p align="center">
  <img src="https://img.shields.io/badge/indicators-21-e5534b?style=flat-square" alt="21 indicators">
  <img src="https://img.shields.io/badge/format-CSV-1f6feb?style=flat-square" alt="CSV">
  <img src="https://img.shields.io/badge/TLP-CLEAR-2ea043?style=flat-square" alt="TLP:CLEAR">
  <img src="https://img.shields.io/badge/consumed%20by-iocmatch-dea584?style=flat-square&logo=rust&logoColor=white" alt="iocmatch">
</p>

**[`iocs.csv`](iocs.csv)** holds the atomic, machine-readable indicators from October 2026 that are safe and useful to operationalize. One row per indicator, seven columns:

```
indicator,type,case,context,first_seen,confidence,source_note
```

| Column | Meaning |
|---|---|
| `indicator` | the atomic value to match (IP, domain, hash, path, app ID…) |
| `type` | indicator class — see the table below |
| `case` | which [case file](../01_cases/) it ties to (e.g. `04` = LiteLLM) |
| `context` | one line on what it is / where it was seen |
| `first_seen` | earliest reported date — anchor your hunt window to it |
| `confidence` | `high` / `medium`, **as reported** by the source |
| `source_note` | who published it |

---

## 📇 What&rsquo;s in here (by type)

| Type | Count | Match against… |
|---|:---:|---|
| `container_tag` | 4 | image registries, CI pull logs, runtime inventories |
| `sha256` | 3 | file / EDR telemetry (`iocmatch --scan` hashes files for you) |
| `ipv4` | 3 | firewall, proxy, netflow, VPN auth logs |
| `filename` | 3 | endpoint file inventories, site-packages |
| `filepath` | 2 | endpoint file inventories (absolute + basename) |
| `entra_app_id` | 2 | Entra ID sign-in & audit logs (service-principal auth) |
| `url` | 1 | proxy / web logs |
| `package` | 1 | SBOM, `pip`/dependency inventories |
| `github_account` | 1 | VCS audit logs |
| `domain` | 1 | DNS / proxy logs |

---

## 🚀 How to use

**With the Rust toolkit** (zero dependencies — see [`../06_rust_tooling/`](../06_rust_tooling/)):

```bash
# text indicators (IPs, domains, URLs, paths) against a log:
iocmatch --iocs 04_iocs/iocs.csv --logs /var/log/nginx/access.log

# hash + filename match a collected/quarantined file tree:
iocmatch --iocs 04_iocs/iocs.csv --scan /path/to/suspect/dir
```

**With your SIEM/EDR:** import as a watchlist and map by type —

- `ipv4` / `domain` / `url` → network, proxy, DNS logs
- `sha256` → file / EDR telemetry
- `entra_app_id` → Entra ID sign-in & audit logs (app-only sign-ins)
- `filename` / `filepath` → endpoint file inventory

**Scope each hunt to the exposure window** from the matching [case file](../01_cases/) — e.g. ConnectWise **≥ 13 Oct**; LiteLLM **21 Oct 11:39–14:20 UTC**.

---

## ⚠️ Caveats (read before blocking)

> [!WARNING]
> 1. **Context-sensitive filenames.** `sitecustomize.py` is a *legitimate* Python filename — only the malicious variant inside `litellm==1.107.0` is an IOC. Match on **hash/path context**, not the bare name.
> 2. **Domain look-alikes.** The LiteLLM exfil domain is **`litellm.dev`** — the legitimate project is **`litellm.ai`**. Don&rsquo;t block the wrong one.
> 3. **Credential campaigns have few atomic IOCs.** FortiBleed, Binance/TraderTraitor, and the Cisco ASA DoS are behavioral — use the [detections](../05_detections/) and each case&rsquo;s guidance instead. TraderTraitor blockchain addresses shift as laundering continues; pull the current set from the FBI/USSS/IRS-CI IC3 alert rather than hardcoding them.
> 4. **Confidence is as-reported.** Corroborate `medium` entries before blocking.
> 5. **TLP:CLEAR.** Re-validate against the cited source before taking blocking action in production.

---

<p align="center"><sub><a href="../README.md">&larr; back to repository root</a></sub></p>
