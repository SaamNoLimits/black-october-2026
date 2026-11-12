# 🦀 Black October 2026 — Defensive Rust Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Rust-std--only-dea584?style=flat-square&logo=rust&logoColor=white" alt="Rust std-only">
  <img src="https://img.shields.io/badge/dependencies-0-2ea043?style=flat-square" alt="zero dependencies">
  <img src="https://img.shields.io/badge/builds-offline-1f6feb?style=flat-square" alt="builds offline">
  <img src="https://img.shields.io/badge/tools-3-8957e5?style=flat-square" alt="3 tools">
  <img src="https://img.shields.io/badge/posture-defensive-e5534b?style=flat-square" alt="defensive">
</p>

Three small, **dependency-free (std-only)** command-line tools for working the October 2026 cases. They are strictly defensive: they read **your** inventory, logs, and files **locally** and report findings. Nothing here scans, attacks, or contacts a third party.

```
06_rust_tooling/
├── Cargo.toml                 workspace (resolver 2, release profile)
├── data/
│   ├── october2026_kev.tsv    fixed-version ruleset for kevcheck
│   ├── sample_inventory.csv   example inventory
│   └── sample_access.log      example web log
└── crates/
    ├── kevcheck/              inventory vs. fixed-version triage
    ├── iocmatch/              IOC matcher (+ in-crate SHA-256)
    └── logtriage/             web/access-log heuristics
```

---

## ⚙️ Build & test

```bash
cd 06_rust_tooling
cargo build --release      # no external crates — builds offline
cargo test                 # version-compare, SHA-256 test vectors, log heuristics
```

Binaries land in `target/release/{kevcheck,iocmatch,logtriage}`. No network, no registry, nothing to vet in a dependency tree.

---

## 🧰 Tools at a glance

| Tool | Question it answers | Reads | Exit code |
|---|---|---|:---:|
| [`kevcheck`](#-kevcheck) | &ldquo;Am I below the fixed version?&rdquo; | inventory CSV + ruleset TSV | `3` if any asset is below its fix |
| [`iocmatch`](#-iocmatch) | &ldquo;Do these indicators appear in my data?&rdquo; | [`iocs.csv`](../04_iocs/iocs.csv) + logs/dirs | `3` on any hit |
| [`logtriage`](#-logtriage) | &ldquo;Which log lines deserve a human?&rdquo; | web/access log | `3` if any line flagged |

Non-zero exit codes mean you can gate CI/CD on any of these.

---

## 🔎 `kevcheck`

Compares an asset inventory against the October 2026 fixed-version ruleset and flags anything below the fix. Pure local version arithmetic — it never touches the asset.

```bash
./target/release/kevcheck --rules data/october2026_kev.tsv --inventory data/sample_inventory.csv
./target/release/kevcheck --inventory data/sample_inventory.csv --only-vuln   # just the findings
```

- **Inventory CSV:** `asset_id,product_key,version`
- **Ruleset TSV:** `product_key <TAB> cve <TAB> fixed_version <TAB> severity <TAB> note`
- Extend [`data/october2026_kev.tsv`](data/october2026_kev.tsv) with your own product keys as you inventory.

<details>
<summary>Sample output</summary>

```text
[VULNERABLE] web-prod-01   php-8.3   8.3.34 < fixed 8.3.36   CVE-2026-109618/109619  (critical-KEV)
             action: Patch then restart PHP workers (Case 05)
[VULNERABLE] ci-gitlab-01  gitlab    19.4.1 < fixed 19.4.2   CVE-2026-97229          (KEV)
[VULNERABLE] vpn-asa-01    cisco-asa-9.20  9.20.4.12 < fixed 9.20.4.50  CVE-2026-76418 (high-KEV)
[ok]         web-prod-02   php-8.3   8.3.36 >= fixed 8.3.36  CVE-2026-109618/109619
...
summary: 7 vulnerable, 2 ok, 1 with no matching rule
```

</details>

---

## 🧬 `iocmatch`

Loads [`../04_iocs/iocs.csv`](../04_iocs/iocs.csv) and hunts for the indicators in your logs and files. Includes a **self-contained SHA-256** so it can hash files and match known-bad hashes with zero dependencies.

```bash
# Text indicators (domains/IPs/URLs/paths) against a log:
./target/release/iocmatch --iocs ../04_iocs/iocs.csv --logs data/sample_access.log
# Hash + name match a directory tree (e.g. a quarantined Python env or image export):
./target/release/iocmatch --iocs ../04_iocs/iocs.csv --scan /path/to/suspect/dir
# Stream logs in:
cat /var/log/nginx/access.log | ./target/release/iocmatch --iocs ../04_iocs/iocs.csv --logs -
```

<details>
<summary>Sample output</summary>

```text
[LOG HIT]  access.log:4   <domain> litellm.dev   (case 04 — LiteLLM 1.107.0 stealer exfil)
[NAME HIT] /suspect/.pc_once_72129118c59f5636c0bb  <filepath>  (case 04 — stealer run-once marker)
[HASH HIT] /suspect/litellm-1.107.0-...whl  sha256 12d4ccc5...b9484  (case 04 — malicious wheel)
summary: 3 indicator hit(s)
```

</details>

> Caveats from [`../04_iocs/README.md`](../04_iocs/README.md) apply (context-sensitive filenames; `litellm.dev` ≠ `litellm.ai`).

---

## 🔦 `logtriage`

Flags web/access-log lines matching October exploitation **patterns** — PHP2Shell multipart POSTs, Oracle EBS `/OA_HTML/` SQLi markers, `litellm.dev`, FortiGate config-backup URIs, and common webshell names. Heuristics for hunting: candidates to review, **not** proof of compromise.

```bash
./target/release/logtriage data/sample_access.log
cat /var/log/apache2/access.log | ./target/release/logtriage -
```

<details>
<summary>Sample output</summary>

```text
[php2shell,webshell] line 2: ... "POST /uploads/up.php HTTP/1.1" ... multipart/form-data ...
[oracle-ebs]         line 3: ... "GET /OA_HTML/OALogout?p=1'%20OR%201=1-- HTTP/1.1" ...
[litellm]            line 4: ... "POST /healthcheck HTTP/1.1" host: litellm.dev ...
[fortigate]          line 5: ... "GET /api/v2/monitor/system/config/backup?scope=global ..."

--- logtriage summary ---
flagged lines: 5     fortigate 1 · litellm 1 · oracle-ebs 1 · php2shell 1 · webshell 2
```

</details>

---

## 🧱 Design notes

> [!NOTE]
> **Why std-only?** So it builds anywhere, offline, with nothing to vet in a dependency tree — exactly what you want for a tool you&rsquo;ll run during incident response on sensitive data. The SHA-256 is implemented in-crate (FIPS 180-4, covered by test vectors for `""`, `"abc"`, and the pangram). If you later want speed or richer parsing, the code is small enough to extend with `regex`, `walkdir`, `sha2`, etc.

> [!IMPORTANT]
> **Scope.** This toolkit contains **no exploit code**. To validate remediation of a specific CVE, use your licensed scanner&rsquo;s authenticated checks, or detonate the **vendor-referenced** PoC in an isolated lab — see each [case file](../01_cases/) and [`../08_references.md`](../08_references.md).

---

<p align="center"><sub><a href="../README.md">&larr; back to repository root</a></sub></p>
