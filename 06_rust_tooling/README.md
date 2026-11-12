# Black October 2026 — Defensive Rust Toolkit

Three small, **dependency-free** (std-only) command-line tools for working the October 2026
cases. They are strictly defensive: they read **your** inventory, logs, and files locally and
report findings. Nothing here scans, attacks, or contacts a third party.

```
06_rust_tooling/
├── Cargo.toml                 workspace
├── data/
│   ├── october2026_kev.tsv    fixed-version ruleset for kevcheck
│   ├── sample_inventory.csv   example inventory
│   └── sample_access.log      example web log
└── crates/
    ├── kevcheck/              inventory vs. fixed-version triage
    ├── iocmatch/              IOC matcher (+ in-crate SHA-256)
    └── logtriage/             web/access-log heuristics
```

## Build

```bash
cd 06_rust_tooling
cargo build --release
cargo test            # unit tests: version compare, SHA-256 vectors, log heuristics
```

Binaries: `target/release/kevcheck`, `target/release/iocmatch`, `target/release/logtriage`.
No network or external crates required.

## kevcheck — "am I below the fixed version?"

Compares an asset inventory against the October 2026 fixed-version ruleset and flags anything
below the fix. Pure local version arithmetic — it never touches the asset.

```bash
cd 06_rust_tooling
./target/release/kevcheck --rules data/october2026_kev.tsv --inventory data/sample_inventory.csv
./target/release/kevcheck --inventory data/sample_inventory.csv --only-vuln   # just the findings
```

- Inventory CSV: `asset_id,product_key,version`
- Ruleset TSV: `product_key <TAB> cve <TAB> fixed_version <TAB> severity <TAB> note`
- Exit code **3** if anything is vulnerable (gate your CI on it). Extend `data/october2026_kev.tsv`
  with your own product keys as you inventory.

## iocmatch — "do these indicators appear in my data?"

Loads `04_iocs/iocs.csv` and hunts for the indicators in your logs and files. Includes a
self-contained SHA-256 so it can hash files and match known-bad hashes with zero dependencies.

```bash
cd 06_rust_tooling
# Match text indicators (domains/IPs/URLs/paths) against a log:
./target/release/iocmatch --iocs ../04_iocs/iocs.csv --logs ../06_rust_tooling/data/sample_access.log
# Hash + name match a directory tree (e.g., a quarantined Python env or image export):
./target/release/iocmatch --iocs ../04_iocs/iocs.csv --scan /path/to/suspect/dir
# Stream logs in:
cat /var/log/nginx/access.log | ./target/release/iocmatch --iocs ../04_iocs/iocs.csv --logs -
```

- Exit code **3** on any hit.
- Caveats from `04_iocs/README.md` apply (context-sensitive filenames; `litellm.dev` vs `litellm.ai`).

## logtriage — "which log lines deserve a human?"

Flags web/access-log lines matching October exploitation patterns (php2shell multipart POSTs,
Oracle EBS `/OA_HTML/` SQLi markers, `litellm.dev`, FortiGate config-backup URIs, common webshell
names). Heuristics for hunting — candidates to review, not proof.

```bash
cd 06_rust_tooling
./target/release/logtriage data/sample_access.log
cat /var/log/apache2/access.log | ./target/release/logtriage -
```

- Exit code **3** if any line is flagged; prints a per-heuristic summary.

## Why std-only?

So it builds anywhere, offline, with nothing to vet in a dependency tree — appropriate for a tool
you'll run during incident response on sensitive data. If you later want speed or richer parsing,
the code is small enough to extend with `regex`, `walkdir`, `sha2`, etc.

## Scope reminder

This toolkit deliberately contains **no exploit code**. For validating remediation of a specific
CVE, use your licensed vulnerability scanner's authenticated checks, or detonate the
**vendor-referenced** PoC in an isolated lab — see each case file and `08_references.md`.
