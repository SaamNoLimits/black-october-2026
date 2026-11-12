# Case 04 — LiteLLM 1.107.0 Supply-Chain Poisoning

## Snapshot

| Field | Value |
|---|---|
| Date | **21 October 2026**, ~11:39–14:20 UTC (PyPI quarantined ~13:20) |
| Package | `litellm==1.107.0` — all 7 PyPI wheels + sdist; Docker tags `v1.107.0`, `latest`, `main-latest`, `main-stable` |
| Payload | Modular infostealer self-named **`privcollect`** (16 categories) + hourly remote-code loader (RAT) |
| Exec path | **Python startup hook** (`cook.pth` → runs before any `import`); `cook.py` = stealer; `sitecustomize.py` = RAT |
| Exfil | GZIP-TAR via HTTP POST to `litellm[.]dev/healthcheck` (typosquat of the real `.ai` domain) |
| Reach | LiteLLM ≈ 23M weekly downloads |
| Root cause | Master key committed to public repo `LiteLLM-Labs/lite-harness` on **27 May 2026**, never revoked → used **10 Oct** to steal a GitHub OAuth token → owner-level repo access |
| Last safe version | **1.106.2** (1.107.0rc1/rc2 also clean; enterprise private release unaffected; GitHub source tag v1.107.0 clean) |

## What happened

LiteLLM is a widely used open-source gateway/proxy for many LLM providers. On **21 October 2026** its **release pipeline** was compromised and a poisoned `1.107.0` was pushed to PyPI and the official container registries.

The malware's defining trait: it executed from a **Python path-configuration file (`.pth`)**, so it ran the moment the interpreter started — **before `import litellm`, and surviving removal of the package**. Merely *installing* the wheel (or pulling/running the Docker image) in a CI runner or proxy container was enough to leak secrets. The `privcollect` stealer harvested across 16 module categories — browsers, cloud providers (AWS/GCP/Azure), AI-tool auth/config files, and the LiteLLM proxy's own saved provider keys (OpenAI, Anthropic, Cohere, etc.) and model config — then exfiltrated to `litellm[.]dev/healthcheck`.

**Root cause chain (LiteLLM postmortem, 24 Oct):** a config file containing a **master key** was committed to the public `LiteLLM-Labs/lite-harness` repo on **27 May 2026** and never revoked. On **10 October** the actor used it to reach the LiteLLM Agent Platform and extract an **organization owner's GitHub CLI OAuth token**, giving owner-level access to all repos — and thus the ability to cut a malicious release. This is LiteLLM's **second** supply-chain compromise of 2026 (the first was the March "TeamPCP" incident).

## Attack chain → MITRE ATT&CK

| Phase | Technique | ID |
|---|---|---|
| Initial access (vendor) | Exposed secret in public repo | T1552.001 |
| Credential access | Steal GitHub OAuth token via platform access | T1528 |
| Supply chain | Compromise software release/registry | T1195.002 |
| Execution (victim) | Python `.pth` startup hook runs at interpreter start | T1546 / T1059.006 |
| Credential access (victim) | Harvest cloud/AI/browser creds (16 modules) | T1555 / T1552 |
| C2 | Hourly remote-code loader | T1105 |
| Exfiltration | GZIP-TAR HTTP POST to typosquat domain | T1041 |

## Why it worked

- **A long-lived secret in a public repo, never rotated** — five months of exposure.
- **Release pipeline trust:** owning a maintainer/org token = owning what users install.
- **`.pth` execution** defeats the intuition that "I didn't import it, so it didn't run."
- **AI toolchains concentrate high-value secrets** (provider API keys, cloud creds) in predictable files.

## Indicators of compromise

| Type | Value |
|---|---|
| Malicious package | `litellm==1.107.0` (all 7 wheels + sdist) |
| Docker tags | `litellm/litellm:v1.107.0`, `:latest`, `:main-latest`, `:main-stable` (GHCR `ghcr.io/berriai/litellm`) |
| Payload files | `cook.pth`, `cook.py`, `sitecustomize.py` |
| Exfil domain | `litellm[.]dev` (path `/healthcheck`); registered **13 Oct 2026** |
| Attacker GitHub acct | `letters9813` (created 13 Oct 2026) |
| Host artifacts | `/tmp/.pc_once_72129118c59f5636c0bb` (run-once marker); `/tmp/remote_code_loader.lock` |
| Win wheel SHA-256 | `12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484` (cp310 win_amd64) |
| macOS ARM64 wheel SHA-256 | `0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a` |
| Infected image index SHA-256 | `1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e` |

(Also in `04_iocs/iocs.csv`; YARA in `05_detections/yara/litellm_privcollect_stealer.yar`.)

## Detection & hunting

- **Package inventory:** search every environment, CI runner, and image for `litellm==1.107.0`. Pin/allow-list to `1.106.2` or a fixed later release.
- **Filesystem:** hunt `cook.pth` / `cook.py` / `sitecustomize.py` in site-packages; the two `/tmp` markers.
- **Network:** any DNS/HTTP to `litellm[.]dev` (note: legit project is `.ai`). Alert on POST to `/healthcheck`.
- **Behavioral:** Python processes reading cloud/AI credential files shortly after `pip install`.
- See the YARA rule and `05_detections/sigma/litellm_python_startup_hook.yml`.

## Mitigation / IR runbook (if 1.107.0 ever ran)

1. **Assume every secret readable by that host/container is stolen.** Removing the package is **not** enough.
2. **Rotate** all cloud keys, AI/LLM provider keys, GitHub/CI tokens, and any secret in env/`.netrc`/CI vars on affected hosts.
3. **Purge** the Docker tags from registries and caches; rebuild images from a clean base pinned to a safe version.
4. **Remove** `cook.pth`/`cook.py`/`sitecustomize.py` and the `/tmp` markers; investigate for the hourly loader's follow-on payloads.
5. Add **startup-hook scanning** (`.pth`, `sitecustomize.py`) to CI and image builds; require signed releases / provenance (e.g., PEP 740 attestations, Sigstore) where available.

## PoC / exploit status

The malicious artifact was pulled and quarantined; this package intentionally does **not** redistribute the stealer. Datadog Security Labs, Socket, SafeDep, StepSecurity, Microsoft, and Gurucul published safe technical analyses and hashes — see references. Use the **YARA/IOCs** here to find it, not to run it.

## Red team takeaway

Add a **supply-chain branch** to every engagement: can you find a long-lived secret in a public repo, and would it reach a release pipeline? And on the blue side, prove you can detect **install-time** (not just import-time) execution. The `.pth` trick is now the default for Python package malware.

## Sources

See `08_references.md` → "Case 04." Primary: LiteLLM postmortem (BerriAI/litellm #47826, 24 Oct); Datadog Security Labs; The Register (21 & 26 Oct); Help Net Security; Gurucul; Socket; SafeDep.
