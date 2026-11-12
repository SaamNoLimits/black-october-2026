# Indicators of Compromise — usage & caveats

`iocs.csv` holds the **atomic, machine-readable** indicators from October 2026 that are safe and useful to operationalize. Columns:

`indicator,type,case,context,first_seen,confidence,source_note`

## How to use

- **SIEM/EDR:** import as a watchlist. Match `ipv4`/`domain`/`url` against network/proxy/DNS logs; `sha256` against file/EDR telemetry; `entra_app_id` against Entra sign-in & audit logs; `filename`/`filepath` against endpoint inventory.
- **Rust tooling:** `iocmatch` consumes this CSV directly — see `06_rust_tooling/README.md`.
- **Scoping windows:** pair each hunt with the exposure window from the case file (e.g., ConnectWise ≥13 Oct; LiteLLM 21 Oct 11:39–14:20 UTC).

## Important caveats

1. **Context-sensitive filenames.** `sitecustomize.py` is a *legitimate* Python filename; only the malicious variant inside `litellm==1.107.0` is an IOC. Match on hash/path context, not the bare name, to avoid false positives.
2. **Domain look-alikes.** The LiteLLM exfil domain is `litellm.dev` — the **legitimate** project is `litellm.ai`. Don't block the wrong one.
3. **Credential campaigns have few atomic IOCs.** FortiBleed, Binance/TraderTraitor, and Cisco ASA DoS are driven by behavior, not static indicators. For those, use the **detections** in `05_detections/` and the behavioral guidance in each case file. TraderTraitor blockchain addresses change as laundering continues — pull the current set from the FBI/USSS/IRS-CI IC3 alert rather than hardcoding them.
4. **Confidence is as-reported.** `medium` entries warrant corroboration before blocking.
5. **These are public (TLP:CLEAR).** Re-validate against the cited sources before taking blocking action in production.
