# Smart Recon V8.5.1 — Recon Normalization Fix

V8.5.1 closes the four evidence-normalization defects confirmed from the raw `sky47.com.pk-20260728-132052` run archive.

## Fixed

### 1. Invalid Naabu port records

Naabu records are accepted only when:

- the record is valid JSON,
- a host is present,
- protocol is TCP,
- port is within `1-65535`.

Port `0` and other invalid records are written to:

- `naabu_rejected_records.jsonl`

The unaltered tool output is retained as:

- `naabu_ports_raw.jsonl`

The compatibility `naabu_ports.jsonl` is rewritten with normalized valid candidates only.

### 2. Naabu/Nmap reconciliation

Naabu results are now labelled `NAABU_CANDIDATE`. Nmap independently rechecks only valid candidates. Final states include:

- `NMAP_CONFIRMED_OPEN`
- `NMAP_NOT_CONFIRMED`
- `NMAP_FAILED`
- `NMAP_NOT_RUN`
- `NAABU_CANDIDATE_UNVALIDATED`

Nmap no longer uses `--open`, allowing closed or filtered states to remain available in XML evidence.

New outputs:

- `port_candidate_reconciliation.json`
- `port_candidate_reconciliation.csv`

### 3. Encoded-host false positives

Recursive host extraction now parses URL authorities. It does not regex-scan raw percent-encoded URL text.

For example:

```text
url=https%3A%2F%2Fadmin.example.com%2Fpath
```

produces only:

```text
admin.example.com
```

and never:

```text
2fadmin.example.com
```

Complete nested HTTP(S) URLs in query values are still parsed safely.

### 4. Screenshot deduplication

Screenshot selection keeps one best URL per host. Recursive recon skips hosts already captured during the same run.

The report distinguishes:

- unique hosts captured,
- unique screenshot contents,
- total retained artifacts,
- duplicate-content artifacts.

### 5. Asset clustering

First-party edge classifications are now separated into:

- `first_party_cdn_fronted`
- `first_party_waf_detected`
- `first_party_direct_web`

Third-party SaaS and DNS-only assets remain separate.

## Installation

Back up the existing project, then copy this package over:

```text
E:\crawllerPhase2\0xCrawllerV2\smart_subdomain_pipeline_v8_modular
```

Retain the existing `.env` and `recon_runs` directories.

## Run

```cmd
run-max-v8.5.1-recursive.cmd sky47.com.pk
```

## Verification

```cmd
python -m compileall .
python -m pytest -q
python .\smart_subdomain_pipeline_v8_modular.py --help
```

The packaged test suite contains regression tests for port `0`, Naabu/Nmap disagreement, encoded nested URLs, screenshot deduplication, and CDN/WAF clustering.
