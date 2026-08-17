# Smart Recon V8.5 — Three-Level Recursive Recon

## Purpose

V8.5 completes the Stage 1 recon architecture by recursively expanding newly discovered **in-scope hostnames**. It does not recurse into unrelated external domains.

The canonical root is level 0:

```text
root domain (level 0)
    ├── discovered/validated web hosts (level 1)
    │      ├── newly discovered/validated hosts (level 2)
    │      │      └── newly discovered/validated hosts (level 3)
    │      └── third-party SaaS evidence retained, not actively crawled
    └── level-4 observations recorded as max-depth boundary, not followed
```

## Shodan corrections

- `/shodan/host/search` now sends `minify=false` when `fields` is present.
- A `/shodan/host/{ip}` HTTP 404 is stored as `status=no_data`, not an error.
- Hostnames discovered during Shodan host enrichment are DNSX-validated and HTTPX-probed in the same run.
- Incremental Shodan host enrichment runs for newly validated first-party/direct hosts at every recursive level.
- No on-demand Shodan scan endpoint is called.

## Recursive execution

Each level runs in this order:

```text
eligible live first-party hosts
    ↓
parallel Katana crawls per host
    + browser-rendered host observations
    + incremental passive Shodan host observations
    ↓
new in-scope hostname deduplication
    ↓
per-level wildcard checks
    ↓
batched DNSX validation
    ↓
batched HTTPX probing + Wappalyzer/CDN evidence
    ↓
ownership classification
    ↓
next level (maximum 3)
```

The recursive crawler does not follow:

- Out-of-scope domains
- Hosts classified as third-party SaaS
- Invalid hostnames
- Wildcard-generated names
- More than three descendant levels
- More than `--recursive-max-hosts`

## Parallelism

Independent host crawls are run with `--recursive-workers`. DNSX and HTTPX stay batched so the same host is not scanned repeatedly.

Default bounded MAX profile:

```text
recursive workers: 4
recursive depth: 3
recursive host cap: 250
per-host Katana depth: 3
per-host Katana duration: 2m
per-host Katana concurrency: 5
per-host Katana rate limit: 20 requests/second
```

## Report outputs

- `recursive_recon_summary.json`
- `recursive_hosts_by_level.json`
- `recursive_urls_all.txt`
- `recursive_wildcard_suspected.json`
- `recon_topology.json`
- `recon_clusters.json`
- `recon_mindmap.mmd`
- `recursive/level_*/` evidence folders

`final_report.md` now includes:

- Recursive level coverage
- Expansion counts
- Host clustering
- Maximum-depth boundary records
- Mermaid recon mind map
- Complete endpoint classification across canonical and recursive crawls

## Run

```cmd
run-max-v8.5-recursive.cmd sky47.com.pk
```

Or invoke Python directly:

```cmd
python .\smart_subdomain_pipeline_v8_modular.py --target sky47.com.pk --authorized --max --recursive-recon --recursive-depth 3 --recursive-workers 4 --recursive-max-hosts 250 --shodan-passive
```
