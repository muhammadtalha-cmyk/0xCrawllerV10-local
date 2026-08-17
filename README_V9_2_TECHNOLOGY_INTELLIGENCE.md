# 0xCrawller V9.2 — Parallel Technology and Service Intelligence

V9.2 runs after V9 asset normalization. It consolidates web technologies, dynamic JavaScript frameworks, servers, runtimes, CMS products, client-side libraries, databases, caches, search engines, queues, and service versions. It records exact versions only when remote evidence defensibly exposes them.

## Five bounded parallel lanes

1. **Custom HTTP evidence** — headers, cookies, generator tags, HTML, asset URLs, public error signatures.
2. **WhatWeb 0.6.4** — more than 1,800 web-technology plugins with version-aware matches.
3. **Wappalyzer Next 2.0.0** — Chromium/Playwright plus the Wappalyzer browser extension for dynamic applications. Browser workers are capped at three; overflow targets use the lighter balanced mode.
4. **Retire.js 5.4.3** — downloaded in-scope JavaScript components and exposed versions/vulnerability metadata.
5. **ZGrab2** — unauthenticated application handshakes for confirmed direct first-party services, including MySQL, PostgreSQL, MongoDB, Redis, AMQP/RabbitMQ, MQTT, MSSQL, Oracle, Memcached, SSH, and mail protocols.

The five lanes execute concurrently. Each lane has independent worker, timeout, and target caps. Wappalyzer's full and balanced subpasses remain sequential inside their lane to prevent two browser-heavy containers competing for memory.

## Accuracy rules

- A Django-looking login page can establish `Django` with a confidence score, but it does not prove an exact Django version.
- Exact versions require explicit headers, generator data, asset/component evidence, browser-extension evidence, Nmap evidence, or protocol handshake fields.
- Database or queue evidence from HTML/errors/Wappalyzer remains `application_reference_not_service_confirmation`.
- `service_confirmed=true` requires current direct-service evidence from Nmap or ZGrab2.
- Third-party SaaS is excluded from active enrichment.
- CDN-fronted hostnames receive web-vhost checks, not origin-network attribution.

Version states:

```text
EXACT_OBSERVED
RANGE_INFERRED
CONFLICTING
NOT_EXPOSED
```

## Build Docker images

```cmd
build-v9.2-tech-images.cmd
```

The Wappalyzer Next image includes Chromium and is larger than the other local images, so its first build takes longer. Subsequent runs reuse the image.

## MAX run

```cmd
run-v9.2-tech-max.cmd sky47.com.pk
```

Direct command:

```cmd
python .\vapt_technology_enricher_v9_2.py --target sky47.com.pk --latest-root .\recon_runs --normalize-if-missing --authorized --max --overwrite --workers 5 --http-workers 8 --js-workers 10 --service-workers 4 --whatweb-threads 12 --wappalyzer-next-workers 3 --wappalyzer-next-balanced-workers 10 --wappalyzer-next-full-target-cap 30 --wappalyzer-next-page-timeout 25 --request-timeout 10 --lane-timeout 1800
```

Local-only reconciliation:

```cmd
python .\vapt_technology_enricher_v9_2.py --target sky47.com.pk --latest-root .\recon_runs --offline --overwrite
```

## Outputs

Created under `<run-folder>\technology_enrichment_v9_2`:

- `technology_target_plan.json`
- `technology_tool_status.json`
- `http_technology_evidence.json`
- `whatweb_results.json`
- `wappalyzer_next_results.json`
- `javascript_components.json`
- `zgrab2_service_results.json`
- `technology_inventory.json` / `.csv`
- `technology_evidence.jsonl`
- `technology_conflicts.json`
- `service_fingerprints.json` / `.csv`
- `asset_inventory_enriched.json`
- `service_inventory_enriched.json`
- `technology_revalidation_queue.json`
- `technology_stack_map.mmd`
- `technology_enrichment_summary.json`
- `technology_enrichment_report.md`

## Limit

No external unauthenticated scanner can guarantee the exact hidden backend, database, or queue version when the application does not expose it. V9.2 reports `NOT_EXPOSED` rather than guessing; authenticated package inventory or an SBOM is the definitive fallback.
