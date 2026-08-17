# Smart Recon V8.4 — Passive Shodan Integration

V8.4 adds a credit-aware passive Shodan stage to V8.3. It does not use Shodan's on-demand scan endpoint and therefore does not spend Shodan scan credits.

## Configuration

Edit `.env` in the pipeline root:

```dotenv
SHODAN_API_KEY=
```

Insert the API key after `=`. The key is loaded locally and is never written to reports, manifests, cache keys, or command logs.

## Passive Shodan workflow

1. Reads API plan information from `/api-info`.
2. Reads the current search-filter list from `/shodan/host/search/filters`.
3. Queries `/dns/domain/{domain}` for known DNS/subdomain records.
4. Loads scoped templates from `shodan_dorks.json`.
5. Validates each rendered query with `/shodan/host/search/tokens`.
6. Runs `/shodan/host/count` first. Counts do not consume query credits.
7. Downloads results only for non-zero scoped queries and only within `--shodan-max-query-credits`.
8. Enriches selected non-CDN, non-third-party IPs with `/shodan/host/{ip}`.
9. Extracts observed ports, products, versions, CPEs, tags, TLS metadata, hostnames, and Shodan vulnerability identifiers.
10. Feeds Shodan-discovered in-scope hostnames into the ordinary DNS validation pipeline.

## Default safety and cost controls

- Shodan is disabled unless `--shodan-passive` is supplied.
- Missing API key causes `NOT_CONFIGURED`, not a pipeline crash.
- Query-credit budget defaults to 10.
- Domain pages default to 1.
- Search pages default to 1 per dork.
- Dork counts run before downloads.
- Advanced database, DevOps, and vulnerability-metadata dorks are disabled by default.
- Organization, ASN, and CIDR dorks are generated only when you explicitly supply those authorized scope values.
- CDN/WAF edge and third-party IP host lookups are excluded by default.
- Shodan on-demand scanning endpoints are not implemented.

## Recommended controlled command

```cmd
py -3 .\smart_subdomain_pipeline_v8_modular.py --target hiapp.pk --authorized --max --shodan-passive --shodan-max-query-credits 10 --shodan-domain-pages 1 --shodan-max-dorks 12 --shodan-pages-per-query 1 --shodan-max-host-lookups 100
```

## Count-only test

This performs DNS-domain lookup plus free dork counts, but does not download search-result pages:

```cmd
py -3 .\smart_subdomain_pipeline_v8_modular.py --target hiapp.pk --authorized --skip-amass --skip-bbot --skip-gobuster --shodan-passive --shodan-count-only --shodan-max-query-credits 2 --no-screenshots
```

The DNS-domain endpoint itself uses query credit, so the budget should not be set below the number of requested domain pages.

## Explicit organization scopes

Only use values that are confirmed to belong to the authorized organization:

```cmd
--shodan-org "Example Organization" --shodan-asn AS64500 --shodan-net 203.0.113.0/24
```

To enable the advanced dorks in `shodan_dorks.json`:

```cmd
--shodan-include-disabled-dorks
```

Some filters are plan-dependent. V8.4 validates rendered queries using Shodan's token endpoint and records unsupported-query errors instead of silently treating them as valid.

## Outputs

- `shodan_api_info.json`
- `shodan_search_filters.json`
- `shodan_dork_plan.json`
- `shodan_dork_counts.json`
- `shodan_credit_ledger.json`
- `shodan_dns_domain.jsonl`
- `shodan_search_results.jsonl`
- `shodan_host_lookups.jsonl`
- `shodan_services.jsonl`
- `shodan_assets.json`
- `shodan_ports.csv`
- `shodan_vulnerabilities.json`
- `shodan_discovered_hosts.txt`
- `shodan_summary.json`

## Result semantics

Shodan observations are passive historical/current database observations. They are not automatically treated as current active confirmation. Port records keep their Shodan timestamp and source, and should be reconciled with authorized Naabu/Nmap results where active confirmation is required.

## V8.4.1 active-scan safety correction

Before Naabu or Nmap target selection, DNS CNAME ownership now takes precedence over HTTP classification. Delegated Microsoft 365/Outlook/Azure/Entra/Intune, SolarWinds, HubSpot, SendGrid, Google-hosted, GitHub Pages, Heroku, and similar third-party services are excluded by default even when HTTPX has no successful record for the hostname.

Generic WAFW00F detections are recorded as `Generic/Unknown WAF` with medium confidence. Conflicting named passive and active WAF providers are retained as `conflicting_or_multi_layer` with medium confidence rather than silently replacing one another.

