# V9.2 Technology and Service Intelligence Report

Source run: `/Users/talha/Downloads/0xCrawllerV10_updated 5/recon_runs/admin.sky47.com.pk-20260811-142405`
Overall status: **PARTIAL**

## Coverage

- Canonical assets considered: `4`
- Web targets enriched: `1`
- Network services fingerprinted: `0`
- JavaScript assets considered: `13`
- Technologies/components consolidated: `9`
- Exact versions observed: `2`
- Technology detected but version not exposed: `7`
- Technology version conflicts: `0`

`NOT_EXPOSED` means the product/framework was detected, but the remote evidence did not reveal a defensible exact version. It is not treated as a scanner failure.

## Parallel tool lanes

| Lane | Status | Targets | Notes |
|---|---|---:|---|
| `http_evidence` | `PARTIAL` | 1 |  |
| `whatweb` | `FAILED` | 1 | Unable to find image '0xcrawller/whatweb:0.6.4' locally docker: Error response from daemon: pull access denied for 0xcrawller/whatweb, repository does not exist or may require 'docker login'  Run 'docker run --help' for more information  |
| `wappalyzer_next` | `FAILED` | 1 |  |
| `retirejs` | `FAILED` | 0 | javascript_downloads_failed |
| `zgrab2` | `SKIPPED` | 0 | no_network_service_targets |
| `nuclei` | `COMPLETE` | 1 |  |

## Technology categories

| Category | Count |
|---|---:|
| Technology | 4 |
| CDN / Security Edge | 2 |
| CMS | 1 |
| Database | 1 |
| Programming Language | 1 |

## Exact observed versions

| Host | Technology | Version | Category | Confidence | Sources |
|---|---|---|---|---|---|
| `admin.sky47.com.pk` | WordPress | `7.0.3` | CMS | `medium` | httpx_wappalyzer |
| `admin.sky47.com.pk` | PHP | `8.3.31` | Programming Language | `medium` | httpx_wappalyzer |

## Database, cache, search, and queue evidence

| Host | Component | Version state | Scope | Service confirmed | Confidence |
|---|---|---|---|---:|---|
| `admin.sky47.com.pk` | MySQL | `NOT_EXPOSED` | application_reference_not_service_confirmation | False | `medium` |

## Service handshakes

| Host | Port | Module | Status | Product | Version | Sources |
|---|---:|---|---|---|---|---|
| — | — | — | — | — | — | No eligible direct first-party network services |

## Vulnerability findings (Nuclei)

Template matches are corroborating evidence for manual review — they are **not** auto-merged into technology confidence scoring above, since a template match can be behavior-based rather than a confirmed exact version.

| Host | Severity | Template | CVE | Matched at |
|---|---|---|---|---|
| `admin.sky47.com.pk` | `INFO` | AAAA Record - IPv6 Detection | — | admin.sky47.com.pk |
| `admin.sky47.com.pk` | `INFO` | Microsoft Azure Domain Tenant ID - Detect | — | https://login.microsoftonline.com:443/admin.sky47.com.pk/v2.0/.well-known/openid-configuration |
| `admin.sky47.com.pk` | `INFO` | DNS DMARC - Detect | — | _dmarc.admin.sky47.com.pk |
| `admin.sky47.com.pk` | `INFO` | MX Record Detection | — | admin.sky47.com.pk |
| `admin.sky47.com.pk` | `INFO` | Email Service Detector | — | admin.sky47.com.pk |
| `admin.sky47.com.pk` | `INFO` | robots.txt file | — | https://admin.sky47.com.pk/robots.txt |
| `admin.sky47.com.pk` | `INFO` | SPF Record - Detection | — | admin.sky47.com.pk |
| `admin.sky47.com.pk` | `INFO` | SSL DNS Names | — | admin.sky47.com.pk:443 |
| `admin.sky47.com.pk` | `INFO` | Detect SSL Certificate Issuer | — | admin.sky47.com.pk:443 |
| `admin.sky47.com.pk` | `INFO` | DNS TXT Record Detected | — | admin.sky47.com.pk |
| `admin.sky47.com.pk` | `INFO` | Wildcard TLS Certificate | — | admin.sky47.com.pk:443 |

High/Critical severity findings: `0` (also added to `technology_revalidation_queue.json`)

## Version conflicts

No conflicting exact versions were observed.

## Technology stack map

```mermaid
flowchart LR
  ROOT["Authorized attack surface"]
  H0["admin.sky47.com.pk\ncdn_edge_or_first_party_frontend"]
  ROOT --> H0
  T1["Cloudflare (version hidden)\nCDN / Security Edge"]
  H0 --> T1
  T2["PHP 8.3.31\nProgramming Language"]
  T1 --> T2
  T3["WordPress 7.0.3\nCMS"]
  T2 --> T3
  T4["MySQL (version hidden)\nDatabase"]
  T3 --> T4
  T5["Cloudflare Browser Insights (version hidden)\nTechnology"]
  T4 --> T5
  T6["HSTS (version hidden)\nTechnology"]
  T5 --> T6
  T7["WordPress Block Editor (version hidden)\nTechnology"]
  T6 --> T7
  H8["autodiscover.admin.sky47.com.pk\nthird_party_saas"]
  ROOT --> H8
  H9["enterpriseenrollment.admin.sky47.com.pk\nthird_party_saas"]
  ROOT --> H9
  T10["Azure Front Door (version hidden)\nCDN / Security Edge"]
  H9 --> T10
  T11["Azure (version hidden)\nTechnology"]
  T10 --> T11
  H12["enterpriseregistration.admin.sky47.com.pk\nthird_party_saas"]
  ROOT --> H12
```

## Interpretation rules

- A framework-like login page can establish a technology fingerprint, but it cannot guarantee an exact backend version.
- Database or queue names found in application errors, HTML, or JavaScript are recorded as application references until a current protocol handshake confirms an exposed service.
- Current Nmap/ZGrab2 evidence has precedence over passive historical records.
- CDN-fronted hostnames receive bounded HTTP technology enrichment, not direct origin-service attribution.
- Third-party SaaS is excluded from active enrichment unless separately authorized.

## Output files

- `technology_inventory.json` / `.csv`
- `technology_evidence.jsonl`
- `technology_conflicts.json`
- `service_fingerprints.json` / `.csv`
- `wappalyzer_next_results.json`
- `javascript_components.json`
- `asset_inventory_enriched.json` / `.csv`
- `service_inventory_enriched.json` / `.csv`
- `technology_revalidation_queue.json`
- `vulnerability_findings.json`
- `technology_stack_map.mmd`
- `technology_enrichment_summary.json`
