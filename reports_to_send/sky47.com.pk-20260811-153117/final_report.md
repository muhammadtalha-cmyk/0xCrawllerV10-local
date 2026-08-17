# Smart Subdomain Recon Report: `sky47.com.pk`

**Overall run status: `COMPLETE`**

Run folder: `recon_runs/sky47.com.pk-20260811-153117`
Generated: `2026-08-11T16:18:33`

## Run health and coverage

- Mode: `max`
- Canonical crawl target: `https://sky47.com.pk`
- Candidates selected: `4268`
- Candidates generated before cap: `4268`
- Candidate list truncated: `False`
- Bulk DNS coverage: `4139/4139` (`100.0%`)
- DNSX chunks completed: `1/1`
- Katana requested configuration: `{"depth": 5, "crawl_duration": "10m", "known_files": "all", "enabled": true}`
- Katana effective configuration: `{"depth": 5, "crawl_duration": "10m", "known_files": "all", "scope": "fqdn", "enabled": true, "concurrency": 10, "rate_limit": 50, "javascript_crawl": true, "ignore_query_params": true}`

## Tool status

| Tool | Status | OK | Timed out | Warnings | Errors | Seconds | Return code |
|---|---|---:|---:|---:|---:|---:|---:|
| gobuster_base | Warning | True | False | 1 | 0 | 3.25 | 0 |
| subfinder | OK | True | False | 0 | 0 | 3.53 | 0 |
| bbot | Warning | True | False | 19 | 0 | 296.11 | 0 |
| amass | OK | True | False | 0 | 0 | 792.46 | 0 |
| httpx_root_probe | OK | True | False | 0 | 0 | 24.98 | 0 |
| katana_canonical | OK | True | False | 0 | 0 | 14.81 | 0 |
| dnsx_priority | OK | True | False | 0 | 0 | 4.81 | 0 |
| dnsx_chunk_0001 | OK | True | False | 0 | 0 | 147.60 | 0 |
| gobuster_custom | Warning | True | False | 1 | 0 | 0.91 | 0 |
| dnsx_wildcards | OK | True | False | 0 | 0 | 3.70 | 0 |
| httpx_probe | Warning | True | False | 2 | 0 | 50.88 | 0 |
| httpx_screenshot | OK | True | False | 0 | 0 | 45.74 | 0 |
| katana_recursive_l1_autodiscover.sky47.com.pk_e7ae19b3 | OK | True | False | 0 | 0 | 11.76 | 0 |
| katana_recursive_l1_enterpriseregistration.sky47.com.pk_3ff2c17b | OK | True | False | 0 | 0 | 13.68 | 0 |
| katana_recursive_l1_enterpriseenrollment.sky47.com.pk_83bc599d | OK | True | False | 0 | 0 | 14.32 | 0 |
| katana_recursive_l1_vpn-h.sky47.com.pk_5e5fc5ba | OK | True | False | 0 | 0 | 13.97 | 0 |
| katana_recursive_l1_www.sky47.com.pk_e17035e6 | OK | True | False | 0 | 0 | 14.81 | 0 |
| katana_recursive_l1_admin.sky47.com.pk_feef67d9 | OK | True | False | 0 | 0 | 47.05 | 0 |
| wafw00f | OK | True | False | 0 | 0 | 4.44 | 0 |
| naabu_port_scan | OK | True | False | 0 | 0 | 1653.96 | 0 |
| nmap_vpn.sky47.com.pk | OK | True | False | 0 | 0 | 1.38 | 0 |
| nmap_vpn-h.sky47.com.pk | OK | True | False | 0 | 0 | 24.15 | 0 |

### Tool diagnostics

#### `gobuster_base`
- Warning: `[+] Timeout:    5s`

#### `bbot`
- Warning: `[INFO] Setup soft-failed for chaos: No API key set`
- Warning: `[INFO] Setup soft-failed for bevigil: No API key set`
- Warning: `[INFO] Setup soft-failed for bufferoverrun: No API key set`
- Warning: `[INFO] Setup soft-failed for builtwith: No API key set`
- Warning: `[INFO] Setup soft-failed for c99: No API key set`

#### `gobuster_custom`
- Warning: `[+] Timeout:    5s`

#### `httpx_probe`
- Warning: `443 chain="network is unreachable; connection refused"`
- Warning: `context deadline exceeded (Client.Timeout exceeded while awaiting headers)`

## Wildcard analysis

Zones tested: `2`
Random probes sent: `6`

| Zone | Wildcard answer | Answers | Matching signature probes |
|---|---:|---:|---:|
| `admin.sky47.com.pk` | False | 0 | 0 |
| `sky47.com.pk` | False | 0 | 0 |

## DNS-validated assets (11)

- `admin.sky47.com.pk` state=`dns_resolved` A=[104.26.14.133, 104.26.15.133, 172.67.69.24] CNAME=[]
- `autodiscover.admin.sky47.com.pk` state=`dns_resolved` A=[40.99.32.120, 40.99.60.8, 40.99.68.40, 40.99.70.184, 40.99.70.200, 40.99.70.216, 40.99.70.232, 52.98.61.56] CNAME=[acdcatm.autodiscover.mira.tm.svc.cloud.microsoft, atm.autodiscover.mira.tm.svc.cloud.microsoft, autod.ms-acdc-autod.office.com, autodiscover.outlook.cloud.microsoft, autodiscover.outlook.com]
- `autodiscover.sky47.com.pk` state=`dns_resolved` A=[104.26.14.133, 104.26.15.133, 172.67.69.24] CNAME=[]
- `enterpriseenrollment.admin.sky47.com.pk` state=`dns_resolved` A=[13.107.228.46] CNAME=[azurefd-t54-prod.trafficmanager.net, enterpriseenrollment-s.manage.microsoft.com, manage-pe.trafficmanager.net, pexsucp-drgzexethuh8cpen.b02.azurefd.net, s-part-0035.t-0009.t-s1-msedge.net, shed.dual-low.s-part-0035.t-0009.t-s1-msedge.net]
- `enterpriseenrollment.sky47.com.pk` state=`dns_resolved` A=[104.26.14.133, 104.26.15.133, 172.67.69.24] CNAME=[]
- `enterpriseregistration.admin.sky47.com.pk` state=`dns_resolved` A=[20.190.147.34, 20.190.147.35, 20.190.147.36, 20.190.147.37, 20.190.177.145, 20.190.177.17, 20.190.177.18, 20.190.177.81, 40.126.18.35, 40.126.18.36] CNAME=[enterpriseregistration.windows.net, na.privatelink.msidentity.com, prdf.aadg.msidentity.com, www.tm.f.prd.aadg.akadns.net]
- `enterpriseregistration.sky47.com.pk` state=`dns_resolved` A=[104.26.14.133, 104.26.15.133, 172.67.69.24] CNAME=[]
- `servicehub.sky47.com.pk` state=`dns_resolved` A=[35.185.32.151] CNAME=[sky47limited.samanage.com]
- `vpn-h.sky47.com.pk` state=`dns_resolved` A=[138.252.175.134] CNAME=[]
- `vpn.sky47.com.pk` state=`dns_resolved` A=[203.135.22.188] CNAME=[]
- `www.sky47.com.pk` state=`dns_resolved` A=[104.26.14.133, 104.26.15.133, 172.67.69.24] CNAME=[]

## Accepted keyword evidence (9)

Rejected noisy/random tokens: `91`

| Keyword | Score | Source(s) |
|---|---:|---|
| `admin` | 100 | exact_subdomain_label |
| `vpn` | 100 | exact_subdomain_label |
| `new` | 92 | katana_url |
| `web` | 92 | katana_url |
| `servicehub` | 78 | exact_subdomain_label |
| `services` | 75 | katana_url |
| `autodiscover` | 73 | exact_subdomain_label |
| `enterpriseenrollment` | 71 | exact_subdomain_label |
| `enterpriseregistration` | 71 | exact_subdomain_label |

## CDN, Wappalyzer technology, and WAF detection

Passive detection is always collected from HTTPX. Technology fingerprints come from HTTPX `-tech-detect` using the Wappalyzer dataset; CDN/WAF provider evidence comes primarily from HTTPX CDNCheck and DNS/CNAME context. Wappalyzer technology alone is supporting evidence, not proof of proxying.

- Assets with CDN evidence: `9`
- Assets with any WAF/security-edge evidence: `7`
- Assets with passive WAF/security-edge evidence: `6`
- Conflicting or multi-layer WAF attributions: `1`
- Generic active WAF detections: `1`
- Unique technologies detected: `12`
- Active WAFW00F requested: `True`
- Active WAFW00F targets: `7`
- Active WAFW00F detections: `7`

| Host | CDN | CDN confidence | WAF/security edge | WAF confidence | Attribution | Detection mode | Technologies |
|---|---|---|---|---|---|---|---|
| `admin.sky47.com.pk` | Cloudflare | high | Cloudflare | high | named_active_fingerprint | active_fingerprinting | Cloudflare, Cloudflare Browser Insights, HSTS, MySQL, PHP:8.3.31, WordPress Block Editor, WordPress:7.0.3 |
| `autodiscover.sky47.com.pk` | Cloudflare | high | Cloudflare | high | named_active_fingerprint | active_fingerprinting | Cloudflare |
| `enterpriseenrollment.sky47.com.pk` | Cloudflare | high | Cloudflare / Azure Front Door | medium | conflicting_or_multi_layer | active_fingerprinting | Azure, Azure Front Door, Cloudflare, Cloudflare Browser Insights, HSTS |
| `enterpriseregistration.sky47.com.pk` | Cloudflare | high | Cloudflare | high | named_active_fingerprint | active_fingerprinting | Cloudflare, HSTS |
| `sky47.com.pk` | Cloudflare | high | Cloudflare | high | named_active_fingerprint | active_fingerprinting | Cloudflare, Cloudflare Browser Insights, HSTS |
| `vpn-h.sky47.com.pk` |  | none | Generic/Unknown WAF | medium | generic_active_fingerprint | active_fingerprinting |  |
| `www.sky47.com.pk` | Cloudflare | high | Cloudflare | high | named_active_fingerprint | active_fingerprinting | Cloudflare, Cloudflare Browser Insights, HSTS |
| `enterpriseenrollment.admin.sky47.com.pk` | azure | high |  | none |  | passive | Azure, Azure Front Door |
| `enterpriseregistration.admin.sky47.com.pk` | azure | high |  | none |  | passive |  |
| `servicehub.sky47.com.pk` | Google | high |  | none |  | passive | HSTS, Ruby, Ruby on Rails, jQuery |

## Passive Shodan reconnaissance

This stage queries Shodan's existing DNS, search, and host databases. It does not submit on-demand Shodan scans.

- Requested: `False`
- Status: `NOT_REQUESTED`
- API key configured: `False`
- Shodan DNS records collected: `0`
- Scoped dorks planned: `0`
- Dorks with non-zero counts: `0`
- Estimated query credits spent: `0` / `0`
- API-reported query-credit delta: `None`
- Host lookups completed: `0`
- Services collected: `0`
- Assets enriched: `0`
- Unique vulnerability identifiers observed in Shodan metadata: `0`


## Recursive recon expansion, clustering, and topology

The canonical root is level 0. Newly discovered in-scope web hosts are revalidated and crawled in parallel for at most three descendant levels. Third-party SaaS is retained as evidence but excluded from active recursive crawling.

- Requested: `True`
- Status: `COMPLETE`
- Maximum descendant depth: `3`
- Levels completed: `1`
- Parallel crawl workers: `4`
- Hosts crawled: `6`
- In-scope hosts observed during expansion: `0`
- Newly DNS-validated hosts: `0`
- URLs observed across canonical and recursive crawls: `237`
- Maximum-depth boundary hosts not followed: `0`
- Host-cap truncation: `False`
- Recursive screenshots skipped because the host was already captured: `6`

### Expansion by level

| Level | Crawled hosts | URLs observed | New hosts observed | New hosts validated | Next-level targets | Boundary |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 6 | 204 | 0 | 0 | 0 | False |

### Asset clusters

| Cluster | Assets | Samples |
|---|---:|---|
| `dns_only` | 2 | `autodiscover.admin.sky47.com.pk`<br>`vpn.sky47.com.pk` |
| `first_party_cdn_fronted` | 6 | `admin.sky47.com.pk`<br>`autodiscover.sky47.com.pk`<br>`enterpriseenrollment.sky47.com.pk`<br>`enterpriseregistration.sky47.com.pk`<br>`sky47.com.pk`<br>`www.sky47.com.pk` |
| `first_party_waf_detected` | 1 | `vpn-h.sky47.com.pk` |
| `root` | 1 | `sky47.com.pk` |
| `third_party_saas` | 3 | `enterpriseenrollment.admin.sky47.com.pk`<br>`enterpriseregistration.admin.sky47.com.pk`<br>`servicehub.sky47.com.pk` |

### Recon mind map

```mermaid
flowchart TD
  N0["admin.sky47.com.pk\nL1 | cdn_edge_or_first_party_frontend"]
  N1["autodiscover.sky47.com.pk\nL1 | cdn_edge_or_first_party_frontend"]
  N2["enterpriseenrollment.admin.sky47.com.pk\nL1 | third_party_saas"]
  N3["enterpriseenrollment.sky47.com.pk\nL1 | cdn_edge_or_first_party_frontend"]
  N4["enterpriseregistration.admin.sky47.com.pk\nL1 | third_party_saas"]
  N5["enterpriseregistration.sky47.com.pk\nL1 | cdn_edge_or_first_party_frontend"]
  N6["servicehub.sky47.com.pk\nL1 | third_party_saas"]
  N7["sky47.com.pk\nL0 | cdn_edge_or_first_party_frontend"]
  N8["vpn-h.sky47.com.pk\nL1 | first_party_or_unknown"]
  N9["www.sky47.com.pk\nL1 | cdn_edge_or_first_party_frontend"]
  N7 -->|initial_inventory| N0
  N7 -->|initial_inventory| N1
  N7 -->|initial_inventory| N2
  N7 -->|initial_inventory| N3
  N7 -->|initial_inventory| N4
  N7 -->|initial_inventory| N5
  N7 -->|initial_inventory| N6
  N7 -->|initial_inventory| N8
  N7 -->|initial_inventory| N9
```

The complete machine-readable graph is stored in `recon_topology.json`; the standalone Mermaid source is `recon_mindmap.mmd`.

## HTTP probing and host classification

| Host | Status | Title | Category | Priority | Edge response | Ownership | Application/SaaS provider | Network CDN | WAF | WAF attribution |
|---|---:|---|---|---|---|---|---|---|---|---|
| `admin.sky47.com.pk` | 200 | Sky47 \| AI-Ready Tier III/IV Data Centre & Sovereign Cloud Pakistan - Sky47 delivers Tier III/IV colocation, sovereign cloud, high-density compute and AI-ready infrastructure to power secure enterprise-grade digital transformation. | Admin / Management Surface | High | application_live | cdn_edge_or_first_party_frontend |  | Cloudflare | Cloudflare | named_active_fingerprint |
| `autodiscover.sky47.com.pk` | 521 |  | Unknown / Needs Review | High | application_or_upstream_error | cdn_edge_or_first_party_frontend |  | Cloudflare | Cloudflare | named_active_fingerprint |
| `enterpriseenrollment.sky47.com.pk` | 404 | Page not found | Unknown / Needs Review | Medium | default_404_or_missing_root_route | cdn_edge_or_first_party_frontend |  | Cloudflare | Cloudflare / Azure Front Door | conflicting_or_multi_layer |
| `enterpriseregistration.sky47.com.pk` | 404 |  | Unknown / Needs Review | Medium | default_404_or_missing_root_route | cdn_edge_or_first_party_frontend |  | Cloudflare | Cloudflare | named_active_fingerprint |
| `sky47.com.pk` | 200 |  | Unknown / Needs Review | Medium | application_live | cdn_edge_or_first_party_frontend |  | Cloudflare | Cloudflare | named_active_fingerprint |
| `vpn-h.sky47.com.pk` | 200 | fw-vpn-portal | Unknown / Needs Review | Medium | application_live | first_party_or_unknown |  |  | Generic/Unknown WAF | generic_active_fingerprint |
| `www.sky47.com.pk` | 200 |  | Unknown / Needs Review | Medium | application_live | cdn_edge_or_first_party_frontend |  | Cloudflare | Cloudflare | named_active_fingerprint |
| `enterpriseenrollment.admin.sky47.com.pk` | 404 | Page not found | Unknown / Needs Review | Medium | default_404_or_missing_root_route | third_party_saas | Microsoft Intune | azure |  |  |
| `enterpriseregistration.admin.sky47.com.pk` | 404 |  | Unknown / Needs Review | Medium | default_404_or_missing_root_route | third_party_saas | Microsoft Azure / Entra ID | azure |  |  |
| `servicehub.sky47.com.pk` | 200 | - SolarWinds Service Desk | Unknown / Needs Review | Medium | application_live | third_party_saas | SolarWinds Service Desk | Google |  |  |

## Controlled port enumeration

This stage is opt-in. DNS CNAME ownership is evaluated before HTTP classification. Third-party delegated services, CDN/security edges, and unresolved ownership are excluded by default. Naabu reports candidate TCP ports; Nmap independently rechecks only valid candidates. A Naabu result is not treated as confirmed open until Nmap reports the port state as `open`.

- Requested: `True`
- Targets selected: `2`
- Targets excluded: `10`
- Naabu candidate hosts: `2`
- Naabu candidate ports: `2`
- Rejected invalid Naabu records: `0`
- Nmap validation requested: `True`
- Nmap port-state/service records: `2`
- Nmap-confirmed open ports: `2`
- Nmap-not-confirmed candidates: `0`

| Host | Port | Naabu status | Nmap state | Final status | Service evidence |
|---|---:|---|---|---|---|
| `vpn-h.sky47.com.pk` | 443 | `NAABU_CANDIDATE` | `open` | `NMAP_CONFIRMED_OPEN` | https |
| `vpn.sky47.com.pk` | 179 | `NAABU_CANDIDATE` | `open` | `NMAP_CONFIRMED_OPEN` | tcpwrapped |

## Endpoint classification across canonical and recursive crawls

Raw unique URLs seen: `237`
Normalized in-scope endpoints: `204`
Deduplicated/filtered/malformed/external: `33`
External references recorded but not crawled into candidate generation: `20`
OpenAPI/Swagger candidates: `0`

| Category | Count | Priority | Samples |
|---|---:|---|---|
| Other Endpoint | 141 | Low | `https://admin.sky47.com.pk/`<br>`https://admin.sky47.com.pk/admin.sky47.com.pk/wp-admin/authorize-application.php`<br>`https://admin.sky47.com.pk/?p=1114`<br>`https://admin.sky47.com.pk/?p=1134`<br>`https://admin.sky47.com.pk/?p=512` |
| API Endpoint | 22 | High | `https://admin.sky47.com.pk/wp-json/wp/v2/leadership/1114`<br>`https://admin.sky47.com.pk/wp-json/wp/v2/leadership/512`<br>`https://admin.sky47.com.pk/wp-json/wp/v2/leadership/513`<br>`https://admin.sky47.com.pk/wp-json/wp/v2/leadership/515`<br>`https://admin.sky47.com.pk/wp-json/wp/v2/leadership/516` |
| CSS/Font Asset | 19 | Low | `https://admin.sky47.com.pk/cdn-cgi/styles/cf.errors.css`<br>`https://admin.sky47.com.pk/cdn-cgi/styles/cf.errors.ie.css`<br>`https://admin.sky47.com.pk/wp-content/cache/wpspeed/css/98244f1aefb944ed671c2def296f228f.css`<br>`https://admin.sky47.com.pk/wp-content/themes/sky47/github.com/necolas/normalize.css`<br>`https://admin.sky47.com.pk/wp-content/themes/sky47/style.css?ver=1.0.0` |
| JavaScript/Static Bundle | 16 | Medium | `https://admin.sky47.com.pk/wp-content/cache/wpspeed/js/01cfc99daabf5b6a636a0c87ad8bbb89.js`<br>`https://admin.sky47.com.pk/wp-content/cache/wpspeed/js/44f22cd1f98901867995af460d75f1fa.js`<br>`https://admin.sky47.com.pk/wp-content/plugins/optimole-wp/assets/build/optimizer/optimizer.js?v=4.2.10`<br>`https://admin.sky47.com.pk/wp-content/plugins/wpspeed/media/core/js/instantpage-5.2.0.js?ver=2.6.10`<br>`https://admin.sky47.com.pk/wp-content/plugins/wpspeed/media/core/js/ls.loader.js?ver=2.6.10` |
| File/Storage Endpoint | 6 | Medium | `https://admin.sky47.com.pk/wp-content/plugins/wpspeed/media/core/js/Chrome`<br>`https://admin.sky47.com.pk/wp-content/plugins/wpspeed/media/core/js/Chrome/`<br>`https://admin.sky47.com.pk/wp-content/plugins/wpspeed/media/lazysizes/types/global`<br>`https://admin.sky47.com.pk/wp-content/plugins/wpspeed/media/lazysizes/types/lazysizes-config`<br>`https://sky47.com.pk/static/js/image/` |

## Internal IP leak / private address references

No private IP reference was found in fields classified as target-controlled response content.

## Screenshot capture

Screenshot execution status: `OK`
Eligible unique hosts: `10`
Selected unique hosts: `10`
Skipped by configured limit: `0`
Coverage: `100.0%`
Main screenshot JSON records: `10`
Unique hosts captured: `10`
Unique screenshot contents: `8`
Total screenshot artifacts retained: `10`
Duplicate-content artifacts: `2`
- Selection policy: One best URL per host; high-priority assets first, then successful/redirecting HTTPS responses, then remaining live responses.
- Screenshot image files were created for the selected URLs.
- `httpx_screenshots/screenshot/admin.sky47.com.pk/67850d20affe62963409c6f68e1b74880de9c305.png`
- `httpx_screenshots/screenshot/autodiscover.sky47.com.pk/e80f5608a478a34777c2254bc44542774c3ee19f.png`
- `httpx_screenshots/screenshot/enterpriseenrollment.admin.sky47.com.pk/513e500767f9fad9abae1c1f0fb2a12611f63b17.png`
- `httpx_screenshots/screenshot/enterpriseenrollment.sky47.com.pk/e1688569ad9e0450a4687da9f95b45d245d1605e.png`
- `httpx_screenshots/screenshot/enterpriseregistration.admin.sky47.com.pk/1ba4a951105857cfc0fe48a6efe74ae361aa80fd.png`
- `httpx_screenshots/screenshot/enterpriseregistration.sky47.com.pk/2498e273fe2373e0ae36ce2ef67dac98dda64cb3.png`
- `httpx_screenshots/screenshot/servicehub.sky47.com.pk/bcb4ad6be20dde9927993783bce47933cb71e4af.png`
- `httpx_screenshots/screenshot/sky47.com.pk/e8d743d5f1dd55056e280e7a6a4d2c8d51b670be.png`
- `httpx_screenshots/screenshot/vpn-h.sky47.com.pk/742b2c2fe9702b8c676c91fc9006a8e6e4a8e84d.png`
- `httpx_screenshots/screenshot/www.sky47.com.pk/cf0b9f171dbdf8efc9b9a4f8fb00ed1a8aeea7ef.png`

## Browser-rendered host/API discovery

Target-scope URLs observed by browser: `66`
All target-scope hosts observed by browser: `10`
New browser-only hosts: `0`
New browser-only hosts validated by DNS: `0`

## Manual VAPT review plan

> These are review tasks, not vulnerability claims. Perform only with explicit authorization and test accounts.

### Admin / Management Surface
- `admin.sky47.com.pk` status=`200` title=`Sky47 \| AI-Ready Tier III/IV Data Centre & Sovereign Cloud Pakistan - Sky47 delivers Tier III/IV colocation, sovereign cloud, high-density compute and AI-ready infrastructure to power secure enterprise-grade digital transformation.` ownership=`cdn_edge_or_first_party_frontend`
  - CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.
  - Check role separation, session timeout, MFA and rate limiting if in scope.
  - Verify authentication is enforced on every administrative route.

### Unknown / Needs Review
- `autodiscover.sky47.com.pk` status=`521` title=`` ownership=`cdn_edge_or_first_party_frontend`
  - CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.
  - The response indicates an application, origin, routing, or TLS problem that requires manual verification.
- `enterpriseenrollment.sky47.com.pk` status=`404` title=`Page not found` ownership=`cdn_edge_or_first_party_frontend`
  - CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.
  - The host answered, but the root route was not found.
- `enterpriseregistration.sky47.com.pk` status=`404` title=`` ownership=`cdn_edge_or_first_party_frontend`
  - CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.
  - The host answered, but the root route was not found.
- `sky47.com.pk` status=`200` title=`` ownership=`cdn_edge_or_first_party_frontend`
  - CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.
- `vpn-h.sky47.com.pk` status=`200` title=`fw-vpn-portal` ownership=`first_party_or_unknown`
- `www.sky47.com.pk` status=`200` title=`` ownership=`cdn_edge_or_first_party_frontend`
  - CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.
- `enterpriseenrollment.admin.sky47.com.pk` status=`404` title=`Page not found` ownership=`third_party_saas`
  - CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.
  - The host answered, but the root route was not found.
  - Third-party managed service; intrusive testing requires explicit authorization for that provider/service.
- `enterpriseregistration.admin.sky47.com.pk` status=`404` title=`` ownership=`third_party_saas`
  - CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.
  - The host answered, but the root route was not found.
  - Third-party managed service; intrusive testing requires explicit authorization for that provider/service.
- `servicehub.sky47.com.pk` status=`200` title=`- SolarWinds Service Desk` ownership=`third_party_saas`
  - CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.
  - Third-party managed service; intrusive testing requires explicit authorization for that provider/service.

## Output files

- `summary.json`
- `command_manifest.json`
- `tool_versions.json`
- `validated_dns_hosts.txt` / `.json` / `.csv`
- `wildcard_suspected_hosts.json`
- `wildcard_check.json`
- `candidate_manifest.jsonl` / `.csv`
- `keyword_evidence.json`
- `rejected_keywords.json`
- `dnsx_chunk_manifest.json`
- `canonical_target.json`
- `katana_urls.txt`
- `endpoint_classification.json`
- `external_references.txt`
- `openapi_candidates.txt`
- `httpx_probe.jsonl`
- `http_review_classification.json` / `.csv`
- `edge_detection_summary.json`
- `waf_targets.txt`
- `waf_detection.json` / `.csv`
- `wafw00f.json` when active WAF fingerprinting is enabled
- `port_scan_target_manifest.json` / `.csv`
- `port_scan_targets.txt`
- `naabu_ports_raw.jsonl` (unaltered tool evidence when available)
- `naabu_ports.jsonl` / `.json` / `.csv` (normalized valid candidates)
- `naabu_rejected_records.jsonl`
- `nmap/*.xml` when Nmap service validation is enabled
- `nmap_services.json` / `.csv`
- `port_candidate_reconciliation.json` / `.csv`
- `port_scan_summary.json`
- `shodan_summary.json` / `shodan_api_info.json` / `shodan_credit_ledger.json`
- `shodan_dork_plan.json` / `shodan_dork_counts.json`
- `shodan_dns_domain.jsonl` / `shodan_search_results.jsonl` / `shodan_host_lookups.jsonl`
- `shodan_services.jsonl` / `shodan_assets.json` / `shodan_ports.csv` / `shodan_vulnerabilities.json`
- `shodan_discovered_hosts.txt` / `shodan_search_filters.json` / `shodan_host_no_data.jsonl`
- `recursive_recon_summary.json` / `recursive_hosts_by_level.json` / `recursive_urls_all.txt`
- `recon_topology.json` / `recon_clusters.json` / `recon_mindmap.mmd`
- `recursive/level_*/` per-level DNS, HTTP, Katana, screenshot, and Shodan evidence
- `screenshot_status.json`
- `internal_ip_leaks.json`
- `final_report.md`

Compatibility aliases are also retained as `confirmed_subdomains.*`.
