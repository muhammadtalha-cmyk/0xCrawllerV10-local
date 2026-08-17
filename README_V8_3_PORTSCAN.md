# Smart Recon V8.3 — Keyword/Provider Corrections + Controlled Port Scanning

## Corrections

1. **Cloudflare/tracking query values are no longer DNS keywords.**
   The pipeline now extracts URL path vocabulary and non-noisy query parameter names only. Values such as `__cf_chl_f_tk`, UTM values, challenge tokens, hashes, and campaign IDs cannot become generated subdomains.

2. **Short Katana-only random tokens are filtered more aggressively.**
   Short words require stronger repetition, and consonant-heavy Katana-only tokens are rejected unless they come from trusted exact-host/user evidence or the curated infrastructure vocabulary.

3. **Application/SaaS ownership is separate from network delivery.**
   Example: `*.samanage.com` is classified as **SolarWinds Service Desk** for application ownership, while an HTTPX `cdn_name=google` signal is retained separately as the **network CDN/provider**.

## Port scanning architecture

Port scanning is disabled unless `--port-scan` or `--nmap-service-scan` is supplied.

### Naabu

- Docker image: `projectdiscovery/naabu:latest`
- TCP CONNECT scan (`-s c`) for Docker Desktop/Windows compatibility
- Top 100 or top 1000 ports, or an explicit bounded port specification
- Explicit rate, thread, retry, and socket-timeout controls
- JSONL output
- Port verification enabled
- CDN exclusion enabled as defense in depth

### Nmap

A local image named `smartrecon/nmap:debian12` is built from `debian:12-slim` when Nmap validation is first requested.

Nmap runs only on ports Naabu already found open:

- TCP connect scan: `-sT`
- Service/version detection: `-sV --version-light`
- No NSE scripts
- No OS detection
- No UDP scan
- Per-host timeout
- XML output parsed into JSON/CSV

## Default target-selection safety

Excluded from active port scanning unless explicitly overridden:

- CDN/WAF edge hosts
- Third-party SaaS CNAMEs

The target manifest records why every host was selected or excluded.

## New options

```text
--port-scan / --naabu
--port-scan-limit 50
--naabu-top-ports 100|1000
--naabu-ports 22,80,443,8000-8100
--naabu-rate 100
--naabu-threads 25
--naabu-retries 2
--naabu-socket-timeout 1500
--naabu-scan-all-ips
--port-scan-timeout 1800
--port-scan-include-cdn
--port-scan-include-third-party
--nmap-service-scan / --nmap
--nmap-workers 2
--nmap-host-timeout 5m
```

## Recommended bounded maximum command

```cmd
run-max-v8.3-portscan.cmd testasp.vulnweb.com
```

Direct one-line form:

```cmd
py -3 .\smart_subdomain_pipeline_v8_modular.py --target testasp.vulnweb.com --authorized --max --active-waf --port-scan --naabu-top-ports 1000 --naabu-rate 100 --naabu-threads 25 --nmap-service-scan --nmap-workers 2 --nmap-host-timeout 5m
```

## New outputs

```text
port_scan_target_manifest.json
port_scan_target_manifest.csv
port_scan_targets.txt
naabu_ports.jsonl
naabu_ports.json
naabu_ports.csv
nmap\*.xml
nmap_services.json
nmap_services.csv
port_scan_summary.json
```

The results are also summarized in `summary.json` and `final_report.md`.

## Verification

```cmd
py -3 -m compileall .
py -3 -m pytest -q
py -3 .\smart_subdomain_pipeline_v8_modular.py --help
```

Expected regression result for this package: `16 passed`.

## V8.4.1 active-scan safety correction

Before Naabu or Nmap target selection, DNS CNAME ownership now takes precedence over HTTP classification. Delegated Microsoft 365/Outlook/Azure/Entra/Intune, SolarWinds, HubSpot, SendGrid, Google-hosted, GitHub Pages, Heroku, and similar third-party services are excluded by default even when HTTPX has no successful record for the hostname.

Generic WAFW00F detections are recorded as `Generic/Unknown WAF` with medium confidence. Conflicting named passive and active WAF providers are retained as `conflicting_or_multi_layer` with medium confidence rather than silently replacing one another.

