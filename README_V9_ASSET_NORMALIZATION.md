# 0xCrawller V9 — Asset Validation and Normalization

V9 is an offline evidence-normalization engine. It does not contact targets or the internet. It consumes one completed V8.5.1 recon run and produces one canonical record per host, service, and endpoint.

## Outputs

- `asset_inventory.json` / `.csv`
- `service_inventory.json` / `.csv`
- `endpoint_inventory.json` / `.csv`
- `asset_relationships.json`
- `asset_conflicts.json`
- `asset_revalidation_queue.json`
- `testing_eligibility.json`
- `normalization_summary.json`
- `asset_normalization_report.md`

## Install

Copy these files into the same directory that contains:

```text
smart_subdomain_pipeline_v8_modular.py
recon_runs\
```

## Run latest target folder

```cmd
python .\vapt_asset_normalizer_v9.py --target sky47.com.pk --latest-root .\recon_runs --overwrite
```

or:

```cmd
run-v9-normalize.cmd sky47.com.pk
```

## Run an exact folder

```cmd
python .\vapt_asset_normalizer_v9.py --run-dir .\recon_runs\sky47.com.pk-20260728-153413 --overwrite
```

Default output:

```text
<run-folder>\normalization_v9\
```

## Policy behavior

- Third-party CNAME/SaaS assets: passive only, blocked from active testing.
- CDN/shared-edge assets: web-vhost and TLS checks allowed; network/OpenVAS routing blocked by default.
- Direct first-party candidates with current confirmed services: eligible for bounded web and network checks.
- Historical, unresolved, and passive-only assets: placed in the revalidation queue.
- Naabu observations are not considered open unless Nmap confirms them.
- Shodan remains passive historical evidence and does not override current DNS/Nmap results.
- Suspicious crawler-derived URLs are quarantined for HTTP revalidation.
