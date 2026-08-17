# Smart Recon V8.2 — CDN, Wappalyzer and WAF Detection

This update adds a structured edge-detection layer to the existing V8.1 pipeline.

## Detection layers

### Passive and automatic

Every HTTPX root/host probe now records:

- Wappalyzer-based technology detection through `httpx -tech-detect`
- HTTPX CDN/WAF provider detection through `httpx -cdn`
- IP, CNAME and ASN evidence
- CDN provider, confidence and evidence source
- passive WAF/security-edge provider, confidence and evidence source
- technology fingerprints per host

Passive detection runs without a new CLI flag.

### Optional active WAF fingerprinting

Use `--active-waf` or `--wafw00f` to run WAFW00F against a bounded set of live, first-party URLs.

WAFW00F can send payload-like requests to distinguish WAF products. Only enable it against explicitly authorized targets.

The first active run automatically builds this local image:

```text
smartrecon/wafw00f:2.4.2
```

The generated Dockerfile pins WAFW00F 2.4.2.

## Files to replace

Copy the complete `smart_recon` folder over your existing folder. The changed or new modules are:

```text
smart_recon/__init__.py
smart_recon/classification.py
smart_recon/cli.py
smart_recon/commands.py
smart_recon/config.py
smart_recon/edge_detection.py        NEW
smart_recon/pipeline.py
smart_recon/reporting.py
smart_recon/runtime.py
```

The entry point remains:

```text
smart_subdomain_pipeline_v8_modular.py
```

## Passive-only command

This still performs Wappalyzer technology and HTTPX CDN/WAF detection:

```cmd
py -3 .\smart_subdomain_pipeline_v8_modular.py --target hiapp.pk --authorized --max
```

## Active WAF command

```cmd
py -3 .\smart_subdomain_pipeline_v8_modular.py --target hiapp.pk --authorized --max --active-waf --waf-limit 15 --waf-request-timeout 7 --waf-stage-timeout 900
```

More complete controlled command:

```cmd
py -3 .\smart_subdomain_pipeline_v8_modular.py --target hiapp.pk --authorized --max --dnsx-workers 3 --dnsx-chunk-size 25000 --dnsx-threads 50 --dnsx-rate-limit 100 --katana-depth 3 --katana-concurrency 10 --katana-rate-limit 50 --katana-duration 10m --active-waf --waf-limit 15 --waf-request-timeout 7 --waf-stage-timeout 900
```

Do not add `--waf-include-third-party` unless the third-party SaaS/CDN providers are explicitly included in your authorization.

## New outputs

```text
edge_detection_summary.json
waf_targets.txt
waf_detection.json
waf_detection.csv
wafw00f.json                    only when active WAF fingerprinting runs
```

The existing files are enriched:

```text
http_review_classification.json
http_review_classification.csv
summary.json
final_report.md
tool_versions.json
command_manifest.json
```

## Key fields per HTTP asset

```json
{
  "technologies": ["Cloudflare", "React"],
  "cdn_detection": {
    "detected": true,
    "provider": "Cloudflare",
    "confidence": "high",
    "evidence": []
  },
  "waf_detection": {
    "detected": true,
    "provider": "Cloudflare",
    "confidence": "high",
    "mode": "passive",
    "evidence": []
  }
}
```

When WAFW00F confirms a product, `waf_detection.mode` becomes `active_fingerprinting` and the active match is preserved separately.

## Verification

```cmd
py -3 -m compileall .\smart_recon
py -3 -m pytest -q .\tests
py -3 .\smart_subdomain_pipeline_v8_modular.py --help
```
