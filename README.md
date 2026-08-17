# Smart Subdomain Pipeline V8.1 (Correctness + Controlled Parallelism)

This is a drop-in replacement for the modular V8 package.

## Main corrections

- One canonical Katana crawl instead of duplicate HTTP and HTTPS crawls.
- Katana scope, duration, concurrency, rate, response-size, and extension controls.
- Evidence-aware keyword filtering that rejects hashes, dimensions, random IDs, numeric tokens, and one-off URL noise.
- Tiered, bounded DNS candidates. Exact discoveries and priority names are never removed by the cap.
- Explicit `--exhaustive` mode for low-confidence pair permutations.
- DNSX bulk input split into non-overlapping chunks processed by a fixed worker pool.
- Per-chunk manifests, retries, coverage percentages, and partial-run reporting.
- Multiple wildcard probes at relevant nested parent zones.
- Strict DNS hostname validation; invalid leading-hyphen and underscore candidates are rejected.
- Separate DNS validation states instead of treating every record as equally confirmed.
- Docker container naming and forced cleanup on timeout.
- Warning/error parsing no longer treats discovered URLs or JSON findings as warnings.
- Endpoint URL canonicalization and path-segment classification.
- Third-party SaaS/CDN ownership classification.
- Browser/container private IP metadata is excluded from leak findings.
- Screenshot selection and coverage are reported explicitly.

## Replace your existing files

Copy these files over the existing project:

```text
smart_recon/
smart_subdomain_pipeline_v7_render.py
smart_subdomain_pipeline_v8_modular.py
run_tests.ps1
```

Keep your existing `recon_runs` directory outside the replacement operation.

## Verify before a real run

```powershell
cd E:\crawllerPhase2\0xCrawllerV2\smart_subdomain_pipeline_v8_modular
.\run_tests.ps1
py -3 .\smart_subdomain_pipeline_v8_modular.py --help
```

## Recommended bounded max run

```powershell
py -3 .\smart_subdomain_pipeline_v8_modular.py `
  --target stay22.com `
  --authorized `
  --max `
  --dnsx-workers 3 `
  --dnsx-chunk-size 25000 `
  --dnsx-threads 50 `
  --dnsx-rate-limit 100 `
  --katana-concurrency 10 `
  --katana-rate-limit 50 `
  --katana-duration 10m
```

## Full low-confidence mode

```powershell
py -3 .\smart_subdomain_pipeline_v8_modular.py `
  --target example.com `
  --authorized `
  --max `
  --exhaustive
```

`--exhaustive` intentionally removes the normal candidate cap and enables pair permutations. Use it only when the authorization and time budget support the extra DNS workload.

## Amass behavior

Amass is passive by default. Use either of these to enable active/brute mode:

```powershell
--amass-active
```

or:

```powershell
--exhaustive
```

## Important outputs

- `summary.json`: overall status, required-stage failures, candidate statistics, and coverage.
- `dnsx_chunk_manifest.json`: every DNSX chunk, attempt count, status, and coverage.
- `candidate_manifest.jsonl`: candidate, tier, score, source, and keyword.
- `keyword_evidence.json`: accepted keywords and evidence.
- `rejected_keywords.json`: rejected random/noisy tokens and reasons.
- `validated_dns_hosts.*`: current-run DNS-validated assets.
- `wildcard_suspected_hosts.json`: records matching repeated wildcard signatures.
- `canonical_target.json`: root URL selected before Katana.
- `external_references.txt`: external URLs recorded separately.
- `openapi_candidates.txt`: normalized OpenAPI/Swagger document candidates.
- `final_report.md`: explicitly marked COMPLETE, PARTIAL, or FAILED.
