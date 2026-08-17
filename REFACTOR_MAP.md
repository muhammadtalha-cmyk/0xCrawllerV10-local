# V8.1 module map

| Concern | Module |
|---|---|
| CLI and new limits/workers | `smart_recon/cli.py` |
| Static defaults and provider map | `smart_recon/config.py` |
| Hostname/domain validation | `smart_recon/validation.py` |
| Keyword quality and candidate tiers | `smart_recon/keywords.py` |
| Docker commands and current tool flags | `smart_recon/commands.py` |
| Container timeout/cleanup and diagnostics | `smart_recon/runtime.py` |
| DNS and discovery parsing | `smart_recon/parsers.py` |
| HTTP/endpoint/ownership classification | `smart_recon/classification.py` |
| Screenshot prioritization/coverage | `smart_recon/screenshots.py` |
| Main stage orchestration and DNS sharding | `smart_recon/pipeline.py` |
| Markdown/CSV reporting | `smart_recon/reporting.py` |
| Regression tests | `tests/test_v81_core.py` |
