# Technology fingerprinting tool selection

Reviewed in July 2026 for 0xCrawller V9.2.

| Tool | Selected version/image | Role | Selection reason |
|---|---|---|---|
| HTTPX/Wappalyzer | existing HTTPX lane | Fast baseline web fingerprints | Already integrated with recon and highly concurrent |
| WhatWeb | 0.6.4, local pinned image | Server/framework/CMS/plugin evidence | Broad plugin corpus and version-aware output |
| Wappalyzer Next | 2.0.0, local pinned image | Dynamic browser-backed fingerprints | Uses Chromium/Playwright and the Wappalyzer browser extension |
| Retire.js | 5.4.3, local pinned image | Client-side JavaScript versions | Specialized library/component and vulnerability metadata |
| ZGrab2 | official GHCR image | Database, cache, queue and protocol handshakes | Structured unauthenticated protocol transcripts across many service families |

A third-party Retire.js container was not adopted as the default because the project is very small and offers weaker provenance than building the official Retire.js release locally.

V9.2 does not use a single fingerprint as proof. It preserves source, confidence, exact/range/hidden version state, service-confirmation state, and conflicts.
