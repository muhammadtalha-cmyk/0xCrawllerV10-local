# Smart Recon V8.4.1 safety correction

This update fixes three evidence-handling issues found in the Sky47 report:

1. DNS CNAME ownership now has precedence over HTTP classification for active port-scan target selection. Microsoft 365, Outlook, Azure/Entra, Intune, SolarWinds, SendGrid, HubSpot, Google-hosted, GitHub Pages, Heroku, and similar delegated services are excluded by default even when HTTPX has no record for the hostname.
2. A generic WAFW00F detection is reported as `Generic/Unknown WAF` with medium confidence, not high confidence.
3. Conflicting named WAF evidence is retained as `conflicting_or_multi_layer` with medium confidence instead of silently replacing the passive outer-edge provider.

The port scan manifest now includes `ownership_source` and `waf_attribution`.
