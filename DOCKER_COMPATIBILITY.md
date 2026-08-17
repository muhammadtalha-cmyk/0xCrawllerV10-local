# Installed Docker compatibility audit (2026-07-27)

The commands were checked against the locally installed image entrypoints,
version output, and help output. Every image entrypoint is already the tool
binary, so the pipeline correctly supplies tool arguments directly after the
image name.

| Tool | Image | Installed version | Image ID (short) | Current generated flags | Invalid/conflicting flags found | Correct/verified flags | Result |
|---|---|---|---|---|---|---|---|
| Subfinder | `projectdiscovery/subfinder:latest` | `v2.14.0` | `8953620e5248` | `-d -all -recursive -silent -o` | None | All generated flags appear in `-h`; `/output` is mounted | Compatible |
| Amass | `owaspamass/amass:latest` | `v5.1.1` | `79c06d6c8de0` | `enum -passive -d` or explicit `enum -active -brute -d` | None | Active brute force remains opt-in through `--amass-active`/`--exhaustive` | Compatible |
| BBOT | `blacklanternsecurity/bbot:stable` | `3.0.0` | `dcd175e05e45` | `-t TARGET -p subdomain-enum` | None | Preset is listed by `--help`; missing optional keys remain warnings when BBOT exits successfully | Compatible |
| Gobuster | `ghcr.io/oj/gobuster:latest` | `3.8.2` | `c00e970a4861` | `dns --domain -w -t --timeout -o --no-color` | Suggested audit command `version` is invalid for this image | Version uses `--version`; pipeline DNS flags are supported; timeout raised from `3s` to `5s` | Compatible |
| Katana | `projectdiscovery/katana:latest` | `v1.6.1` | `a05d8460d34d` | `-u -d -jc -kf all -fs fqdn -iqp -ct -c -rl -mrs -ef -silent -o` | Old `-kf robotstxt,sitemapxml` is invalid; known files require depth at least 3; old `-fs rdn` was broader than the canonical host | `-kf all`; effective depth at least 3; `-fs fqdn`; duration such as `2m` | Compatible after fix |
| DNSX | `projectdiscovery/dnsx:latest` | `1.2.2` | `8fced0bedf36` | `-l -a -aaaa -cname -resp -t -rl -retry -j -omit-raw -silent -o` | None | `-j` is this version's JSONL flag; retries must be at least 1 | Compatible |
| HTTPX | `projectdiscovery/httpx:latest` | `v1.10.0` | `e2f89a700e53` | `-l -silent -json` plus probes; screenshot flags `-screenshot -exclude-screenshot-bytes -exclude-headless-body -srd -o` | None | `-json` aliases JSONL in this version; all detailed and screenshot flags appear in `-h` | Compatible |

Windows bind mounts use resolved absolute paths in the form
`E:\path\to\run:/output`, which Docker Desktop accepts. Tool output paths use
`/output/...`, placing results in the intended run directory. Runtime-generated
container names are unique and timeout cleanup force-removes the named
container before terminating the Windows process tree.

The effective global DNSX bulk rate is
`dnsx-workers × dnsx-rate-limit`; it is now recorded in
`dnsx_chunk_manifest.json`.
