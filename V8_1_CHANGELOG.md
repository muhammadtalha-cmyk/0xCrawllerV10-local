# V8.1 change log

## Correctness

1. Invalid DNS labels are rejected rather than rewritten.
2. Root and nested wildcard zones use repeated probes.
3. Exact wildcard-matching discoveries are retained but clearly marked; generated wildcard matches are not promoted as independent active assets.
4. Previous-run assets are not silently counted as current validation when revalidation fails.
5. Private IP findings only come from target-response fields, not screenshot browser networking metadata.
6. Endpoint classification uses normalized URLs, path segments, extensions, and ownership context.
7. External and third-party references are isolated from the in-scope endpoint list.

## Performance

1. Duplicate HTTP/HTTPS Katana crawls were replaced by an HTTPX canonical-root probe and one bounded crawl.
2. DNSX bulk candidates use medium non-overlapping chunks and a fixed worker pool.
3. Failed DNSX chunks can be retried at reduced concurrency/rate without rerunning completed chunks.
4. Candidate generation is bounded in normal/max modes and noisy URL tokens are removed before permutations.

## Reporting

1. Runs are COMPLETE, PARTIAL, or FAILED.
2. DNS coverage shows processed input, total input, chunk completion, and percentage.
3. Tool warnings and errors are separated.
4. Screenshot eligibility, selection, skips, and percentage are shown.
5. Compatibility `confirmed_subdomains.*` files remain, but the preferred names are `validated_dns_hosts.*`.
