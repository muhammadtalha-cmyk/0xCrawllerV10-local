"""Keyword extraction, quality scoring, and bounded DNS candidate generation."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, unquote, urlparse

from .config import COMMON_WORDS, MUTATION_SUFFIXES, NOISE_WORDS, PRIORITY_CANDIDATE_LABELS
from .validation import normalize_candidate

DIMENSION_RE = re.compile(r"^\d{2,5}x\d{2,5}$", re.IGNORECASE)
HEX_RE = re.compile(r"^[a-f0-9]{8,}$", re.IGNORECASE)
UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", re.IGNORECASE)
BASE36ISH_RE = re.compile(r"^[a-z0-9]{8,}$", re.IGNORECASE)

QUERY_KEY_NOISE_RE = re.compile(
    r"^(?:__cf_|cf_|utm_|gclid$|fbclid$|msclkid$|yclid$|_ga$|_gl$|token$|signature$|sig$|nonce$|hash$)",
    re.IGNORECASE,
)
STATIC_PATH_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def split_to_words(text: str) -> set[str]:
    decoded = unquote(str(text)).replace("%5C", "/").replace("\\", "/")
    pieces = re.split(r"[^A-Za-z0-9-]+", decoded)
    output: set[str] = set()
    for piece in pieces:
        if not piece:
            continue
        camel = re.sub(r"([a-z])([A-Z])", r"\1 \2", piece)
        for sub in camel.split():
            for token in re.split(r"[-_]+", sub):
                if token:
                    output.add(token.lower())
    return output


def assess_keyword(word: str) -> dict[str, Any]:
    original = str(word or "").strip()
    value = original.lower().replace("_", "-")
    value = re.sub(r"[^a-z0-9-]", "", value).strip("-")
    result: dict[str, Any] = {
        "original": original,
        "keyword": value,
        "accepted": False,
        "reason": "",
        "score": 0,
    }
    if not value:
        result["reason"] = "empty_after_normalization"
        return result
    if value in NOISE_WORDS:
        result["reason"] = "known_noise_word"
        return result
    if len(value) < 3:
        result["reason"] = "too_short"
        return result
    if len(value) > 30:
        result["reason"] = "too_long"
        return result
    if DIMENSION_RE.fullmatch(value):
        result["reason"] = "image_dimension"
        return result
    if UUID_RE.fullmatch(value):
        result["reason"] = "uuid"
        return result
    if re.fullmatch(r"\d+", value):
        result["reason"] = "numeric_only"
        return result
    if HEX_RE.fullmatch(value):
        result["reason"] = "hex_or_build_hash"
        return result

    letters = sum(ch.isalpha() for ch in value)
    digits = sum(ch.isdigit() for ch in value)
    alnum = max(1, letters + digits)
    alpha_ratio = letters / alnum
    digit_ratio = digits / alnum
    entropy = shannon_entropy(value.replace("-", ""))

    known = value in set(COMMON_WORDS) or value in set(MUTATION_SUFFIXES)
    if not known and letters < 3:
        result["reason"] = "insufficient_letters"
        return result
    if digits and not known:
        numeric_suffix = re.fullmatch(r"([a-z][a-z-]{2,15})(\d{1,3})", value)
        prefix = numeric_suffix.group(1) if numeric_suffix else ""
        if not numeric_suffix or prefix not in set(COMMON_WORDS):
            result["reason"] = "mixed_alphanumeric_identifier"
            return result
    if not known and alpha_ratio < 0.70:
        result["reason"] = "low_alpha_ratio"
        return result
    if (
        not known
        and BASE36ISH_RE.fullmatch(value.replace("-", ""))
        and len(value.replace("-", "")) >= 8
        and digit_ratio >= 0.20
        and entropy >= 3.0
    ):
        result["reason"] = "high_entropy_alphanumeric_token"
        return result
    if not known and len(value) >= 12 and entropy >= 3.45 and "-" not in value:
        result["reason"] = "high_entropy_long_token"
        return result

    score = 60
    if known:
        score = 92
    elif value in PRIORITY_CANDIDATE_LABELS:
        score = 96
    elif "-" in value:
        score += 5
    if digits:
        score -= min(20, digits * 3)
    if len(value) > 18:
        score -= 10
    if entropy > 3.2:
        score -= 8

    result.update({
        "accepted": True,
        "reason": "accepted",
        "score": max(1, min(100, score)),
        "alpha_ratio": round(alpha_ratio, 3),
        "digit_ratio": round(digit_ratio, 3),
        "entropy": round(entropy, 3),
    })
    return result


def filter_keywords(words: Iterable[str]) -> set[str]:
    return {
        assessment["keyword"]
        for assessment in (assess_keyword(word) for word in words)
        if assessment["accepted"]
    }


def filter_keywords_with_details(
    words: Iterable[str],
    *,
    source: str,
    context: str | None = None,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    accepted: dict[str, dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    for word in words:
        assessment = assess_keyword(word)
        assessment["source"] = source
        if context:
            assessment["context"] = context[:500]
        if assessment["accepted"]:
            keyword = assessment["keyword"]
            current = accepted.get(keyword)
            if current is None or int(assessment["score"]) > int(current["score"]):
                accepted[keyword] = assessment
        else:
            rejected.append(assessment)
    return accepted, rejected


def keyword_tokens_from_url(url: str, target: str) -> set[str]:
    """Extract stable URL vocabulary without consuming query parameter values.

    Query values commonly contain Cloudflare challenge tokens, tracking IDs, JWTs,
    hashes, and campaign identifiers. Those values caused random strings to be
    promoted into DNS candidates. Only in-scope host labels, path segments, and
    non-noisy query *names* are eligible.
    """
    raw = unquote(str(url)).replace("\\", "/")
    parsed = urlparse(raw if re.match(r"^[a-zA-Z]+://", raw) else "https://" + raw)
    words: set[str] = set()
    host = (parsed.hostname or "").lower()
    if host and (host == target or host.endswith("." + target)):
        labels = host[:-len(target)].strip(".").split(".") if host != target else []
        for label in labels:
            words |= split_to_words(label)

    # Keep meaningful route vocabulary. Static file stems are still allowed, but
    # their extensions and query values are not.
    for segment in (parsed.path or "/").split("/"):
        segment = segment.strip()
        if not segment:
            continue
        lowered = segment.lower()
        for suffix in STATIC_PATH_SUFFIXES:
            if lowered.endswith(suffix):
                segment = segment[: -len(suffix)]
                break
        words |= split_to_words(segment)

    try:
        query_keys = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    except ValueError:
        query_keys = []
    for key in query_keys:
        if QUERY_KEY_NOISE_RE.search(key):
            continue
        words |= split_to_words(key)
    return words


def extract_keywords_from_url(url: str, target: str) -> set[str]:
    words: set[str] = set()
    raw = unquote(str(url)).replace("\\", "/")
    parsed = urlparse(raw if re.match(r"^[a-zA-Z]+://", raw) else "https://" + raw)
    host = (parsed.hostname or "").lower()
    if host and (host == target or host.endswith("." + target)):
        labels = host[:-len(target)].strip(".").split(".") if host != target else []
        for label in labels:
            words |= split_to_words(label)
    words |= keyword_tokens_from_url(url, target)
    return filter_keywords(words)


def _add_candidate(
    records: dict[str, dict[str, Any]],
    *,
    host: str,
    target: str,
    tier: int,
    score: int,
    source: str,
    keyword: str | None = None,
) -> None:
    normalized = normalize_candidate(host, target)
    if not normalized:
        return
    candidate = {
        "candidate": normalized,
        "tier": tier,
        "score": max(0, min(100, int(score))),
        "source": source,
        "keyword": keyword,
    }
    existing = records.get(normalized)
    if existing is None or (candidate["tier"], -candidate["score"]) < (existing["tier"], -existing["score"]):
        records[normalized] = candidate


def generate_candidate_records(
    target: str,
    keyword_evidence: Mapping[str, Mapping[str, Any]],
    *,
    exact_hosts: Iterable[str],
    previous_hosts: Iterable[str] = (),
    max_mode: bool,
    exhaustive: bool,
    candidate_limit: int | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Generate deterministic tiered candidates without silently discarding exact discoveries."""
    records: dict[str, dict[str, Any]] = {}

    _add_candidate(records, host=target, target=target, tier=0, score=100, source="root_target")
    for host in exact_hosts:
        _add_candidate(records, host=host, target=target, tier=0, score=100, source="exact_tool_discovery")
    for host in previous_hosts:
        _add_candidate(records, host=host, target=target, tier=0, score=99, source="previous_run")
    for label in PRIORITY_CANDIDATE_LABELS:
        _add_candidate(
            records,
            host=f"{label}.{target}",
            target=target,
            tier=1,
            score=98,
            source="priority_curated",
            keyword=label,
        )
    for word in COMMON_WORDS:
        _add_candidate(
            records,
            host=f"{word}.{target}",
            target=target,
            tier=1,
            score=92,
            source="common_curated",
            keyword=word,
        )

    ranked_keywords = sorted(
        keyword_evidence.items(),
        key=lambda item: (-int(item[1].get("score", 0)), item[0]),
    )
    for word, evidence in ranked_keywords:
        score = int(evidence.get("score", 60))
        source = str(evidence.get("source") or "target_derived")
        tier = 1 if score >= 90 else 2
        _add_candidate(
            records,
            host=f"{word}.{target}",
            target=target,
            tier=tier,
            score=score,
            source=source,
            keyword=word,
        )

    mutation_map: dict[str, tuple[int, str]] = {
        word: (int(evidence.get("score", 60)), str(evidence.get("source") or "target_derived"))
        for word, evidence in ranked_keywords
        if int(evidence.get("score", 60)) >= 55
    }
    for word in COMMON_WORDS:
        mutation_map.setdefault(word, (92, "common_curated"))
    mutation_words = [
        (word, score, source)
        for word, (score, source) in sorted(mutation_map.items(), key=lambda item: (-item[1][0], item[0]))
    ]
    if not max_mode:
        mutation_words = mutation_words[:250]
        suffixes = ["dev", "test", "uat", "api", "admin", "app", "portal"]
    else:
        mutation_words = mutation_words[:2_000]
        suffixes = MUTATION_SUFFIXES

    for word, base_score, source in mutation_words:
        for suffix in suffixes:
            if word == suffix:
                continue
            mutation_score = max(30, base_score - 15)
            _add_candidate(
                records,
                host=f"{word}-{suffix}.{target}",
                target=target,
                tier=2,
                score=mutation_score,
                source=f"mutation:{source}",
                keyword=word,
            )
            _add_candidate(
                records,
                host=f"{suffix}-{word}.{target}",
                target=target,
                tier=2,
                score=mutation_score,
                source=f"mutation:{source}",
                keyword=word,
            )

    if exhaustive:
        pair_words = [word for word, score, _ in mutation_words if 3 <= len(word) <= 14 and score >= 45][:500]
        for first_index, first in enumerate(pair_words):
            for second in pair_words[first_index + 1:]:
                if len(first) + len(second) > 24:
                    continue
                _add_candidate(
                    records,
                    host=f"{first}-{second}.{target}",
                    target=target,
                    tier=3,
                    score=25,
                    source="exhaustive_pair_permutation",
                    keyword=f"{first},{second}",
                )
                _add_candidate(
                    records,
                    host=f"{second}-{first}.{target}",
                    target=target,
                    tier=3,
                    score=25,
                    source="exhaustive_pair_permutation",
                    keyword=f"{second},{first}",
                )

    all_sorted = sorted(records.values(), key=lambda item: (item["tier"], -item["score"], item["candidate"]))
    exact_and_priority = [item for item in all_sorted if item["tier"] <= 1]
    lower_tiers = [item for item in all_sorted if item["tier"] > 1]

    truncated = False
    dropped = 0
    if candidate_limit is not None and candidate_limit > 0:
        remaining_slots = max(0, candidate_limit - len(exact_and_priority))
        if len(lower_tiers) > remaining_slots:
            truncated = True
            dropped = len(lower_tiers) - remaining_slots
            lower_tiers = lower_tiers[:remaining_slots]
    selected = exact_and_priority + lower_tiers
    selected_records = {item["candidate"]: item for item in selected}

    stats = {
        "generated_before_limit": len(records),
        "selected_after_limit": len(selected_records),
        "candidate_limit": candidate_limit,
        "truncated": truncated,
        "dropped_by_limit": dropped,
        "tier_counts": {
            str(tier): sum(1 for item in selected if item["tier"] == tier)
            for tier in range(4)
        },
    }
    return selected_records, stats


def generate_candidates(target: str, words: Iterable[str], max_mode: bool) -> set[str]:
    """Compatibility wrapper retained for external imports."""
    evidence = {word: assess_keyword(word) for word in filter_keywords(words)}
    records, _ = generate_candidate_records(
        target,
        evidence,
        exact_hosts=(),
        max_mode=max_mode,
        exhaustive=False,
        candidate_limit=None,
    )
    return set(records)
