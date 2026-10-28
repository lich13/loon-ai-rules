#!/usr/bin/env python3
"""Build public Loon/mihomo rule lists; never read application or client data."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


META_REPOSITORY = "https://github.com/MetaCubeX/meta-rules-dat"
META_HEAD = "https://api.github.com/repos/MetaCubeX/meta-rules-dat/commits/meta"
META_RAW = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat"
KELEE_URL = "https://kelee.one/Tool/Loon/Lsr/AI.lsr"
LOON_USER_AGENT = "Loon/1005 CFNetwork/3860.600.31 Darwin/25.0.0"
CLAUDE_SUFFIXES = frozenset((
    "anthropic.com", "clau.de", "claude.ai", "claude.com", "claude.dev",
    "claudemcpclient.com", "claudemcpcontent.com", "claudeusercontent.com",
))
CLAUDE_EXTRA = (
    "DOMAIN-SUFFIX,claude.app",
    "IP-CIDR,160.79.104.0/23,no-resolve",
    "IP-CIDR6,2607:6bc0::/48,no-resolve",
)
CLAUDE_COMPATIBILITY = (
    "DOMAIN,anthropic.auth0.com",
    "DOMAIN,anthropic-com.ghost.io",
    "DOMAIN,anthropic.com.cdn.cloudflare.net",
    "DOMAIN-SUFFIX,sentry.io",
    "DOMAIN-SUFFIX,statsigapi.net",
)
CURSOR_SUFFIXES = frozenset(("cursor-cdn.com", "cursor.com", "cursor.sh", "cursorapi.com"))
CURSOR_EXTRA = (
    "DOMAIN-SUFFIX,cursorvm.com",
    "DOMAIN,anysphere-binaries.s3.us-east-1.amazonaws.com",
)
SHARED_INFRASTRUCTURE = frozenset((
    "sentry.io", "statsigapi.net", "datadoghq.com", "datadoghq.eu",
    "sift.com", "siftscience.com", "intercom.io", "intercomcdn.com",
    "cloudflare.com", "cloudflare.net", "b-cdn.net", "auth0.com", "ghost.io",
    "usefathom.com", "github.com", "githubusercontent.com", "googleapis.com",
))
AZURE_REGEX = r"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$"
ALLOWED_CONJUNCTIONS = frozenset((
    ("chatgpt-async-webps-prod-", "webpubsub.azure.com"),
    ("openaicom-api-", "azurefd.net"),
    ("antigravity-auto-updater-", "run.app"),
    # Google Drive file content hosts look like doc-0s-2c-docs.googleusercontent.com.
    ("-docs", "googleusercontent.com"),
))
# Google-operated single-label TLDs present in MetaCubeX google/youtube; any other
# single-label suffix (for example "com") is rejected.
REVIEWED_TLDS = frozenset((
    "android", "chrome", "dclk", "gbiz", "gle", "gmail", "goog", "google", "guge",
    "hangout", "nexus", "xn--flw351e", "xn--qcka1pmc", "youtube",
))
# Google Play download regexes in MetaCubeX google; dropped only when the named
# suffix is published (googlevideo.com in HighTraffic, xn--ngstr-lra8j.com in Google).
COVERED_REGEXES = {
    r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.xn--ngstr-lra8j\.com$": "DOMAIN-SUFFIX,xn--ngstr-lra8j.com",
    r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$": "DOMAIN-SUFFIX,googlevideo.com",
}
HIGH_TRAFFIC_UPSTREAMS = ("youtube", "twitch", "tiktok")
# Drive / Photos file content only; account, search, API and web UI stay in Google.list.
GOOGLE_CONTENT_HOSTS = (
    "DOMAIN,drive.usercontent.google.com",
    "DOMAIN,docs.googleusercontent.com",
    "AND,((DOMAIN-KEYWORD,-docs),(DOMAIN-SUFFIX,googleusercontent.com))",
    "DOMAIN,video-downloads.googleusercontent.com",
    "DOMAIN,photos.fife.usercontent.google.com",
    "DOMAIN,lh3.googleusercontent.com",
    "DOMAIN,lh4.googleusercontent.com",
    "DOMAIN,lh5.googleusercontent.com",
    "DOMAIN,lh6.googleusercontent.com",
)
GITHUB_DOWNLOAD_HOSTS = (
    "DOMAIN,objects.githubusercontent.com",
    "DOMAIN,release-assets.githubusercontent.com",
    "DOMAIN,raw.githubusercontent.com",
    "DOMAIN,media.githubusercontent.com",
    "DOMAIN,codeload.github.com",
    "DOMAIN,github-releases.githubusercontent.com",
    "DOMAIN,pkg-containers.githubusercontent.com",
    "DOMAIN-SUFFIX,ghcr.io",
)
# Exact storage hosts taken from MetaCubeX github.list and moved to HighTraffic.
GITHUB_MOVED_RE = re.compile(
    r"DOMAIN,(?:github-production-[a-z0-9-]+\.s3\.amazonaws\.com|github-cloud\.s3\.amazonaws\.com"
    r"|productionresultssa\d{1,2}\.blob\.core\.windows\.net)"
)
# Whole shared suffixes that must never be routed as high traffic.
HIGH_TRAFFIC_FORBIDDEN = (
    "google.com", "googleapis.com", "googleusercontent.com", "usercontent.google.com",
    "github.com", "githubusercontent.com", "amazonaws.com", "s3.amazonaws.com",
    "blob.core.windows.net", "cloudfront.net", "akamaized.net", "edgesuite.net",
)
OUTPUT_NAMES = ("HighTraffic.list", "AI-Meta.list", "AI-Kelee.list", "GitHub.list", "Google.list")
DOMAIN_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")


class RuleError(ValueError):
    pass


def conjunction(keyword, suffix):
    return f"AND,((DOMAIN-KEYWORD,{keyword}),(DOMAIN-SUFFIX,{suffix}))"


def parse_rule(line):
    """Accept only the audited cross-client grammar, without dropping unknown rules."""
    parts = [part.strip() for part in line.strip().split(",")]
    kind = parts[0]
    if kind in ("DOMAIN", "DOMAIN-SUFFIX") and len(parts) == 2:
        domain = parts[1].lower()
        if kind == "DOMAIN-SUFFIX" and domain in REVIEWED_TLDS:
            return f"{kind},{domain}"
        if not DOMAIN_RE.fullmatch(domain):
            raise RuleError("invalid domain")
        return f"{kind},{domain}"
    if kind == "DOMAIN-REGEX" and len(parts) == 2 and parts[1] == AZURE_REGEX:
        return conjunction("chatgpt-async-webps-prod-", "webpubsub.azure.com")
    if kind == "AND":
        compact = re.sub(r"\s+", "", line)
        for keyword, suffix in ALLOWED_CONJUNCTIONS:
            if compact in (
                conjunction(keyword, suffix),
                f"AND,((DOMAIN-SUFFIX,{suffix}),(DOMAIN-KEYWORD,{keyword}))",
            ):
                return conjunction(keyword, suffix)
        raise RuleError("unknown logical rule")
    if kind in ("IP-CIDR", "IP-CIDR6") and len(parts) == 3 and parts[2] == "no-resolve":
        try:
            network = ipaddress.ip_network(parts[1], strict=True)
        except ValueError as error:
            raise RuleError("invalid IP network") from error
        if network.version != (4 if kind == "IP-CIDR" else 6):
            raise RuleError("IP rule family mismatch")
        normalized = f"{kind},{network},no-resolve"
        if normalized not in CLAUDE_EXTRA:
            raise RuleError("unreviewed IP network")
        return normalized
    raise RuleError(f"unsupported rule type or syntax: {kind[:32]}")


def printable(text, limit=120):
    """Upstream text is shown in logs only after removing control characters and truncating."""
    text = "".join(char if char.isprintable() else "?" for char in text)
    return text if len(text) <= limit else text[:limit] + "..."


def parse_rules(text, source, warnings=None):
    """Parse a source. Without a warnings list any unsupported rule is an error;
    with one, that single rule is skipped and reported instead."""
    if len(text.encode("utf-8")) > 2_000_000:
        raise RuleError(f"{source}: source is too large")
    rules, skipped, total = set(), 0, 0
    for number, line in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        total += 1
        try:
            rules.add(parse_rule(line))
        except RuleError as error:
            if warnings is None:
                raise RuleError(f"{source}:{number}: {error}") from error
            skipped += 1
            warnings.append(f"{source}:{number}: skipped {printable(line)} ({error})")
    if not rules:
        raise RuleError(f"{source}: empty rules")
    # Many unusable lines means the download is not a rule list (for example an HTML page).
    if skipped > 5 and skipped * 5 > total:
        raise RuleError(f"{source}: {skipped} of {total} lines are not supported rules")
    return rules


def strip_covered_regexes(text, source, warnings=None):
    """Remove reviewed regexes that a published suffix rule fully covers; unreviewed
    regexes are an error, or skipped with a warning when a warnings list is given."""
    kept, required = [], set()
    for line in text.lstrip("\ufeff").splitlines():
        stripped = line.strip()
        if stripped.startswith("DOMAIN-REGEX,"):
            pattern = stripped.split(",", 1)[1].strip()
            if pattern not in COVERED_REGEXES:
                if warnings is None:
                    raise RuleError(f"{source}: unreviewed regex rule")
                warnings.append(f"{source}: skipped unreviewed regex rule {printable(stripped)}")
                continue
            required.add(COVERED_REGEXES[pattern])
            continue
        kept.append(line)
    return "\n".join(kept) + "\n", required


def covered_by(rule, rules):
    if rule in rules:
        return True
    kind, value, *_ = rule.split(",")
    if kind not in ("DOMAIN", "DOMAIN-SUFFIX"):
        return False
    return any(
        other.startswith("DOMAIN-SUFFIX,")
        and (value == other.split(",")[1] or value.endswith("." + other.split(",")[1]))
        for other in rules
    )


def compact_rules(rules):
    rules = set(rules)
    return sorted(rule for rule in rules if not covered_by(rule, rules - {rule}))


def domain_matches(rules, domain):
    """Small independent input surface for coverage guards and fixture checks."""
    for rule in rules:
        kind, value, *_ = rule.split(",")
        if kind == "DOMAIN" and domain == value:
            return True
        if kind == "DOMAIN-SUFFIX" and (domain == value or domain.endswith("." + value)):
            return True
        if kind == "AND":
            for keyword, suffix in ALLOWED_CONJUNCTIONS:
                if rule == conjunction(keyword, suffix) and keyword in domain and domain.endswith("." + suffix):
                    return True
    return False


LIST_ORDER = OUTPUT_NAMES  # client match order: HighTraffic, AI-Meta, AI-Kelee, GitHub, Google
# Inputs of each published list; a missing input makes only that list fall back.
LIST_INPUTS = {
    "AI-Meta.list": ("meta_ai", "meta_claude", "meta_cursor"),
    "AI-Kelee.list": ("kelee",),
    "HighTraffic.list": ("meta_youtube", "meta_twitch", "meta_tiktok", "meta_github"),
    "GitHub.list": ("meta_github",),
    "Google.list": ("meta_google",),
}
MIN_RULES = {"HighTraffic.list": 50, "AI-Meta.list": 10, "AI-Kelee.list": 1, "GitHub.list": 10, "Google.list": 100}
SOURCE_LABELS = {
    "meta_ai": "Meta AI", "meta_claude": "Meta Anthropic", "meta_cursor": "Meta Cursor",
    "meta_youtube": "Meta YouTube", "meta_twitch": "Meta Twitch", "meta_tiktok": "Meta TikTok",
    "meta_github": "Meta GitHub", "meta_google": "Meta Google", "kelee": "Kelee AI",
}


def domain_only(rules, source, warnings):
    """Upstreams that must be domain lists: skip any other rule with a warning."""
    kept = set()
    for rule in rules:
        if rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")):
            kept.add(rule)
        else:
            warnings.append(f"{source}: skipped non-domain rule {rule}")
    return kept


def drop_matching(rules, domains, source, reason, warnings, keep=()):
    """Drop rules that would route a whole shared/unrelated domain (or its subdomains)."""
    kept = set()
    for rule in rules:
        if rule not in keep and any(
            domain_matches({rule}, domain) or domain_matches({rule}, "unrelated." + domain) for domain in domains
        ):
            warnings.append(f"{source}: skipped {rule} ({reason})")
            continue
        kept.add(rule)
    return kept


def require(rules, domains, message):
    if not all(domain_matches(rules, domain) for domain in domains):
        raise RuleError(message)


def build_ai_meta(meta_ai, meta_claude, meta_cursor, warnings):
    ai = parse_rules(meta_ai, "Meta AI", warnings)
    claude = domain_only(parse_rules(meta_claude, "Meta Anthropic", warnings), "Meta Anthropic", warnings)
    cursor = domain_only(parse_rules(meta_cursor, "Meta Cursor", warnings), "Meta Cursor", warnings)
    if not all(f"DOMAIN-SUFFIX,{domain}" in cursor for domain in CURSOR_SUFFIXES):
        raise RuleError("Meta Cursor: source lost required domains")
    cursor = drop_matching(cursor, SHARED_INFRASTRUCTURE | CLAUDE_SUFFIXES | {
        "claude.app", "x.com", "twitter.com", "spacex.ai", "amazonaws.com",
        "s3.us-east-1.amazonaws.com", "chatgpt.com", "openai.com", "google.com",
        "grok.com", "x.ai", "grokipedia.com", "grokusercontent.com",
    }, "Meta Cursor", "unrelated service or shared infrastructure", warnings,
        keep={f"DOMAIN-SUFFIX,{domain}" for domain in CURSOR_SUFFIXES})
    cursor.update(CURSOR_EXTRA)
    require(claude, CLAUDE_SUFFIXES, "Anthropic source lost required domains")
    require(claude, ("servd-anthropic-website.b-cdn.net",), "Anthropic source lost the website CDN")
    claude = drop_matching(claude, SHARED_INFRASTRUCTURE | {"browser-intake-us5-datadoghq.com"},
                           "Meta Anthropic", "shared infrastructure or telemetry", warnings)
    claude.update(CLAUDE_EXTRA)
    claude.update(CLAUDE_COMPATIBILITY)
    # Guard Meta AI body size before merge so Claude alone cannot mask an empty AI source.
    ai_base = set(compact_rules(rule for rule in ai if not covered_by(rule, claude)))
    if len(ai_base) < 10:
        raise RuleError("incomplete AI sources")
    ai = drop_matching(ai, ("github.com",), "Meta AI", "entire GitHub site", warnings)
    # Merge Anthropic/Claude (core + extras + compatibility) and Cursor (core + extras).
    ai = set(compact_rules(ai | claude | cursor))
    require(ai, ("chatgpt.com", "api.openai.com", "gemini.google.com", "openrouter.ai",
                 "copilot-proxy.githubusercontent.com"), "Meta AI source lost required services")
    require(ai, CLAUDE_SUFFIXES, "AI-Meta lost required Claude domains after merge")
    if not all(covered_by(rule, ai) for rule in cursor):
        raise RuleError("AI-Meta lost required Cursor domains after merge")
    return ai


def build_ai_kelee(kelee, warnings):
    extra = parse_rules(kelee, "Kelee AI", warnings)
    return drop_matching(extra, ("github.com",), "Kelee AI", "entire GitHub site", warnings)


def github_storage(github_source):
    moved = {rule for rule in github_source if GITHUB_MOVED_RE.fullmatch(rule)}
    if not any("productionresultssa" in rule for rule in moved) or not any(".s3." in rule for rule in moved):
        raise RuleError("Meta GitHub: source lost download storage hosts")
    return moved


def parse_github(meta_github, warnings):
    rules = domain_only(parse_rules(meta_github, "Meta GitHub", warnings), "Meta GitHub", warnings)
    require(rules, ("github.com", "githubusercontent.com"), "Meta GitHub: source lost required domains")
    return rules


def build_high_traffic(meta_youtube, meta_twitch, meta_tiktok, meta_github, warnings):
    high = set()
    for key, domains in (
        ("meta_youtube", ("youtube.com", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com",
                          "youtube-nocookie.com")),
        ("meta_twitch", ("twitch.tv",)),
        ("meta_tiktok", ("tiktok.com",)),
    ):
        source = SOURCE_LABELS[key]
        text = {"meta_youtube": meta_youtube, "meta_twitch": meta_twitch, "meta_tiktok": meta_tiktok}[key]
        rules = domain_only(parse_rules(text, source, warnings), source, warnings)
        require(rules, domains, f"{source}: source lost required domains")
        high |= drop_matching(rules, HIGH_TRAFFIC_FORBIDDEN, source, "entire shared domain", warnings)
    high |= github_storage(parse_github(meta_github, warnings))
    return high | set(GOOGLE_CONTENT_HOSTS) | set(GITHUB_DOWNLOAD_HOSTS)


def build_github(meta_github, warnings):
    source = parse_github(meta_github, warnings)
    return source - github_storage(source) - set(GITHUB_DOWNLOAD_HOSTS)


def build_google(meta_google, warnings):
    text, required = strip_covered_regexes(meta_google, "Meta Google", warnings)
    rules = domain_only(parse_rules(text, "Meta Google", warnings), "Meta Google", warnings)
    require(rules, ("google.com", "googleapis.com", "play.google.com", "googleplay.com", "accounts.google.com"),
            "Meta Google: source lost required domains")
    build_google.required_suffixes = required
    return rules


build_google.required_suffixes = set()
BUILDERS = {
    "AI-Meta.list": build_ai_meta,
    "AI-Kelee.list": build_ai_kelee,
    "HighTraffic.list": build_high_traffic,
    "GitHub.list": build_github,
    "Google.list": build_google,
}


def reconcile(candidates, warnings):
    """Apply cross-list precedence: AI always wins; otherwise the earlier list in client order keeps a rule."""
    ai = set(compact_rules(candidates["AI-Meta.list"]))
    kelee = set(compact_rules(rule for rule in candidates["AI-Kelee.list"] if not covered_by(rule, ai)))
    ai_all = ai | kelee
    high = set()
    for rule in candidates["HighTraffic.list"]:
        if covered_by(rule, ai_all):
            warnings.append(f"HighTraffic: {rule} is already an AI rule; kept only in the AI lists")
            continue
        # HighTraffic is matched first, so a broader rule must not capture any AI host.
        shadowed = [other for other in ai_all if other.startswith(("DOMAIN,", "DOMAIN-SUFFIX,"))
                    and domain_matches({rule}, other.split(",", 1)[1])]
        if shadowed:
            warnings.append(f"HighTraffic: dropped {rule}; it would capture AI rule {sorted(shadowed)[0]}")
            continue
        high.add(rule)
    high = set(compact_rules(high))
    earlier = ai_all | high
    github = set(compact_rules(rule for rule in candidates["GitHub.list"] if not covered_by(rule, earlier)))
    earlier |= github
    google = set(compact_rules(rule for rule in candidates["Google.list"] if not covered_by(rule, earlier)))
    return {"HighTraffic.list": high, "AI-Meta.list": ai, "AI-Kelee.list": kelee,
            "GitHub.list": github, "Google.list": google}


def check_list(name, rules):
    """Post-merge guards for a freshly built list; failure falls back to the published version."""
    if name == "AI-Kelee.list" and not rules:
        raise RuleError("incomplete AI sources: Kelee adds nothing beyond AI-Meta")
    if len(rules) < MIN_RULES[name]:
        raise RuleError(f"{name}: too few rules after cross-list deduplication ({len(rules)})")
    if name == "GitHub.list":
        require(rules, ("github.com",), "GitHub list lost the main site")
    if name == "Google.list":
        require(rules, ("google.com", "googleapis.com", "play.google.com"), "Google list lost required domains")


def verify_invariants(result):
    names = list(result)
    for index, first in enumerate(names):
        for second in names[index + 1:]:
            if set(result[first]) & set(result[second]):
                raise RuntimeError(f"{first} and {second} share rules")
    ai_all = set(result["AI-Meta.list"]) | set(result["AI-Kelee.list"])
    for rule in ai_all:
        kind, value, *_ = rule.split(",")
        if kind in ("DOMAIN", "DOMAIN-SUFFIX") and domain_matches(result["HighTraffic.list"], value):
            raise RuntimeError("HighTraffic would capture an AI rule")


def build_lists(sources, previous=None, warnings=None):
    """Build every list independently.

    Returns (rules, status, failures). status[name] is "built", "kept" (previously
    published rules reused) or "missing" (no usable version; the file is not written).
    """
    previous = previous or {}
    warnings = [] if warnings is None else warnings
    failures = {}
    built = {}
    build_google.required_suffixes = set()
    for name in LIST_ORDER:
        missing = [SOURCE_LABELS[key] for key in LIST_INPUTS[name] if sources.get(key) is None]
        if missing:
            failures[name] = f"source unavailable: {', '.join(missing)}"
            continue
        try:
            built[name] = BUILDERS[name](*(sources[key] for key in LIST_INPUTS[name]), warnings=warnings)
        except RuleError as error:
            failures[name] = str(error)
    for _ in range(len(LIST_ORDER) + 1):
        status, candidates = {}, {}
        for name in LIST_ORDER:
            if name in built:
                status[name], candidates[name] = "built", built[name]
            elif previous.get(name):
                status[name], candidates[name] = "kept", set(previous[name])
            else:
                status[name], candidates[name] = "missing", set()
        trial = []
        result = reconcile(candidates, trial)
        late = {}
        for name in LIST_ORDER:
            if status[name] == "built":
                try:
                    check_list(name, result[name])
                except RuleError as error:
                    late[name] = str(error)
        if not late:
            break
        for name, message in late.items():
            failures[name] = message
            del built[name]
    else:  # pragma: no cover - each pass removes at least one list
        raise RuntimeError("list fallback did not converge")
    warnings.extend(trial)
    for name in LIST_ORDER:
        if status[name] == "kept":
            dropped = set(previous[name]) - result[name]
            if dropped:
                warnings.append(f"{name}: previous version kept; removed {len(dropped)} rules now owned by another list")
    if status["Google.list"] == "built":
        for suffix in sorted(build_google.required_suffixes):
            if suffix not in result["HighTraffic.list"] | result["Google.list"]:
                warnings.append(f"Meta Google: covered regex lost its published suffix {suffix}")
        if domain_matches(result["Google.list"], "www.youtube.com"):
            warnings.append("Google: YouTube is routed by Google.list because HighTraffic no longer covers it")
    verify_invariants(result)
    for name, message in failures.items():
        state = "keeping the previous version" if status[name] == "kept" else "no previous version to keep"
        failures[name] = f"{message} ({state})"
    rules = {name: sorted(result[name]) for name in LIST_ORDER}
    return rules, status, failures


def build_rules(meta_ai, meta_claude, kelee, meta_cursor,
                meta_youtube, meta_twitch, meta_tiktok, meta_github, meta_google, warnings=None):
    """Strict build from complete sources: any list failure raises (used by tests and audits)."""
    sources = dict(meta_ai=meta_ai, meta_claude=meta_claude, kelee=kelee, meta_cursor=meta_cursor,
                   meta_youtube=meta_youtube, meta_twitch=meta_twitch, meta_tiktok=meta_tiktok,
                   meta_github=meta_github, meta_google=meta_google)
    rules, _, failures = build_lists(sources, warnings=warnings)
    if failures:
        name = next(iter(failures))
        raise RuleError(failures[name].rsplit(" (", 1)[0])
    return rules


def fetch_text(url):
    # Only public upstream URLs are supplied here. No app settings or credentials.
    user_agent = (
        LOON_USER_AGENT
        if url == KELEE_URL else "loon-ai-rules/1"
    )
    result = subprocess.run(
        ["curl", "--fail-with-body", "--silent", "--show-error", "--location",
         "--connect-timeout", "15", "--max-time", "60", "--max-filesize", "2000000",
         "--user-agent", user_agent, url],
        capture_output=True, timeout=70,
    )
    if result.returncode:
        source = "Kelee" if url == KELEE_URL else "MetaCubeX"
        details = [f"curl {result.returncode}"]
        status = re.search(rb"error:\s*(\d{3})\b", result.stderr)
        if status:
            details.append("HTTP " + status.group(1).decode("ascii"))
        if b"/cdn-cgi/challenge-platform" in result.stdout or b"cf-chl-" in result.stdout:
            details.append("browser challenge")
        raise RuleError(f"{source}: public upstream download failed ({', '.join(details)})")
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuleError("public upstream is not UTF-8") from error


def fetch_kelee_with_browser_tls():
    """Use Safari's TLS profile with the Loon UA for the public Loon endpoint."""
    try:
        from curl_cffi import get
    except ImportError as error:
        raise RuleError("browser TLS support requires the pinned curl_cffi dependency") from error
    content = bytearray()
    oversized = False

    def receive(chunk):
        nonlocal oversized
        if len(content) + len(chunk) > 2_000_000:
            oversized = True
            return 0
        content.extend(chunk)
        return len(chunk)

    try:
        response = get(
            KELEE_URL, impersonate="safari_ios", default_headers=False,
            headers={"User-Agent": LOON_USER_AGENT, "Accept": "*/*"},
            timeout=60, max_redirects=3, content_callback=receive,
        )
    except Exception as error:
        if oversized:
            raise RuleError("Kelee: source is too large") from None
        raise RuleError(f"Kelee: browser TLS transport failed ({type(error).__name__})") from None
    if oversized:
        raise RuleError("Kelee: source is too large")
    challenge = ", browser challenge" if b"/cdn-cgi/challenge-platform" in content or b"cf-chl-" in content else ""
    if response.status_code != 200 or challenge:
        raise RuleError(f"Kelee: public upstream download failed (HTTP {response.status_code}{challenge})")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuleError("Kelee: public upstream is not UTF-8") from error


def fetch_with_browser_tls(url):
    return fetch_kelee_with_browser_tls() if url == KELEE_URL else fetch_text(url)


def fetch_sources(fetch=fetch_text, errors=None):
    """Download every source. With an errors dict, a failed download is recorded and
    its source set to None so only the lists that need it fall back; without one it raises."""
    def attempt(key, url):
        try:
            return fetch(url)
        except (RuleError, OSError, subprocess.TimeoutExpired) as error:
            if errors is None:
                raise
            errors[key] = printable(str(error) or type(error).__name__)
            return None

    keys = ("meta_ai", "meta_claude", "meta_cursor", "meta_youtube", "meta_twitch", "meta_tiktok",
            "meta_github", "meta_google")
    upstreams = ("category-ai-!cn", "anthropic", "cursor", "youtube", "twitch", "tiktok", "github", "google")
    commit = None
    try:
        head = fetch(META_HEAD)
        try:
            commit = json.loads(head)["sha"]
        except (ValueError, KeyError, TypeError) as error:
            raise RuleError("invalid Meta revision response") from error
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise RuleError("invalid Meta revision")
    except (RuleError, OSError, subprocess.TimeoutExpired) as error:
        if errors is None:
            raise
        errors["meta_head"] = printable(str(error) or type(error).__name__)
        commit = None
    sources = {}
    if commit:
        base = f"{META_RAW}/{commit}/geo/geosite/classical"
        for key, upstream in zip(keys, upstreams):
            sources[key] = attempt(key, f"{base}/{upstream}.list")
    else:
        sources.update(dict.fromkeys(keys))
    sources["kelee"] = attempt("kelee", KELEE_URL)
    return sources, commit


def render_artifacts(rules, commit):
    result = {}
    for name in OUTPUT_NAMES:
        lines = rules[name]
        body = "\n".join(lines) + "\n"
        headers = ["# Public routing rules for Loon and mihomo. Generated; do not edit."]
        meta_attribution = [
            "# Attribution: MetaCubeX/meta-rules-dat; underlying domain data: v2fly/domain-list-community.",
            "# Licenses: https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE",
            "# https://github.com/v2fly/domain-list-community/blob/master/LICENSE",
        ]
        if name == "HighTraffic.list":
            headers += [f"# Source: {META_RAW}/{commit}/geo/geosite/classical/{upstream}.list"
                        for upstream in HIGH_TRAFFIC_UPSTREAMS + ("github",)]
            headers += meta_attribution
            headers += ["# Change: github.list contributes only its exact S3 / Actions artifact storage hosts.",
                        "# Additions: Google Drive / Photos file content hosts and GitHub download hosts.",
                        "# https://github.com/lich13/loon-ai-rules#high-traffic",
                        "# Change: entries already in AI-Meta / AI-Kelee are left there."]
        elif name == "GitHub.list":
            headers += [f"# Source: {META_RAW}/{commit}/geo/geosite/classical/github.list"]
            headers += meta_attribution
            headers += ["# Change: remove download hosts (HighTraffic.list) and Copilot (AI-Meta.list)."]
        elif name == "Google.list":
            headers += [f"# Source: {META_RAW}/{commit}/geo/geosite/classical/google.list"]
            headers += meta_attribution
            headers += ["# Change: remove YouTube and Drive/Photos content (HighTraffic.list) and AI hosts (AI-Meta / AI-Kelee).",
                        "# Change: drop two Google Play download regexes covered by published suffix rules."]
        elif name == "AI-Kelee.list":
            headers += [f"# Source: {KELEE_URL}",
                        "# Attribution: iKeLee / luestr/ProxyResource; CC BY-NC-SA 4.0.",
                        "# License: https://github.com/luestr/ProxyResource/blob/main/LICENSE",
                        "# Change: normalize grammar; remove Meta-covered entries (Claude and Cursor merged into AI-Meta)."]
        else:
            upstreams = ("category-ai-!cn", "anthropic", "cursor")
            headers += [f"# Source: {META_RAW}/{commit}/geo/geosite/classical/{upstream}.list"
                        for upstream in upstreams]
            headers += ["# Attribution: MetaCubeX/meta-rules-dat; underlying domain data: v2fly/domain-list-community.",
                        "# Licenses: https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE",
                        "# https://github.com/v2fly/domain-list-community/blob/master/LICENSE"]
            headers += ["# Additions: merge Anthropic/Claude (desktop network, official IP ranges, compatibility).",
                        "# https://code.claude.com/docs/en/desktop#network-access-requirements",
                        "# https://platform.claude.com/docs/en/api/ip-addresses",
                        "# Compatibility: three exact Anthropic hosts; Sentry and Statsig domain suffixes.",
                        "# https://github.com/lich13/loon-ai-rules#claude-compatibility",
                        "# Additions: merge Cursor (hosted computers and exact download host).",
                        "# https://prod.cursor.com/help/troubleshooting/sign-in-domains",
                        "# https://prod.cursor.com/docs/enterprise/network-configuration",
                        "# Change: use the audited Azure keyword + suffix compatibility rule."]
        headers += [f"# Rules: {len(lines)}", f"# Content SHA-256: {hashlib.sha256(body.encode()).hexdigest()}"]
        result[name] = "\n".join(headers) + "\n\n" + body
    return result


def semantic_body(text):
    return "\n".join(line for line in text.splitlines() if line.strip() and not line.startswith("#"))


def read_previous(output_dir):
    """Rules of the currently published files, used when a list cannot be rebuilt."""
    previous = {}
    for name in OUTPUT_NAMES:
        path = Path(output_dir) / name
        if not path.is_file():
            continue
        try:
            rules = parse_rules(path.read_text(encoding="utf-8"), f"published {name}", [])
        except (RuleError, OSError, UnicodeDecodeError):
            continue
        previous[name] = rules
    return previous


KEPT_NOTE = "# Note: previous version kept because this run could not rebuild it; cross-list duplicates removed."


def render_kept(old_text, lines):
    """Re-render a kept list after cross-list deduplication, keeping its original source headers."""
    body = "\n".join(lines) + "\n"
    headers = [line for line in old_text.splitlines() if line.startswith("#")
               and not line.startswith(("# Rules:", "# Content SHA-256:")) and line != KEPT_NOTE]
    headers += [KEPT_NOTE, f"# Rules: {len(lines)}",
                f"# Content SHA-256: {hashlib.sha256(body.encode()).hexdigest()}"]
    return "\n".join(headers) + "\n\n" + body


class UpdateReport:
    def __init__(self, rules, changed, status, failures, warnings, download_errors):
        self.rules, self.changed, self.status = rules, changed, status
        self.failures, self.warnings, self.download_errors = failures, warnings, download_errors

    @property
    def ok(self):
        return not self.failures

    def __iter__(self):  # backwards-compatible "rules, changed = update(...)"
        return iter((self.rules, self.changed))


def update(output_dir, fetch=fetch_text):
    output_dir = Path(output_dir)
    warnings, download_errors = [], {}
    sources, commit = fetch_sources(fetch, download_errors)
    previous = read_previous(output_dir)
    rules, status, failures = build_lists(sources, previous, warnings)
    warnings = list(dict.fromkeys(warnings))
    fresh = render_artifacts(rules, commit or "unknown")
    artifacts = {}
    for name in OUTPUT_NAMES:
        path = output_dir / name
        if status[name] == "built":
            artifacts[name] = fresh[name]
        elif status[name] == "kept" and set(rules[name]) != previous[name]:
            artifacts[name] = render_kept(path.read_text(encoding="utf-8"), rules[name])
    changed_names = [
        name for name, text in artifacts.items()
        if not (output_dir / name).is_file() or semantic_body((output_dir / name).read_text()) != semantic_body(text)
    ]
    obsolete = [output_dir / name for name in ("Claude.list", "Cursor.list") if (output_dir / name).is_file()]
    report = UpdateReport(rules, bool(changed_names or obsolete), status, failures, warnings, download_errors)
    if not report.changed:
        return report
    # Every artifact is rendered and validated before the first destination replacement.
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ai-rules-", dir=output_dir.parent) as scratch:
        for name in changed_names:
            path = Path(scratch) / name
            with path.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(artifacts[name])
                stream.flush()
                os.fsync(stream.fileno())
        for name in changed_names:
            os.replace(Path(scratch) / name, output_dir / name)
    for stale in obsolete:
        stale.unlink()
    # The workflow publishes the written files in one Git commit.
    return report


def annotation(level, message):
    escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return f"::{level}::{escaped}"


def write_summary(report, path):
    lines = ["## 规则更新结果", "", "| 列表 | 状态 | 规则数 |", "| --- | --- | --- |"]
    labels = {"built": "已更新/已校验", "kept": "沿用上次发布版本", "missing": "无可用版本，未发布"}
    for name in OUTPUT_NAMES:
        lines.append(f"| `{name}` | {labels[report.status[name]]} | {len(report.rules[name])} |")
    if report.failures:
        lines += ["", "### 未能重建的列表", ""]
        lines += [f"- `{name}`: {printable(message, 300)}" for name, message in report.failures.items()]
    if report.download_errors:
        lines += ["", "### 下载失败", ""]
        lines += [f"- {key}: {message}" for key, message in report.download_errors.items()]
    if report.warnings:
        lines += ["", f"### 警告（{len(report.warnings)}）", ""]
        lines += [f"- {printable(message, 300)}" for message in report.warnings[:200]]
        if len(report.warnings) > 200:
            lines.append(f"- 另有 {len(report.warnings) - 200} 条省略")
    with open(path, "a", encoding="utf-8") as stream:
        stream.write("\n".join(lines).replace("`", "'").replace("'HighTraffic", "`HighTraffic") + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "rules")
    parser.add_argument("--browser-tls", action="store_true", help="use Safari-compatible TLS for the Loon source")
    args = parser.parse_args()
    try:
        report = update(args.output, fetch_with_browser_tls if args.browser_tls else fetch_text)
    except (RuleError, OSError, subprocess.TimeoutExpired, RuntimeError) as error:
        parser.exit(1, f"Rule update stopped: {printable(str(error), 300)}\n")
    for message in report.warnings:
        print(annotation("warning", printable(message, 300)))
    for name, message in report.failures.items():
        print(annotation("error", printable(f"{name}: {message}", 300)))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        write_summary(report, os.environ["GITHUB_STEP_SUMMARY"])
    print(json.dumps({"changed": report.changed, "status": report.status,
                      "counts": {name: len(lines) for name, lines in report.rules.items()},
                      "warnings": len(report.warnings), "failures": report.failures}, ensure_ascii=False))
    # 2 = some lists fell back to their previous version; the others were still written.
    if report.failures:
        sys.exit(2)


if __name__ == "__main__":
    main()
