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


def parse_rules(text, source):
    if len(text.encode("utf-8")) > 2_000_000:
        raise RuleError(f"{source}: source is too large")
    rules = set()
    for number, line in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rules.add(parse_rule(line))
        except RuleError as error:
            raise RuleError(f"{source}:{number}: {error}") from error
    if not rules:
        raise RuleError(f"{source}: empty rules")
    return rules


def strip_covered_regexes(text, source):
    """Remove only reviewed regexes that a published suffix rule fully covers."""
    kept, required = [], set()
    for line in text.lstrip("\ufeff").splitlines():
        stripped = line.strip()
        if stripped.startswith("DOMAIN-REGEX,"):
            pattern = stripped.split(",", 1)[1].strip()
            if pattern not in COVERED_REGEXES:
                raise RuleError(f"{source}: unreviewed regex rule")
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


def build_rules(meta_ai, meta_claude, kelee, meta_cursor,
                meta_youtube, meta_twitch, meta_tiktok, meta_github, meta_google):
    ai = parse_rules(meta_ai, "Meta AI")
    claude = parse_rules(meta_claude, "Meta Anthropic")
    extra = parse_rules(kelee, "Kelee AI")
    cursor = parse_rules(meta_cursor, "Meta Cursor")
    if any(not rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")) for rule in cursor):
        raise RuleError("Meta Cursor: upstream must contain domain rules only")
    if not all(f"DOMAIN-SUFFIX,{domain}" in cursor for domain in CURSOR_SUFFIXES):
        raise RuleError("Meta Cursor: source lost required domains")
    cursor.update(CURSOR_EXTRA)
    for domain in SHARED_INFRASTRUCTURE | CLAUDE_SUFFIXES | {
        "claude.app", "x.com", "twitter.com", "spacex.ai", "amazonaws.com",
        "s3.us-east-1.amazonaws.com", "chatgpt.com", "openai.com", "google.com",
        "grok.com", "x.ai", "grokipedia.com", "grokusercontent.com",
    }:
        if domain_matches(cursor, domain) or domain_matches(cursor, "unrelated." + domain):
            raise RuleError("Cursor source includes unrelated services or shared infrastructure")
    if any(not rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")) for rule in claude):
        raise RuleError("Anthropic upstream must contain domain rules only")
    if not all(domain_matches(claude, domain) for domain in CLAUDE_SUFFIXES):
        raise RuleError("Anthropic source lost required domains")
    if not domain_matches(claude, "servd-anthropic-website.b-cdn.net"):
        raise RuleError("Anthropic source lost the website CDN")
    claude.update(CLAUDE_EXTRA)
    claude.update(CLAUDE_COMPATIBILITY)
    for domain in SHARED_INFRASTRUCTURE:
        if domain_matches(CLAUDE_COMPATIBILITY, domain):
            continue
        if domain_matches(claude, domain) or domain_matches(claude, "unrelated." + domain):
            raise RuleError("Anthropic source includes shared infrastructure")
    # A named telemetry endpoint is also shared across tenants, not Claude-specific.
    if domain_matches(claude, "browser-intake-us5-datadoghq.com"):
        raise RuleError("Anthropic source includes shared telemetry")
    # Guard Meta AI body size before merge so Claude alone cannot mask an empty AI source.
    ai_base = set(compact_rules(rule for rule in ai if not covered_by(rule, claude)))
    if len(ai_base) < 10:
        raise RuleError("incomplete AI sources")
    # Merge Anthropic/Claude (core + extras + compatibility) and Cursor (core + extras)
    # into the AI服务-bound AI-Meta output.
    ai = set(compact_rules(ai | claude | cursor))
    extra = set(compact_rules(rule for rule in extra if not covered_by(rule, ai)))
    if not all(domain_matches(ai, domain) for domain in (
        "chatgpt.com", "api.openai.com", "gemini.google.com", "openrouter.ai",
        "copilot-proxy.githubusercontent.com",
    )):
        raise RuleError("Meta AI source lost required services")
    if not all(domain_matches(ai, domain) for domain in CLAUDE_SUFFIXES):
        raise RuleError("AI-Meta lost required Claude domains after merge")
    if not all(covered_by(rule, ai) for rule in cursor):
        raise RuleError("AI-Meta lost required Cursor domains after merge")
    if not extra:
        raise RuleError("incomplete AI sources")
    if domain_matches(ai | extra, "github.com"):
        raise RuleError("AI rules include the entire GitHub site")
    high, github, google, overlaps = build_traffic_rules(
        ai, extra, meta_youtube, meta_twitch, meta_tiktok, meta_github, meta_google,
    )
    result = {
        "HighTraffic.list": sorted(high),
        "AI-Meta.list": sorted(ai),
        "AI-Kelee.list": sorted(extra),
        "GitHub.list": sorted(github),
        "Google.list": sorted(google),
    }
    names = list(result)
    for index, first in enumerate(names):
        for second in names[index + 1:]:
            if set(result[first]) & set(result[second]):
                raise RuleError(f"{first} and {second} share rules")
    LAST_OVERLAPS[:] = overlaps
    return result


# High-traffic candidates left in the AI lists by the last build, for the run summary.
LAST_OVERLAPS = []


def build_traffic_rules(ai, extra, meta_youtube, meta_twitch, meta_tiktok, meta_github, meta_google):
    """HighTraffic first, then GitHub and Google minus everything published earlier."""
    youtube = parse_rules(meta_youtube, "Meta YouTube")
    twitch = parse_rules(meta_twitch, "Meta Twitch")
    tiktok = parse_rules(meta_tiktok, "Meta TikTok")
    github_source = parse_rules(meta_github, "Meta GitHub")
    google_text, required_suffixes = strip_covered_regexes(meta_google, "Meta Google")
    google_source = parse_rules(google_text, "Meta Google")
    for source, rules in (("Meta YouTube", youtube), ("Meta Twitch", twitch), ("Meta TikTok", tiktok),
                          ("Meta GitHub", github_source), ("Meta Google", google_source)):
        if any(not rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")) for rule in rules):
            raise RuleError(f"{source}: upstream must contain domain rules only")
    for source, rules, domains in (
        ("Meta YouTube", youtube, ("youtube.com", "googlevideo.com", "ytimg.com",
                                   "youtubei.googleapis.com", "youtube-nocookie.com")),
        ("Meta Twitch", twitch, ("twitch.tv",)),
        ("Meta TikTok", tiktok, ("tiktok.com",)),
        ("Meta GitHub", github_source, ("github.com", "githubusercontent.com")),
        ("Meta Google", google_source, ("google.com", "googleapis.com", "play.google.com",
                                        "googleplay.com", "accounts.google.com")),
    ):
        if not all(domain_matches(rules, domain) for domain in domains):
            raise RuleError(f"{source}: source lost required domains")
    moved = {rule for rule in github_source if GITHUB_MOVED_RE.fullmatch(rule)}
    if not any("productionresultssa" in rule for rule in moved) or not any(".s3." in rule for rule in moved):
        raise RuleError("Meta GitHub: source lost download storage hosts")
    high = youtube | twitch | tiktok | moved | set(GOOGLE_CONTENT_HOSTS) | set(GITHUB_DOWNLOAD_HOSTS)
    for domain in HIGH_TRAFFIC_FORBIDDEN:
        if domain_matches(high, domain) or domain_matches(high, "unrelated." + domain):
            raise RuleError("HighTraffic includes an entire shared domain")
    # AI entries win: drop high-traffic rules already published by the AI lists.
    ai_all = ai | extra
    overlaps = sorted(rule for rule in high if covered_by(rule, ai_all))
    high = set(compact_rules(rule for rule in high if not covered_by(rule, ai_all)))
    # HighTraffic is matched before the AI lists, so it must not capture any AI host.
    for rule in ai_all:
        kind, value, *_ = rule.split(",")
        if kind in ("DOMAIN", "DOMAIN-SUFFIX") and domain_matches(high, value):
            raise RuleError("HighTraffic would capture an AI rule")
    earlier = ai_all | high
    github = set(compact_rules(
        rule for rule in github_source - moved if not covered_by(rule, earlier)
    ))
    if not domain_matches(github, "github.com"):
        raise RuleError("GitHub list lost the main site")
    earlier |= github
    google = set(compact_rules(rule for rule in google_source if not covered_by(rule, earlier)))
    for suffix in required_suffixes:
        if suffix not in high | google:
            raise RuleError("Meta Google: regex is not covered by a published suffix")
    if domain_matches(google, "youtube.com") or domain_matches(google, "www.youtube.com"):
        raise RuleError("Google list still includes YouTube")
    if not all(domain_matches(google, domain) for domain in ("google.com", "googleapis.com", "play.google.com")):
        raise RuleError("Google list lost required domains")
    if len(high) < 50 or len(github) < 10 or len(google) < 100:
        raise RuleError("incomplete traffic sources")
    return high, github, google, overlaps


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


def fetch_sources(fetch=fetch_text):
    head = fetch(META_HEAD)
    try:
        commit = json.loads(head)["sha"]
    except (ValueError, KeyError, TypeError) as error:
        raise RuleError("invalid Meta revision response") from error
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuleError("invalid Meta revision")
    base = f"{META_RAW}/{commit}/geo/geosite/classical"
    sources = {
        "meta_ai": fetch(f"{base}/category-ai-!cn.list"),
        "meta_claude": fetch(f"{base}/anthropic.list"),
        "meta_cursor": fetch(f"{base}/cursor.list"),
        "meta_youtube": fetch(f"{base}/youtube.list"),
        "meta_twitch": fetch(f"{base}/twitch.list"),
        "meta_tiktok": fetch(f"{base}/tiktok.list"),
        "meta_github": fetch(f"{base}/github.list"),
        "meta_google": fetch(f"{base}/google.list"),
        "kelee": fetch(KELEE_URL),
    }
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


def update(output_dir, fetch=fetch_text):
    sources, commit = fetch_sources(fetch)
    rules = build_rules(**sources)
    artifacts = render_artifacts(rules, commit)
    output_dir = Path(output_dir)
    obsolete = ("Claude.list", "Cursor.list")
    up_to_date = all(
        (output_dir / name).is_file() and semantic_body((output_dir / name).read_text()) == semantic_body(text)
        for name, text in artifacts.items()
    )
    obsolete_present = any((output_dir / name).is_file() for name in obsolete)
    if up_to_date and not obsolete_present:
        return rules, False
    # No destination writes occur until every download, conversion and guard succeeds.
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ai-rules-", dir=output_dir.parent) as scratch:
        for name, text in artifacts.items():
            path = Path(scratch) / name
            with path.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
        for name in OUTPUT_NAMES:
            os.replace(Path(scratch) / name, output_dir / name)
    for name in obsolete:
        stale = output_dir / name
        if stale.is_file():
            stale.unlink()
    # The workflow publishes all validated files in one Git commit.
    return rules, True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "rules")
    parser.add_argument("--browser-tls", action="store_true", help="use Safari-compatible TLS for the Loon source")
    args = parser.parse_args()
    try:
        rules, changed = update(args.output, fetch_with_browser_tls if args.browser_tls else fetch_text)
    except (RuleError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Rule update stopped: {error}\n")
    print(json.dumps({"changed": changed, "counts": {name: len(lines) for name, lines in rules.items()},
                      "high_traffic_kept_in_ai": LAST_OVERLAPS}, ensure_ascii=False))


if __name__ == "__main__":
    main()
