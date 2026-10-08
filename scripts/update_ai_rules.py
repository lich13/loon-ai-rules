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
CLAUDE_SUFFIXES = frozenset((
    "anthropic.com", "clau.de", "claude.ai", "claude.com", "claude.dev",
    "claudemcpclient.com", "claudemcpcontent.com", "claudeusercontent.com",
))
CLAUDE_EXTRA = (
    "DOMAIN-SUFFIX,claude.app",
    "IP-CIDR,160.79.104.0/23,no-resolve",
    "IP-CIDR6,2607:6bc0::/48,no-resolve",
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
))
OUTPUT_NAMES = ("Claude.list", "AI-Meta.list", "AI-Kelee.list")
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


def build_rules(meta_ai, meta_claude, kelee):
    ai = parse_rules(meta_ai, "Meta AI")
    claude = parse_rules(meta_claude, "Meta Anthropic")
    extra = parse_rules(kelee, "Kelee AI")
    if any(not rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")) for rule in claude):
        raise RuleError("Anthropic upstream must contain domain rules only")
    if not all(domain_matches(claude, domain) for domain in CLAUDE_SUFFIXES):
        raise RuleError("Anthropic source lost required domains")
    if not domain_matches(claude, "servd-anthropic-website.b-cdn.net"):
        raise RuleError("Anthropic source lost the website CDN")
    claude.update(CLAUDE_EXTRA)
    for domain in SHARED_INFRASTRUCTURE:
        if domain_matches(claude, domain) or domain_matches(claude, "unrelated." + domain):
            raise RuleError("Anthropic source includes shared infrastructure")
    # A named telemetry endpoint is also shared across tenants, not Claude-specific.
    if domain_matches(claude, "browser-intake-us5-datadoghq.com"):
        raise RuleError("Anthropic source includes shared telemetry")
    ai = set(compact_rules(rule for rule in ai if not covered_by(rule, claude)))
    extra = set(compact_rules(rule for rule in extra if not covered_by(rule, claude | ai)))
    if not all(domain_matches(ai, domain) for domain in (
        "chatgpt.com", "api.openai.com", "gemini.google.com", "openrouter.ai",
        "copilot-proxy.githubusercontent.com",
    )):
        raise RuleError("Meta AI source lost required services")
    if len(ai) < 10 or not extra:
        raise RuleError("incomplete AI sources")
    if domain_matches(ai | extra, "github.com"):
        raise RuleError("AI rules include the entire GitHub site")
    return {
        "Claude.list": compact_rules(claude),
        "AI-Meta.list": sorted(ai),
        "AI-Kelee.list": sorted(extra),
    }


def fetch_text(url):
    # Only public upstream URLs are supplied here. No app settings or credentials.
    user_agent = (
        "Loon/1005 CFNetwork/3860.600.31 Darwin/25.0.0"
        if url == KELEE_URL else "loon-ai-rules/1"
    )
    result = subprocess.run(
        ["curl", "--fail", "--silent", "--show-error", "--location",
         "--connect-timeout", "15", "--max-time", "60", "--max-filesize", "2000000",
         "--user-agent", user_agent, url],
        capture_output=True, timeout=70,
    )
    if result.returncode:
        source = "Kelee" if url == KELEE_URL else "MetaCubeX"
        raise RuleError(f"{source}: public upstream download failed (curl {result.returncode})")
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuleError("public upstream is not UTF-8") from error


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
        "kelee": fetch(KELEE_URL),
    }
    return sources, commit


def render_artifacts(rules, commit):
    result = {}
    for name in OUTPUT_NAMES:
        lines = rules[name]
        body = "\n".join(lines) + "\n"
        headers = ["# Public routing rules for Loon and mihomo. Generated; do not edit."]
        if name == "AI-Kelee.list":
            headers += [f"# Source: {KELEE_URL}",
                        "# Attribution: iKeLee / luestr/ProxyResource; CC BY-NC-SA 4.0.",
                        "# License: https://github.com/luestr/ProxyResource/blob/main/LICENSE",
                        "# Change: normalize grammar; remove Claude and Meta-covered entries."]
        else:
            upstream = "anthropic" if name == "Claude.list" else "category-ai-!cn"
            headers += [f"# Source: {META_RAW}/{commit}/geo/geosite/classical/{upstream}.list",
                        "# Attribution: MetaCubeX/meta-rules-dat; underlying domain data: v2fly/domain-list-community.",
                        "# Licenses: https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE",
                        "# https://github.com/v2fly/domain-list-community/blob/master/LICENSE"]
            if name == "Claude.list":
                headers += ["# Additions: Claude Desktop network requirements and official inbound IP ranges.",
                            "# https://code.claude.com/docs/en/desktop#network-access-requirements",
                            "# https://platform.claude.com/docs/en/api/ip-addresses"]
            else:
                headers += ["# Change: remove Claude; use the audited Azure keyword + suffix compatibility rule."]
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
    if all((output_dir / name).is_file() and semantic_body((output_dir / name).read_text()) == semantic_body(text)
           for name, text in artifacts.items()):
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
    # The workflow publishes all three validated files in one Git commit.
    return rules, True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "rules")
    args = parser.parse_args()
    try:
        rules, changed = update(args.output)
    except (RuleError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Rule update stopped: {error}\n")
    print(json.dumps({"changed": changed, "counts": {name: len(lines) for name, lines in rules.items()}}))


if __name__ == "__main__":
    main()
