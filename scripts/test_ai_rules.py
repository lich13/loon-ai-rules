#!/usr/bin/env python3
"""Offline behavior checks for the public AI routing rule generator."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import update_ai_rules as generator


REVISION = "a" * 40
NEXT_REVISION = "b" * 40
CLAUDE_CORE = (
    "DOMAIN-SUFFIX,anthropic.com",
    "DOMAIN-SUFFIX,clau.de",
    "DOMAIN-SUFFIX,claude.ai",
    "DOMAIN-SUFFIX,claude.com",
    "DOMAIN-SUFFIX,claude.dev",
    "DOMAIN-SUFFIX,claudemcpclient.com",
    "DOMAIN-SUFFIX,claudemcpcontent.com",
    "DOMAIN-SUFFIX,claudeusercontent.com",
    "DOMAIN,servd-anthropic-website.b-cdn.net",
    "DOMAIN,upstream-core.example.invalid",
)
CLAUDE_COMPATIBILITY_RULES = (
    "DOMAIN,anthropic.auth0.com",
    "DOMAIN,anthropic-com.ghost.io",
    "DOMAIN,anthropic.com.cdn.cloudflare.net",
    "DOMAIN-SUFFIX,sentry.io",
    "DOMAIN-SUFFIX,statsigapi.net",
)
AI_CORE = (
    "DOMAIN-SUFFIX,chatgpt.com",
    "DOMAIN-SUFFIX,openai.com",
    "DOMAIN,gemini.google.com",
    "DOMAIN-SUFFIX,openrouter.ai",
    "DOMAIN,copilot-proxy.githubusercontent.com",
)
AI_SYNTHETIC = tuple(
    f"DOMAIN-SUFFIX,provider-{number}.example.invalid" for number in range(7)
)
XAI_CORE = (
    "DOMAIN-SUFFIX,grok.com",
    "DOMAIN-SUFFIX,grokipedia.com",
    "DOMAIN-SUFFIX,x.ai",
    "DOMAIN-SUFFIX,grok.x.com",
)
CURSOR_CORE = (
    "DOMAIN-SUFFIX,cursor-cdn.com",
    "DOMAIN-SUFFIX,cursor.com",
    "DOMAIN-SUFFIX,cursor.sh",
    "DOMAIN-SUFFIX,cursorapi.com",
)
XAI_EXTRA = (
    "DOMAIN-SUFFIX,cursorvm.com",
    "DOMAIN-SUFFIX,grokusercontent.com",
    "DOMAIN,accounts.spacex.ai",
    "DOMAIN,anysphere-binaries.s3.us-east-1.amazonaws.com",
)
KELEE_XAI_FALLBACKS = (
    "DOMAIN,api.grokusercontent.com",
    "DOMAIN,api.cursorvm.com",
)
REVIEWED_NETWORKS = tuple(
    rule for rule in generator.CLAUDE_EXTRA if rule.startswith(("IP-CIDR,", "IP-CIDR6,"))
)
KELEE_ADDITIONS = (
    "DOMAIN-SUFFIX,supplement.example.invalid",
    "DOMAIN,standalone.example.invalid",
)


def source_text(lines):
    return "\n".join(lines) + "\n"


def valid_sources():
    """Independent public service expectations plus synthetic deduplication cases."""
    claude = source_text(CLAUDE_CORE)
    ai = source_text(AI_CORE + AI_SYNTHETIC + XAI_CORE + CURSOR_CORE + CLAUDE_CORE + (
        "DOMAIN,api.anthropic.com",
        "DOMAIN,download.claude.app",
        "DOMAIN,api.provider-0.example.invalid",
        "DOMAIN-SUFFIX,child.provider-0.example.invalid",
    ) + REVIEWED_NETWORKS)
    kelee = ai + source_text(KELEE_ADDITIONS + KELEE_XAI_FALLBACKS + (
        "DOMAIN,api.supplement.example.invalid",
        "DOMAIN-SUFFIX,child.supplement.example.invalid",
        "DOMAIN,standalone.example.invalid",
        "DOMAIN,api.github.com",
    ))
    return {
        "meta_ai": ai,
        "meta_claude": claude,
        "meta_xai": source_text(XAI_CORE),
        "meta_cursor": source_text(CURSOR_CORE),
        "kelee": kelee,
    }


class FixtureFetch:
    def __init__(self, sources=None, revision=REVISION):
        self.sources = valid_sources() if sources is None else sources
        base = f"{generator.META_RAW}/{revision}/geo/geosite/classical"
        self.responses = {
            generator.META_HEAD: json.dumps({"sha": revision}),
            f"{base}/category-ai-!cn.list": self.sources["meta_ai"],
            f"{base}/anthropic.list": self.sources["meta_claude"],
            f"{base}/xai.list": self.sources["meta_xai"],
            f"{base}/cursor.list": self.sources["meta_cursor"],
            generator.KELEE_URL: self.sources["kelee"],
        }
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        if url not in self.responses:
            raise AssertionError("request is outside the fixed source fixture")
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response


def snapshot(directory):
    result = {}
    for name in generator.OUTPUT_NAMES:
        path = directory / name
        stat = path.stat()
        result[name] = (path.read_bytes(), stat.st_mtime_ns, stat.st_ino)
    return result


class OfflineTestCase(unittest.TestCase):
    def setUp(self):
        network = patch.object(
            generator.subprocess, "run",
            side_effect=AssertionError("network requests are forbidden in these tests"),
        )
        network.start()
        self.addCleanup(network.stop)


class ParseRuleTests(OfflineTestCase):
    def test_domain_rules_normalize_case_and_whitespace(self):
        for kind in ("DOMAIN", "DOMAIN-SUFFIX"):
            with self.subTest(kind=kind):
                self.assertEqual(
                    generator.parse_rule(f"  {kind} , API.Example.Invalid  "),
                    f"{kind},api.example.invalid",
                )

    def test_audited_conjunctions_accept_both_operand_orders(self):
        self.assertEqual(len(generator.ALLOWED_CONJUNCTIONS), 3)
        for keyword, suffix in generator.ALLOWED_CONJUNCTIONS:
            expected = f"AND,((DOMAIN-KEYWORD,{keyword}),(DOMAIN-SUFFIX,{suffix}))"
            reverse = f" AND, ((DOMAIN-SUFFIX, {suffix}), (DOMAIN-KEYWORD, {keyword})) "
            with self.subTest(keyword=keyword):
                self.assertEqual(generator.parse_rule(expected), expected)
                self.assertEqual(generator.parse_rule(reverse), expected)

    def test_azure_regex_converts_to_the_audited_conjunction(self):
        self.assertEqual(
            generator.parse_rule(f"DOMAIN-REGEX,{generator.AZURE_REGEX}"),
            "AND,((DOMAIN-KEYWORD,chatgpt-async-webps-prod-),(DOMAIN-SUFFIX,webpubsub.azure.com))",
        )

    def test_only_both_reviewed_ip_networks_are_accepted(self):
        self.assertEqual(len(REVIEWED_NETWORKS), 2)
        self.assertEqual({line.split(",")[0] for line in REVIEWED_NETWORKS}, {"IP-CIDR", "IP-CIDR6"})
        for line in REVIEWED_NETWORKS:
            with self.subTest(family=line.split(",")[0]):
                self.assertEqual(generator.parse_rule(line), line)

    def test_unknown_syntax_regex_and_ip_rules_are_rejected(self):
        invalid = (
            "DOMAIN,example.invalid,DIRECT",
            "DOMAIN-KEYWORD,example",
            r"DOMAIN-REGEX,^.*\.example\.invalid$",
            "DOMAIN-REGEX," + generator.AZURE_REGEX.replace(r"\S+", ".*"),
            "AND,((DOMAIN-KEYWORD,example),(DOMAIN-SUFFIX,example.invalid))",
            "OR,((DOMAIN,one.example.invalid),(DOMAIN,two.example.invalid))",
            "IP-CIDR,127.0.0.1/32,no-resolve",
            "IP-CIDR6,::1/128,no-resolve",
            "IP-CIDR,127.0.0.1/8,no-resolve",
            "IP-CIDR,127.0.0.256/32,no-resolve",
            "IP-ASN,64512,no-resolve",
            "PROCESS-NAME,fixture-process",
            "MATCH,DIRECT",
        )
        for line in invalid:
            with self.subTest(rule=line.split(",")[0]):
                with self.assertRaises(generator.RuleError):
                    generator.parse_rule(line)

    def test_reviewed_ips_still_require_the_correct_family_and_no_resolve(self):
        for line in REVIEWED_NETWORKS:
            kind, network, _ = line.split(",")
            other_family = "IP-CIDR6" if kind == "IP-CIDR" else "IP-CIDR"
            for invalid in (f"{kind},{network}", f"{other_family},{network},no-resolve", line + ",DIRECT"):
                with self.subTest(family=kind):
                    with self.assertRaises(generator.RuleError):
                        generator.parse_rule(invalid)

    def test_malformed_domains_are_rejected(self):
        for domain in ("", "example", "*.example.invalid", "-bad.example.invalid", "bad-.example.invalid", "example.invalid."):
            with self.subTest(domain=domain):
                with self.assertRaises(generator.RuleError):
                    generator.parse_rule(f"DOMAIN,{domain}")

    def test_bom_comments_blank_lines_and_duplicates_are_handled(self):
        self.assertEqual(
            generator.parse_rules("\ufeff# fixture\r\n\r\nDOMAIN,API.Example.Invalid\r\n  # comment\r\nDOMAIN,api.example.invalid\n", "fixture"),
            {"DOMAIN,api.example.invalid"},
        )

    def test_unknown_rule_reports_the_source_and_line_number(self):
        with self.assertRaisesRegex(generator.RuleError, r"fixture:3: unsupported rule type"):
            generator.parse_rules("# fixture\nDOMAIN,example.invalid\nIP-ASN,64512\n", "fixture")

    def test_empty_and_oversized_sources_are_rejected(self):
        for text in ("", "\ufeff# only a comment\n\n", "#" + "x" * 2_000_000):
            with self.subTest(length=len(text)):
                with self.assertRaises(generator.RuleError):
                    generator.parse_rules(text, "fixture")


class BuildRulesTests(OfflineTestCase):
    def test_complete_claude_core_and_approved_supplements_are_preserved(self):
        built = generator.build_rules(**valid_sources())
        self.assertEqual(
            built["Claude.list"],
            sorted(CLAUDE_CORE + ("DOMAIN-SUFFIX,claude.app",)
                   + REVIEWED_NETWORKS + CLAUDE_COMPATIBILITY_RULES),
        )

    def test_xai_has_four_meta_suffixes_and_four_approved_additions(self):
        built = generator.build_rules(**valid_sources())
        self.assertEqual(built["Xai.list"], sorted(XAI_CORE + CURSOR_CORE + XAI_EXTRA))
        self.assertEqual(len(built["Xai.list"]), 12)
        self.assertEqual(len(set(built["Xai.list"])), 12)

    def test_xai_and_cursor_suffixes_match_multiple_subdomain_levels(self):
        xai = generator.build_rules(**valid_sources())["Xai.list"]
        for suffix in tuple(rule.split(",", 1)[1] for rule in XAI_CORE + CURSOR_CORE) + (
            "cursorvm.com", "grokusercontent.com",
        ):
            for domain in (suffix, "fixture." + suffix, "nested.fixture." + suffix):
                with self.subTest(domain=domain):
                    self.assertTrue(generator.domain_matches(xai, domain))
            for domain in ("not" + suffix, suffix + ".example.invalid", suffix.replace(".", "-")):
                with self.subTest(domain=domain):
                    self.assertFalse(generator.domain_matches(xai, domain))

    def test_xai_exact_external_hosts_do_not_expand_to_other_tenants(self):
        xai = generator.build_rules(**valid_sources())["Xai.list"]
        exact_hosts = (
            ("accounts.spacex.ai", ("spacex.ai", "other.spacex.ai", "child.accounts.spacex.ai",
                                     "notaccounts.spacex.ai")),
            ("anysphere-binaries.s3.us-east-1.amazonaws.com",
             ("amazonaws.com", "s3.us-east-1.amazonaws.com", "other.s3.us-east-1.amazonaws.com",
              "other-binaries.s3.us-east-1.amazonaws.com",
              "anysphere-binaries.s3.us-east-2.amazonaws.com",
              "child.anysphere-binaries.s3.us-east-1.amazonaws.com")),
        )
        for host, other_tenants in exact_hosts:
            with self.subTest(host=host):
                self.assertIn("DOMAIN," + host, xai)
                self.assertNotIn("DOMAIN-SUFFIX," + host, xai)
                self.assertTrue(generator.domain_matches(xai, host))
            for domain in other_tenants:
                with self.subTest(domain=domain):
                    self.assertFalse(generator.domain_matches(xai, domain))

    def test_xai_does_not_import_github_claude_or_unrelated_rules_from_other_sources(self):
        built = generator.build_rules(**valid_sources())
        xai = built["Xai.list"]
        for domain in (
            "api.github.com", "claude.com", "anthropic.com", "provider-0.example.invalid",
            "supplement.example.invalid",
        ):
            with self.subTest(domain=domain):
                self.assertFalse(generator.domain_matches(xai, domain))
        for domain in ("api.grokusercontent.com", "api.cursorvm.com"):
            with self.subTest(domain=domain):
                self.assertTrue(generator.domain_matches(xai, domain))
        self.assertTrue(generator.domain_matches(built["AI-Kelee.list"], "api.github.com"))
        for rule in XAI_CORE + CURSOR_CORE:
            self.assertIn(rule, built["AI-Meta.list"])
        for rule in KELEE_XAI_FALLBACKS:
            self.assertIn(rule, built["AI-Kelee.list"])

    def test_xai_rejects_shared_infrastructure_github_and_other_provider_domains(self):
        blocked = tuple(generator.SHARED_INFRASTRUCTURE) + tuple(generator.CLAUDE_SUFFIXES) + (
            "github.com", "x.com", "twitter.com", "claude.app", "spacex.ai", "amazonaws.com",
            "s3.us-east-1.amazonaws.com", "chatgpt.com", "openai.com", "google.com",
        )
        for source in ("meta_xai", "meta_cursor"):
            for domain in blocked:
                with self.subTest(source=source, domain=domain):
                    sources = valid_sources()
                    sources[source] += f"DOMAIN-SUFFIX,{domain}\n"
                    with self.assertRaisesRegex(generator.RuleError, "Xai source includes unrelated"):
                        generator.build_rules(**sources)

    def test_xai_sources_require_each_core_domain_as_a_suffix_rule(self):
        for source, core in (("meta_xai", XAI_CORE), ("meta_cursor", CURSOR_CORE)):
            for line in core:
                with self.subTest(source=source, rule=line):
                    sources = valid_sources()
                    sources[source] = source_text(item for item in core if item != line) + line.replace(
                        "DOMAIN-SUFFIX,", "DOMAIN,"
                    ) + "\n"
                    with self.assertRaisesRegex(generator.RuleError, "source lost required domains"):
                        generator.build_rules(**sources)

    def test_xai_core_domains_are_individually_required(self):
        for source, core in (("meta_xai", XAI_CORE), ("meta_cursor", CURSOR_CORE)):
            for line in core:
                with self.subTest(source=source, rule=line):
                    sources = valid_sources()
                    sources[source] = source_text(item for item in core if item != line)
                    with self.assertRaisesRegex(generator.RuleError, "source lost required domains"):
                        generator.build_rules(**sources)

    def test_shared_compatibility_suffixes_cover_subdomains_with_label_boundaries(self):
        claude = generator.build_rules(**valid_sources())["Claude.list"]
        for suffix in ("sentry.io", "statsigapi.net"):
            for domain in (suffix, "fixture." + suffix, "nested.fixture." + suffix):
                with self.subTest(domain=domain):
                    self.assertTrue(generator.domain_matches(claude, domain))
            for domain in ("not" + suffix, suffix + ".example.invalid", suffix.replace(".", "-")):
                with self.subTest(domain=domain):
                    self.assertFalse(generator.domain_matches(claude, domain))
        for domain in ("sentry.i0", "statsigapi.ne", "statsigapi.com"):
            with self.subTest(domain=domain):
                self.assertFalse(generator.domain_matches(claude, domain))

    def test_anthropic_external_hosts_are_exact_without_other_tenant_coverage(self):
        claude = generator.build_rules(**valid_sources())["Claude.list"]
        external_hosts = (
            ("anthropic.auth0.com", "auth0.com", "fixture.auth0.com"),
            ("anthropic-com.ghost.io", "ghost.io", "fixture.ghost.io"),
            ("anthropic.com.cdn.cloudflare.net", "cloudflare.net", "fixture.cdn.cloudflare.net"),
        )
        for host, platform, other_tenant in external_hosts:
            with self.subTest(host=host):
                self.assertIn("DOMAIN," + host, claude)
                self.assertNotIn("DOMAIN-SUFFIX," + host, claude)
                self.assertTrue(generator.domain_matches(claude, host))
            for domain in (platform, other_tenant, "child." + host, "not" + host,
                           host + ".example.invalid"):
                with self.subTest(domain=domain):
                    self.assertFalse(generator.domain_matches(claude, domain))

    def test_claude_is_removed_from_meta_and_kelee(self):
        built = generator.build_rules(**valid_sources())
        self.assertEqual(built["AI-Meta.list"], sorted(AI_CORE + AI_SYNTHETIC + XAI_CORE + CURSOR_CORE))
        self.assertEqual(built["AI-Kelee.list"], sorted(KELEE_ADDITIONS + KELEE_XAI_FALLBACKS + ("DOMAIN,api.github.com",)))
        for name in ("AI-Meta.list", "AI-Kelee.list"):
            with self.subTest(output=name):
                self.assertTrue(set(built[name]).isdisjoint(built["Claude.list"]))

    def test_compatibility_rules_and_subdomains_are_removed_from_meta_and_kelee(self):
        baseline = generator.build_rules(**valid_sources())
        covered = CLAUDE_COMPATIBILITY_RULES + (
            "DOMAIN,fixture.sentry.io",
            "DOMAIN,nested.fixture.sentry.io",
            "DOMAIN-SUFFIX,fixture.sentry.io",
            "DOMAIN,fixture.statsigapi.net",
            "DOMAIN,nested.fixture.statsigapi.net",
            "DOMAIN-SUFFIX,fixture.statsigapi.net",
        )
        for source in ("meta_ai", "kelee"):
            with self.subTest(source=source):
                sources = valid_sources()
                sources[source] += source_text(covered)
                self.assertEqual(generator.build_rules(**sources), baseline)

    def test_compatibility_duplicates_in_all_sources_do_not_change_output(self):
        sources = valid_sources()
        repeated = dict(sources)
        for name in ("meta_ai", "meta_claude", "kelee"):
            repeated[name] += source_text(CLAUDE_COMPATIBILITY_RULES * 3)
        self.assertEqual(generator.build_rules(**repeated), generator.build_rules(**sources))

    def test_compatibility_deduplication_keeps_other_tenants_and_near_miss_hosts(self):
        baseline = generator.build_rules(**valid_sources())
        retained = (
            "DOMAIN,fixture.auth0.com",
            "DOMAIN,fixture.ghost.io",
            "DOMAIN,fixture.cdn.cloudflare.net",
            "DOMAIN,child.anthropic.auth0.com",
            "DOMAIN,child.anthropic-com.ghost.io",
            "DOMAIN,child.anthropic.com.cdn.cloudflare.net",
            "DOMAIN,notsentry.io",
            "DOMAIN,sentry.io.example.invalid",
            "DOMAIN,notstatsigapi.net",
            "DOMAIN,statsigapi.net.example.invalid",
        )
        for source, output in (("meta_ai", "AI-Meta.list"), ("kelee", "AI-Kelee.list")):
            with self.subTest(source=source):
                sources = valid_sources()
                sources[source] += source_text(retained)
                expected = dict(baseline)
                expected[output] = sorted(baseline[output] + list(retained))
                self.assertEqual(generator.build_rules(**sources), expected)

    def test_kelee_deduplication_respects_suffix_boundaries_and_exact_rules(self):
        sources = valid_sources()
        sources["meta_ai"] += "DOMAIN,exact.example.invalid\n"
        additions = (
            "DOMAIN-SUFFIX,exact.example.invalid",
            "DOMAIN,otherprovider-0.example.invalid",
            "DOMAIN,api.provider-0.example.invalid",
        )
        sources["kelee"] += source_text(additions)
        built = generator.build_rules(**sources)
        self.assertEqual(
            built["AI-Kelee.list"],
            sorted(KELEE_ADDITIONS + KELEE_XAI_FALLBACKS + ("DOMAIN,api.github.com",) + additions[:2]),
        )

    def test_unapproved_shared_platforms_and_telemetry_do_not_enter_claude(self):
        blocked = (
            "datadoghq.com", "datadoghq.eu", "sift.com", "siftscience.com",
            "intercom.io", "intercomcdn.com", "cloudflare.com", "cloudflare.net",
            "b-cdn.net", "auth0.com", "ghost.io", "usefathom.com", "github.com",
            "githubusercontent.com", "googleapis.com", "browser-intake-us5-datadoghq.com",
        )
        for domain in blocked:
            for kind in ("DOMAIN", "DOMAIN-SUFFIX"):
                with self.subTest(domain=domain, kind=kind):
                    sources = valid_sources()
                    sources["meta_claude"] += f"{kind},{domain}\n"
                    with self.assertRaisesRegex(generator.RuleError, "shared (infrastructure|telemetry)"):
                        generator.build_rules(**sources)

    def test_unrelated_asn_is_rejected_in_every_source(self):
        for source in valid_sources():
            with self.subTest(source=source):
                sources = valid_sources()
                sources[source] += "IP-ASN,64512,no-resolve\n"
                with self.assertRaises(generator.RuleError):
                    generator.build_rules(**sources)

    def test_anthropic_upstream_cannot_expand_to_ip_rules(self):
        sources = valid_sources()
        sources["meta_claude"] += source_text(REVIEWED_NETWORKS)
        with self.assertRaisesRegex(generator.RuleError, "domain rules only"):
            generator.build_rules(**sources)

    def test_ordinary_github_is_rejected_but_copilot_is_retained(self):
        baseline = generator.build_rules(**valid_sources())
        self.assertIn("DOMAIN,copilot-proxy.githubusercontent.com", baseline["AI-Meta.list"])
        for source in ("meta_ai", "kelee"):
            with self.subTest(source=source):
                sources = valid_sources()
                sources[source] += "DOMAIN-SUFFIX,github.com\n"
                with self.assertRaisesRegex(generator.RuleError, "entire GitHub site"):
                    generator.build_rules(**sources)

    def test_each_required_claude_domain_and_website_cdn_is_guarded(self):
        for line in CLAUDE_CORE[:-1]:
            with self.subTest(rule=line):
                sources = valid_sources()
                sources["meta_claude"] = source_text(item for item in CLAUDE_CORE if item != line)
                with self.assertRaisesRegex(generator.RuleError, "Anthropic source lost"):
                    generator.build_rules(**sources)

    def test_each_required_ai_service_is_guarded(self):
        for line in AI_CORE:
            with self.subTest(rule=line):
                sources = valid_sources()
                sources["meta_ai"] = source_text(item for item in sources["meta_ai"].splitlines() if item != line)
                with self.assertRaisesRegex(generator.RuleError, "Meta AI source lost required services"):
                    generator.build_rules(**sources)

    def test_empty_sources_and_missing_supplements_are_rejected(self):
        for source in valid_sources():
            with self.subTest(source=source):
                sources = valid_sources()
                sources[source] = "# empty fixture\n"
                with self.assertRaises(generator.RuleError):
                    generator.build_rules(**sources)
        sources = valid_sources()
        sources["kelee"] = sources["meta_ai"]
        with self.assertRaisesRegex(generator.RuleError, "incomplete AI sources"):
            generator.build_rules(**sources)

    def test_suspiciously_small_ai_source_is_rejected(self):
        sources = valid_sources()
        sources["meta_ai"] = source_text(AI_CORE)
        with self.assertRaisesRegex(generator.RuleError, "incomplete AI sources"):
            generator.build_rules(**sources)

    def test_input_order_comments_and_duplicates_do_not_change_output(self):
        sources = valid_sources()
        rearranged = {
            name: "# regenerated upstream fixture\n" + source_text(reversed(text.splitlines())) + text
            for name, text in sources.items()
        }
        self.assertEqual(generator.build_rules(**sources), generator.build_rules(**rearranged))


class FetchTextTests(OfflineTestCase):
    def test_kelee_request_uses_the_compatible_loon_user_agent(self):
        content = b"DOMAIN,example.invalid\n"
        response = subprocess.CompletedProcess([], 0, stdout=content, stderr=b"")
        with patch.object(generator.subprocess, "run", return_value=response) as run:
            self.assertEqual(generator.fetch_text(generator.KELEE_URL), content.decode())
        command = run.call_args.args[0]
        self.assertEqual(command[-1], generator.KELEE_URL)
        self.assertEqual(command.count("--user-agent"), 1)
        self.assertEqual(
            command[command.index("--user-agent") + 1],
            "Loon/1005 CFNetwork/3860.600.31 Darwin/25.0.0",
        )

    def test_only_the_exact_kelee_entrypoint_gets_the_loon_identity(self):
        urls = (
            generator.META_HEAD,
            f"{generator.META_RAW}/{REVISION}/geo/geosite/classical/anthropic.list",
            "https://example.invalid/Tool/Loon/Lsr/AI.lsr",
            generator.KELEE_URL + "?fixture=example.invalid",
        )
        response = subprocess.CompletedProcess([], 0, stdout=b"fixture", stderr=b"")
        for url in urls:
            with self.subTest(source=url.rsplit("/", 1)[-1]):
                with patch.object(generator.subprocess, "run", return_value=response) as run:
                    generator.fetch_text(url)
                command = run.call_args.args[0]
                self.assertEqual(command[-1], url)
                self.assertEqual(command.count("--user-agent"), 1)
                self.assertEqual(command[command.index("--user-agent") + 1], "loon-ai-rules/1")

    def test_failed_curl_responses_report_the_source_without_response_contents(self):
        for url, source in ((generator.KELEE_URL, "Kelee"), (generator.META_HEAD, "MetaCubeX")):
            for code in (22, 28):
                with self.subTest(source=source, code=code):
                    response = subprocess.CompletedProcess(
                        [], code, stdout=b"DOMAIN,example.invalid\n",
                        stderr=b"fixture transport detail: example.invalid",
                    )
                    with patch.object(generator.subprocess, "run", return_value=response):
                        with self.assertRaises(generator.RuleError) as caught:
                            generator.fetch_text(url)
                    self.assertEqual(
                        str(caught.exception),
                        f"{source}: public upstream download failed (curl {code})",
                    )
                    self.assertNotIn("example.invalid", str(caught.exception))

    def test_successful_transport_with_non_utf8_content_is_rejected(self):
        response = subprocess.CompletedProcess([], 0, stdout=b"\xff\xfe", stderr=b"")
        with patch.object(generator.subprocess, "run", return_value=response):
            with self.assertRaisesRegex(generator.RuleError, "not UTF-8"):
                generator.fetch_text(generator.KELEE_URL)

    def test_process_timeout_and_launch_failure_are_not_converted_to_content(self):
        failures = (subprocess.TimeoutExpired("fixture download", 70), OSError("fixture launch failure"))
        for error in failures:
            with self.subTest(error=type(error).__name__):
                with patch.object(generator.subprocess, "run", side_effect=error):
                    with self.assertRaises(type(error)) as caught:
                        generator.fetch_text(generator.KELEE_URL)
                self.assertIs(caught.exception, error)


class BrowserTlsTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.get = Mock(side_effect=AssertionError("browser TLS requests require a fixture"))
        module = patch.dict(sys.modules, {"curl_cffi": SimpleNamespace(get=self.get)})
        module.start()
        self.addCleanup(module.stop)

    def serve(self, chunks, status=200):
        def request(_url, **options):
            for chunk in chunks:
                self.assertEqual(options["content_callback"](chunk), len(chunk))
            return SimpleNamespace(status_code=status)

        self.get.side_effect = request

    def test_kelee_uses_loon_headers_with_safari_tls_and_returns_streamed_content(self):
        chunks = (b"DOMAIN,", b"example.invalid\n")
        self.serve(chunks)
        self.assertEqual(generator.fetch_kelee_with_browser_tls(), "DOMAIN,example.invalid\n")
        self.get.assert_called_once()
        self.assertEqual(self.get.call_args.args, (generator.KELEE_URL,))
        options = self.get.call_args.kwargs
        self.assertEqual(options["impersonate"], "safari_ios")
        self.assertIs(options["default_headers"], False)
        self.assertEqual(options["headers"], {
            "User-Agent": "Loon/1005 CFNetwork/3860.600.31 Darwin/25.0.0",
            "Accept": "*/*",
        })
        self.assertEqual(options["timeout"], 60)
        self.assertEqual(options["max_redirects"], 3)

    def test_only_the_exact_kelee_entrypoint_switches_transport(self):
        self.serve((b"DOMAIN,example.invalid\n",))
        urls = (
            generator.META_HEAD,
            f"{generator.META_RAW}/{REVISION}/geo/geosite/classical/anthropic.list",
            "https://example.invalid/Tool/Loon/Lsr/AI.lsr",
            generator.KELEE_URL + "?fixture=example.invalid",
            generator.KELEE_URL + "/",
        )
        with patch.object(generator, "fetch_text", return_value="fixture curl") as curl:
            self.assertEqual(
                generator.fetch_with_browser_tls(generator.KELEE_URL),
                "DOMAIN,example.invalid\n",
            )
            curl.assert_not_called()
            for url in urls:
                with self.subTest(source=url.rsplit("/", 1)[-1]):
                    self.assertEqual(generator.fetch_with_browser_tls(url), "fixture curl")
                    curl.assert_called_with(url)
            self.assertEqual(curl.call_count, len(urls))
        self.get.assert_called_once()

    def test_source_at_the_size_limit_is_accepted(self):
        self.serve((b"x" * 1_000_000, b"y" * 1_000_000))
        self.assertEqual(generator.fetch_kelee_with_browser_tls(), "x" * 1_000_000 + "y" * 1_000_000)

    def test_oversized_stream_is_aborted_and_rejected_even_if_transport_returns(self):
        for transport_raises in (False, True):
            with self.subTest(transport_raises=transport_raises):
                accepted = []

                def request(_url, **options):
                    receive = options["content_callback"]
                    accepted.append(receive(b"x" * 1_000_000))
                    accepted.append(receive(b"y" * 1_000_000))
                    accepted.append(receive(b"z"))
                    if transport_raises:
                        raise RuntimeError("fixture callback aborted: example.invalid")
                    return SimpleNamespace(status_code=200)

                self.get.side_effect = request
                with self.assertRaisesRegex(generator.RuleError, "^Kelee: source is too large$"):
                    generator.fetch_kelee_with_browser_tls()
                self.assertEqual(accepted, [1_000_000, 1_000_000, 0])

    def test_non_success_status_is_rejected_without_response_contents(self):
        for status in (204, 301, 403, 500):
            with self.subTest(status=status):
                self.serve((b"fixture response body: example.invalid",), status)
                with self.assertRaises(generator.RuleError) as caught:
                    generator.fetch_kelee_with_browser_tls()
                self.assertEqual(
                    str(caught.exception),
                    f"Kelee: public upstream download failed (HTTP {status})",
                )
                self.assertNotIn("example.invalid", str(caught.exception))

    def test_browser_challenges_are_rejected_without_response_contents(self):
        for status in (200, 403):
            for marker in (b"/cdn-cgi/challenge-platform", b"cf-chl-fixture"):
                with self.subTest(status=status, marker=marker):
                    self.serve((b"<html>fixture: example.invalid ", marker, b"</html>"), status)
                    with self.assertRaisesRegex(generator.RuleError, "browser challenge") as caught:
                        generator.fetch_kelee_with_browser_tls()
                    self.assertNotIn("example.invalid", str(caught.exception))
                    self.assertNotIn(marker.decode(), str(caught.exception))

    def test_non_utf8_content_is_rejected(self):
        self.serve((b"DOMAIN,example.invalid\n", b"\xff\xfe"))
        with self.assertRaisesRegex(generator.RuleError, "^Kelee: public upstream is not UTF-8$"):
            generator.fetch_kelee_with_browser_tls()

    def test_transport_failures_are_rejected_without_exception_details(self):
        for error_type in (TimeoutError, OSError, RuntimeError):
            with self.subTest(error_type=error_type.__name__):
                self.get.side_effect = error_type("fixture transport details: example.invalid")
                with self.assertRaises(generator.RuleError) as caught:
                    generator.fetch_kelee_with_browser_tls()
                self.assertEqual(
                    str(caught.exception),
                    f"Kelee: browser TLS transport failed ({error_type.__name__})",
                )
                self.assertNotIn("example.invalid", str(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)

    def test_missing_optional_dependency_is_rejected(self):
        with patch.dict(sys.modules, {"curl_cffi": None}):
            with self.assertRaisesRegex(generator.RuleError, "requires the pinned curl_cffi dependency"):
                generator.fetch_kelee_with_browser_tls()
        self.get.assert_not_called()


class FetchSourcesTests(OfflineTestCase):
    def test_all_four_meta_files_are_pinned_to_the_same_single_head_lookup(self):
        fetch = FixtureFetch()
        sources, revision = generator.fetch_sources(fetch)
        self.assertEqual(revision, REVISION)
        self.assertEqual(sources, valid_sources())
        self.assertEqual(fetch.calls, list(fetch.responses))
        self.assertEqual(fetch.calls.count(generator.META_HEAD), 1)
        self.assertTrue(all(f"/{REVISION}/" in url for url in fetch.calls[1:5]))

    def test_invalid_revision_responses_stop_before_rule_downloads(self):
        invalid = ("not json", "{}", "null", "[]", '{"sha": null}', '{"sha": 7}',
                   json.dumps({"sha": "main"}), json.dumps({"sha": "a" * 39}), json.dumps({"sha": "g" * 40}))
        for response in invalid:
            with self.subTest(response=response):
                fetch = FixtureFetch()
                fetch.responses[generator.META_HEAD] = response
                with self.assertRaises(generator.RuleError):
                    generator.fetch_sources(fetch)
                self.assertEqual(fetch.calls, [generator.META_HEAD])


class UpdateTests(OfflineTestCase):
    def test_all_four_files_have_the_validated_rules_and_matching_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rules"
            rules, changed = generator.update(output, FixtureFetch())
            self.assertTrue(changed)
            self.assertEqual(set(path.name for path in output.iterdir()), set(generator.OUTPUT_NAMES))
            for name, lines in rules.items():
                with self.subTest(output=name):
                    text = (output / name).read_text(encoding="utf-8")
                    body = source_text(lines)
                    self.assertEqual(text.split("\n\n", 1)[1], body)
                    self.assertIn(f"# Rules: {len(lines)}\n", text)
                    self.assertIn(f"# Content SHA-256: {hashlib.sha256(body.encode()).hexdigest()}\n", text)
                    self.assertNotIn("\r", text)
                    self.assertIn("# Attribution:", text)
                    if name == "AI-Kelee.list":
                        self.assertIn(generator.KELEE_URL, text)
                        self.assertIn("CC BY-NC-SA 4.0", text)
                    elif name == "Xai.list":
                        self.assertIn(f"/{REVISION}/geo/geosite/classical/xai.list", text)
                        self.assertIn(f"/{REVISION}/geo/geosite/classical/cursor.list", text)
                    else:
                        self.assertIn(f"/{REVISION}/", text)
                    if name == "Claude.list":
                        self.assertIn("# Compatibility:", text)
                        self.assertIn("https://github.com/lich13/loon-ai-rules#claude-compatibility", text)
            self.assertEqual([path.name for path in Path(temporary).iterdir()], ["rules"])

    def test_regeneration_keeps_compatibility_rules_when_upstream_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rules"
            generator.update(output, FixtureFetch())
            sources = valid_sources()
            sources["meta_claude"] += "DOMAIN,refreshed-core.example.invalid\n"
            _, changed = generator.update(output, FixtureFetch(sources, NEXT_REVISION))
            self.assertTrue(changed)
            text = (output / "Claude.list").read_text(encoding="utf-8")
            body = text.split("\n\n", 1)[1].splitlines()
            self.assertIn("DOMAIN,refreshed-core.example.invalid", body)
            self.assertIn(f"/{NEXT_REVISION}/", text)
            for rule in CLAUDE_COMPATIBILITY_RULES:
                with self.subTest(rule=rule):
                    self.assertEqual(body.count(rule), 1)
            self.assertEqual([path.name for path in Path(temporary).iterdir()], ["rules"])

    def test_every_artifact_is_ready_before_the_first_destination_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rules"
            expected = generator.build_rules(**valid_sources())
            replacements = []
            real_replace = generator.os.replace

            def replace(source, destination):
                source, destination = Path(source), Path(destination)
                if not replacements:
                    self.assertEqual({path.name for path in source.parent.iterdir()}, set(generator.OUTPUT_NAMES))
                    for name, lines in expected.items():
                        self.assertEqual((source.parent / name).read_text().split("\n\n", 1)[1], source_text(lines))
                self.assertEqual(destination.parent, output)
                replacements.append(destination.name)
                real_replace(source, destination)

            with patch.object(generator.os, "replace", side_effect=replace):
                generator.update(output, FixtureFetch())
            self.assertEqual(replacements, list(generator.OUTPUT_NAMES))

    def test_failure_at_each_download_preserves_existing_files(self):
        for failed_url in FixtureFetch().responses:
            with self.subTest(source=failed_url.rsplit("/", 1)[-1]):
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "rules"
                    generator.update(output, FixtureFetch())
                    before = snapshot(output)
                    fetch = FixtureFetch()
                    fetch.responses[failed_url] = generator.RuleError("fixture download failed")
                    with self.assertRaises(generator.RuleError):
                        generator.update(output, fetch)
                    self.assertEqual(snapshot(output), before)
                    self.assertEqual(fetch.calls[-1], failed_url)
                    self.assertEqual([path.name for path in Path(temporary).iterdir()], ["rules"])

    def test_download_timeout_and_io_failure_preserve_existing_files(self):
        failures = (subprocess.TimeoutExpired("fixture download", 1), OSError("fixture transport failure"))
        for error in failures:
            with self.subTest(error=type(error).__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "rules"
                    generator.update(output, FixtureFetch())
                    before = snapshot(output)
                    fetch = FixtureFetch()
                    fetch.responses[generator.KELEE_URL] = error
                    with self.assertRaises(type(error)):
                        generator.update(output, fetch)
                    self.assertEqual(snapshot(output), before)

    def test_actual_fetch_failure_at_each_source_preserves_existing_files(self):
        for failed_url in FixtureFetch().responses:
            with self.subTest(source=failed_url.rsplit("/", 1)[-1]):
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "rules"
                    generator.update(output, FixtureFetch())
                    before = snapshot(output)
                    fetch = FixtureFetch()

                    def download(command, **_kwargs):
                        url = command[-1]
                        content = fetch(url).encode("utf-8")
                        return subprocess.CompletedProcess(
                            command, 22 if url == failed_url else 0,
                            stdout=content, stderr=b"fixture transport detail: example.invalid",
                        )

                    with patch.object(generator.subprocess, "run", side_effect=download):
                        with self.assertRaises(generator.RuleError):
                            generator.update(output, generator.fetch_text)
                    self.assertEqual(fetch.calls[-1], failed_url)
                    self.assertEqual(snapshot(output), before)
                    self.assertEqual([path.name for path in Path(temporary).iterdir()], ["rules"])

    def test_validation_failure_preserves_every_destination_file(self):
        invalid_sources = []
        unknown = valid_sources()
        unknown["kelee"] += "IP-ASN,64512,no-resolve\n"
        invalid_sources.append(unknown)
        unknown_xai = valid_sources()
        unknown_xai["meta_xai"] += "IP-ASN,64512,no-resolve\n"
        invalid_sources.append(unknown_xai)
        missing = valid_sources()
        missing["meta_claude"] = source_text(CLAUDE_CORE[1:])
        invalid_sources.append(missing)
        missing_xai = valid_sources()
        missing_xai["meta_xai"] = source_text(XAI_CORE[:-1])
        invalid_sources.append(missing_xai)
        missing_cursor = valid_sources()
        missing_cursor["meta_cursor"] = source_text(CURSOR_CORE[:-1])
        invalid_sources.append(missing_cursor)
        for source in valid_sources():
            empty = valid_sources()
            empty[source] = ""
            invalid_sources.append(empty)
        for index, sources in enumerate(invalid_sources):
            with self.subTest(fixture=index):
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "rules"
                    generator.update(output, FixtureFetch())
                    before = snapshot(output)
                    with self.assertRaises(generator.RuleError):
                        generator.update(output, FixtureFetch(sources))
                    self.assertEqual(snapshot(output), before)

    def test_failed_first_generation_does_not_create_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "not-created" / "rules"
            fetch = FixtureFetch()
            fetch.responses[generator.KELEE_URL] = generator.RuleError("fixture download failed")
            with self.assertRaises(generator.RuleError):
                generator.update(output, fetch)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_staging_write_failure_preserves_all_four_existing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rules"
            generator.update(output, FixtureFetch())
            before = snapshot(output)
            sources = valid_sources()
            sources["kelee"] += "DOMAIN,new-supplement.example.invalid\n"
            with patch.object(generator.os, "fsync", side_effect=[None, OSError("fixture staging write failed")]):
                with patch.object(generator.os, "replace", wraps=generator.os.replace) as replace:
                    with self.assertRaisesRegex(OSError, "fixture staging write failed"):
                        generator.update(output, FixtureFetch(sources))
                    replace.assert_not_called()
            self.assertEqual(snapshot(output), before)
            self.assertEqual([path.name for path in Path(temporary).iterdir()], ["rules"])

    def test_identical_generation_does_not_rewrite_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rules"
            first, _ = generator.update(output, FixtureFetch())
            before = snapshot(output)
            with patch.object(generator.os, "replace") as replace:
                second, changed = generator.update(output, FixtureFetch())
            self.assertFalse(changed)
            self.assertEqual(first, second)
            replace.assert_not_called()
            self.assertEqual(snapshot(output), before)

    def test_upstream_revision_and_comment_changes_do_not_rewrite_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rules"
            generator.update(output, FixtureFetch())
            before = snapshot(output)
            sources = {name: "# a new source comment\n" + source_text(reversed(text.splitlines()))
                       for name, text in valid_sources().items()}
            with patch.object(generator.os, "replace") as replace:
                _, changed = generator.update(output, FixtureFetch(sources, NEXT_REVISION))
            self.assertFalse(changed)
            replace.assert_not_called()
            self.assertEqual(snapshot(output), before)

    def test_missing_artifact_is_repaired_as_a_complete_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rules"
            generator.update(output, FixtureFetch())
            (output / "AI-Kelee.list").unlink()
            _, changed = generator.update(output, FixtureFetch())
            self.assertTrue(changed)
            self.assertEqual({path.name for path in output.iterdir()}, set(generator.OUTPUT_NAMES))


if __name__ == "__main__":
    unittest.main()
