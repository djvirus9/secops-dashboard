from __future__ import annotations

import json

import pytest
from app.parsers import ParserRegistry, get_parser, parse_scan_results
from defusedxml.common import DefusedXmlException


def test_catch_all_json_parser_does_not_shadow_auto_detection():
    content = json.dumps(
        {
            "results": [
                {
                    "title": "Example vulnerability",
                    "severity": "high",
                    "asset": "server-1",
                }
            ]
        }
    )

    assert ParserRegistry.auto_detect(content, "scan.json") is None

    explicit = parse_scan_results(
        content,
        parser_name="generic-json",
        filename="scan.json",
    )
    assert explicit[0].asset == "server-1"
    assert explicit[0].severity.value == "high"


def test_catch_all_parsers_are_marked_non_auto_detectable():
    parser = get_parser("checkmarx_cxflow")
    assert parser is not None
    parser_class = type(parser)
    assert ParserRegistry.is_auto_detectable(parser_class) is False


def test_legacy_parser_signatures_and_field_aliases_are_supported(monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_PARSERS", "true")
    content = json.dumps(
        {
            "results": [
                {
                    "gem": {"name": "rack", "version": "1.0"},
                    "advisory": {"title": "Rack issue", "cve": "CVE-2026-0001"},
                    "criticality": "high",
                }
            ]
        }
    )
    findings = parse_scan_results(content, parser_name="bundler_audit", filename="audit.json")
    assert findings[0].cve_id == "CVE-2026-0001"
    assert findings[0].severity.value == "high"


def test_string_severities_from_legacy_parsers_are_normalized(monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_PARSERS", "true")
    content = json.dumps(
        {
            "version": "1.0",
            "generated_at": "2026-09-09T00:00:00Z",
            "results": {
                "src/settings.py": [
                    {"type": "Secret Keyword", "line_number": 12}
                ]
            },
        }
    )
    findings = parse_scan_results(content, parser_name="detect_secrets")
    assert findings[0].severity.value == "high"


@pytest.mark.parametrize(
    "parser_name",
    ["credscan", "detect_secrets", "gitguardian", "gitleaks", "noseyparker"],
)
def test_secret_scanners_are_classified_for_storage_redaction(parser_name):
    parser = get_parser(parser_name)

    assert parser is not None
    assert parser.category.value == "secrets"
    assert ParserRegistry.contains_secret_evidence(parser_name)


@pytest.mark.parametrize(
    ("expected", "content"),
    [
        (
            "semgrep",
            {
                "results": [
                    {
                        "check_id": "python.lang.correctness.example",
                        "path": "app.py",
                        "start": {"line": 1},
                        "extra": {"severity": "ERROR", "metadata": {}},
                    }
                ]
            },
        ),
        (
            "osv-scanner",
            {"results": [{"source": {"path": "go.mod"}, "packages": []}]},
        ),
        (
            "nuclei",
            {
                "template-id": "http-misconfiguration",
                "info": {"name": "HTTP misconfiguration", "severity": "high"},
                "host": "https://example.test",
            },
        ),
    ],
)
def test_representative_formats_auto_detect_without_ambiguity(expected, content):
    detected = ParserRegistry.auto_detect(json.dumps(content), "scan.json")
    assert detected is not None
    assert detected.name == expected


def test_ambiguous_specific_formats_require_explicit_parser(monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_PARSERS", "true")
    class First:
        name = "first"
        auto_detectable = True

        @classmethod
        def can_parse(cls, content, filename=None):
            return content == "match"

    class Second(First):
        name = "second"

    original = ParserRegistry._parsers.copy()
    monkeypatch.setattr(ParserRegistry, "_parsers", {"first": First, "second": Second})
    with pytest.raises(ValueError, match="Ambiguous scan format"):
        ParserRegistry.auto_detect("match")
    monkeypatch.setattr(ParserRegistry, "_parsers", original)


def test_xml_entities_are_rejected_before_parser_exception_handlers(monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_PARSERS", "true")
    malicious_xml = """<!DOCTYPE nmaprun [
    <!ENTITY secret "expanded-value">
    ]><nmaprun><host><address addr="&secret;" /></host></nmaprun>"""

    with pytest.raises(DefusedXmlException):
        parse_scan_results(malicious_xml, parser_name="nmap", filename="scan.xml")


def test_veracode_detection_requires_the_exact_xml_namespace():
    parser = get_parser("veracode")
    assert parser is not None
    valid = (
        '<detailedreport xmlns="https://www.veracode.com/schema/reports/export/1.0" '
        'app_id="example" />'
    )
    misleading = "<report><url>https://veracode.com/example</url></report>"

    assert parser.can_parse(valid, "results.xml")
    assert not parser.can_parse(misleading, "results.xml")
    assert not parser.can_parse("veracode.com", "results.xml")
