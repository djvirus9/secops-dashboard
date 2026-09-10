from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from app.parsers import get_parser, list_parsers, parse_scan_results
from app.parsers.support import VERIFIED_PARSERS


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "parsers"
FIXTURES = {path.stem: json.loads(path.read_text()) for path in sorted(FIXTURE_DIR.glob("*.json"))}
CASES = [(name, parser) for name, fixture in FIXTURES.items() for parser in fixture["parsers"]]


def content(value):
    return value if isinstance(value, str) else json.dumps(value, indent=2)


def test_every_enabled_parser_has_fixture_coverage():
    assert {parser for _, parser in CASES} == VERIFIED_PARSERS


@pytest.mark.parametrize(("name", "parser"), CASES)
def test_verified_vendor_findings_are_preserved(name, parser):
    fixture = FIXTURES[name]
    findings = parse_scan_results(content(fixture["valid"]), parser_name=parser, filename=fixture["filename"])
    assert len(findings) == len(fixture["expected"])
    for finding, expected in zip(findings, fixture["expected"]):
        payload = finding.to_signal_payload()
        for key, value in expected.items():
            assert payload[key] == value


@pytest.mark.parametrize(("name", "parser"), CASES)
def test_verified_clean_scans_are_accepted(name, parser):
    fixture = FIXTURES[name]
    assert parse_scan_results(content(fixture["clean"]), parser_name=parser, filename=fixture["filename"]) == []


@pytest.mark.parametrize(("name", "parser"), CASES)
def test_invalid_vendor_shape_is_never_a_successful_clean_scan(name, parser):
    fixture = FIXTURES[name]
    with pytest.raises(ValueError):
        parse_scan_results(content(fixture["invalid"]), parser_name=parser, filename=fixture["filename"])


@pytest.mark.parametrize("parser", sorted(VERIFIED_PARSERS))
def test_truncated_input_is_rejected(parser):
    malformed = 'title,severity\n"unfinished' if parser == "generic-csv" else '{"truncated":'
    with pytest.raises(ValueError):
        parse_scan_results(malformed, parser_name=parser)


@pytest.mark.parametrize("parser", sorted(VERIFIED_PARSERS))
def test_unrecognized_empty_object_is_rejected(parser):
    with pytest.raises(ValueError):
        parse_scan_results("{}", parser_name=parser)


def test_unverified_adapters_are_listed_but_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ALLOW_UNVERIFIED_PARSERS", raising=False)
    metadata = {parser["name"]: parser for parser in list_parsers()}
    assert metadata["trivy"]["enabled"] is True
    assert metadata["trivy"]["verification_status"] == "verified"
    assert metadata["wiz"]["enabled"] is False
    assert metadata["wiz"]["verification_status"] == "unverified"
    assert metadata["wiz"]["unavailable_reason"]
    assert metadata["wiz"]["file_types"] == ["json"]
    with pytest.raises(ValueError, match="disabled"):
        parse_scan_results('{"findings": [{"title": "Example"}]}', parser_name="wiz")


def test_compatibility_opt_in_does_not_allow_silent_clean_or_malformed_scans(monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_PARSERS", "true")
    finding = parse_scan_results('{"findings": [{"title": "Example"}]}', parser_name="wiz")
    assert finding[0].title == "Example"
    for invalid in ('{"truncated":', "{}", "[]", "Title,Severity\nExample,HIGH\n"):
        with pytest.raises(ValueError):
            parse_scan_results(invalid, parser_name="wiz")


@pytest.mark.parametrize("parser", ["sarif", "codeql"])
@pytest.mark.parametrize(("score", "severity"), [(0, "info"), (0.1, "low"), (4, "medium"), (7, "high"), (9, "critical"), (10, "critical")])
def test_sarif_security_severity_boundaries(parser, score, severity):
    document = copy.deepcopy(FIXTURES["sarif"]["valid"])
    document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = str(score)
    finding = parse_scan_results(json.dumps(document), parser_name=parser)[0]
    assert finding.severity.value == severity
    assert finding.cvss_score == score


@pytest.mark.parametrize("score", ["NaN", "Infinity", "bad", "-0.1", "10.1"])
def test_invalid_sarif_security_score_is_rejected(score):
    document = copy.deepcopy(FIXTURES["sarif"]["valid"])
    document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = score
    with pytest.raises(ValueError):
        parse_scan_results(json.dumps(document), parser_name="codeql")


def test_codeql_uses_rule_default_and_rule_index_and_auto_detection():
    document = copy.deepcopy(FIXTURES["sarif"]["valid"])
    run = document["runs"][0]
    run["tool"]["driver"]["rules"][0]["properties"].pop("security-severity")
    run["results"][0].pop("ruleId")
    run["results"][0]["ruleIndex"] = 0
    finding = parse_scan_results(json.dumps(document))[0]
    assert finding.severity.value == "high"
    assert finding.source_id == "py/example"


def test_nessus_cvss3_without_cvss2_is_preserved():
    document = FIXTURES["nessus"]["valid"].replace("<cvss_base_score>7.0</cvss_base_score>", "")
    assert parse_scan_results(document, parser_name="nessus")[0].cvss_score == 9.8


def test_nuclei_malformed_later_record_rejects_whole_report():
    valid = json.dumps(FIXTURES["nuclei_json"]["valid"])
    with pytest.raises(ValueError, match="line 2"):
        parse_scan_results(valid + '\n{"truncated":', parser_name="nuclei")


def test_parser_cannot_silently_drop_a_source_record(monkeypatch):
    parser = get_parser("bandit")
    monkeypatch.setattr(type(parser), "parse", lambda self, content, filename=None: [])
    with pytest.raises(ValueError, match="preserve every finding"):
        parse_scan_results(json.dumps(FIXTURES["bandit"]["valid"]), parser_name="bandit")


@pytest.mark.parametrize("parser", ["bandit", "semgrep"])
def test_scanner_reported_errors_do_not_look_like_clean_scans(parser):
    document = copy.deepcopy(FIXTURES[parser]["clean"])
    document["errors"] = [{"message": "Scan failed"}]
    with pytest.raises(ValueError, match="incomplete scans"):
        parse_scan_results(json.dumps(document), parser_name=parser)


@pytest.mark.parametrize(("case", "parser"), [("trivy", "trivy"), ("grype", "grype"), ("osv", "osv-scanner")])
def test_sca_components_distinguish_packages_without_version_in_identity(case, parser):
    first, second = parse_scan_results(json.dumps(FIXTURES[case]["valid"]), parser_name=parser)
    assert first.source_id == second.source_id
    assert first.component != second.component
    assert first.component_version == second.component_version == "1.0"
    assert "1.0" not in first.component


def test_normalized_output_rejects_invalid_scores_and_reference_types():
    for item in ({"title": "Example", "cvss": "NaN"}, {"title": "Example", "references": [{}]}):
        with pytest.raises(ValueError):
            parse_scan_results(json.dumps([item]), parser_name="generic-json")


def test_invalid_severity_and_duplicate_json_fields_are_rejected():
    for document in ('{"title":"Example","severity":"urgent"}', '{"findings":[{"title":"Example"}],"findings":[]}'):
        with pytest.raises(ValueError):
            parse_scan_results(document, parser_name="generic-json")


def test_unexpected_adapter_error_never_exposes_scan_evidence(monkeypatch):
    from app.parsers import ScanValidationError

    def fail(self, content, filename=None):
        raise ValueError("SYNTHETIC-SECRET-IN-EXCEPTION")

    monkeypatch.setattr(type(get_parser("bandit")), "parse", fail)
    with pytest.raises(ScanValidationError) as error:
        parse_scan_results(json.dumps(FIXTURES["bandit"]["valid"]), parser_name="bandit")
    assert "SYNTHETIC-SECRET" not in str(error.value)


@pytest.mark.parametrize("wrapper", ["credentials", "matches"])
def test_credscan_json_envelopes(wrapper):
    records = FIXTURES["credscan_json"]["valid"]
    assert parse_scan_results(json.dumps({wrapper: records}), parser_name="credscan")[0].line_number == 12
    assert parse_scan_results(json.dumps({wrapper: []}), parser_name="credscan") == []


@pytest.mark.parametrize("parser", ["aws-security-hub", "aws_asff"])
def test_asff_array_and_single_finding_forms(parser):
    records = FIXTURES["asff"]["valid"]["Findings"]
    for document in (records, records[0]):
        assert len(parse_scan_results(json.dumps(document), parser_name=parser)) == 2


def test_sarif_artifact_index_and_markdown_message():
    document = copy.deepcopy(FIXTURES["sarif"]["valid"])
    run = document["runs"][0]
    run["artifacts"] = [{"location": {"uri": "app.py"}}]
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}
    run["results"][0]["message"] = {"markdown": "**Example**"}
    finding = parse_scan_results(json.dumps(document), parser_name="sarif")[0]
    assert finding.file_path == "app.py"
    assert finding.description == "**Example**"


def test_blank_credscan_rows_do_not_create_phantom_findings():
    with pytest.raises(ValueError, match="credential type is missing"):
        parse_scan_results("CredentialType,FileName\n,app.py\n", parser_name="credscan")


@pytest.mark.parametrize(("field", "byte_limit"), [
    ("asset", 1500), ("file_path", 4096), ("source_id", 2000),
    ("component", 2000), ("component_version", 1000), ("cve_id", 256),
    ("description", 100_000), ("recommendation", 100_000),
])
def test_normalized_utf8_byte_limits(field, byte_limit):
    from app.parsers.base import ParsedFinding, Severity
    from app.parsers.validation import validate_findings

    finding = ParsedFinding(title="Example", tool="generic-json", severity=Severity.LOW)
    setattr(finding, field, "é" * (byte_limit // 2))
    validate_findings([finding], 1)
    setattr(finding, field, getattr(finding, field) + "é")
    with pytest.raises(ValueError, match="byte limit"):
        validate_findings([finding], 1)


@pytest.mark.parametrize(("field", "limit"), [("title", 500), ("tool", 100)])
def test_normalized_title_and_tool_character_limits(field, limit):
    from app.parsers.base import ParsedFinding, Severity
    from app.parsers.validation import validate_findings

    finding = ParsedFinding(title="Example", tool="generic-json", severity=Severity.LOW)
    setattr(finding, field, "🛡" * limit)
    validate_findings([finding], 1)
    setattr(finding, field, "x" * (limit + 1))
    with pytest.raises(ValueError, match="character limit"):
        validate_findings([finding], 1)


@pytest.mark.parametrize("field", ["title", "tool", "asset", "file_path", "source_id", "component",
                                   "component_version", "cve_id", "description", "recommendation"])
def test_normalized_text_rejects_nul_for_postgresql(field):
    from app.parsers.base import ParsedFinding, Severity
    from app.parsers.validation import validate_findings

    finding = ParsedFinding(title="Example", tool="generic-json", severity=Severity.LOW)
    setattr(finding, field, "before\x00after")
    with pytest.raises(ValueError, match="NUL"):
        validate_findings([finding], 1)


@pytest.mark.parametrize("field", ["references", "tags"])
def test_normalized_collections_have_count_and_utf8_limits(field):
    from app.parsers.base import ParsedFinding, Severity
    from app.parsers.validation import validate_findings

    finding = ParsedFinding(title="Example", tool="generic-json", severity=Severity.LOW)
    setattr(finding, field, ["item"] * 1000)
    validate_findings([finding], 1)
    for values in (["item"] * 1001, ["🛡" * 1025], ["before\x00after"]):
        setattr(finding, field, values)
        with pytest.raises(ValueError):
            validate_findings([finding], 1)
    setattr(finding, field, ["🛡" * 1024])
    validate_findings([finding], 1)


@pytest.mark.parametrize("parser", ["generic-json", "generic-csv"])
def test_generic_titles_are_preserved_or_rejected_without_truncation(parser):
    def report(title):
        return json.dumps([{"title": title}]) if parser == "generic-json" else "title\n" + title + "\n"

    title = "x" * 500
    assert parse_scan_results(report(title), parser_name=parser)[0].title == title
    with pytest.raises(ValueError, match="character limit"):
        parse_scan_results(report(title + "x"), parser_name=parser)


@pytest.mark.parametrize("field", ["line_number", "cwe_id"])
def test_normalized_numbers_fit_postgresql_integer(field):
    from app.parsers.base import ParsedFinding, Severity
    from app.parsers.validation import validate_findings

    finding = ParsedFinding(title="Example", tool="generic-json", severity=Severity.LOW)
    setattr(finding, field, 2_147_483_647)
    validate_findings([finding], 1)
    setattr(finding, field, 2_147_483_648)
    with pytest.raises(ValueError, match="database integer"):
        validate_findings([finding], 1)
