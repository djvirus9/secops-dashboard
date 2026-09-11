"""GitHub client contracts using synthetic, streamed HTTP responses only."""
import asyncio
from dataclasses import asdict
import gzip
import json
import zlib

import httpx
import pytest

from app.github_sync import client as github

TOKEN = "ghp_SYNTHETIC_NOT_A_REAL_CREDENTIAL"
REPOSITORY = "synthetic-owner/synthetic-repo"
CODE_PATH = f"/repos/{REPOSITORY}/code-scanning/alerts"
DEPENDABOT_PATH = f"/repos/{REPOSITORY}/dependabot/alerts"


def code_alert(number=1, state="open"):
    return {"number": number, "state": None,
            "rule": {"id": "py/synthetic", "description": "Synthetic unsafe input",
                     "full_description": "Validate synthetic input before use.",
                     "severity": "warning", "security_severity_level": "critical",
                     "tags": ["security", "external/cwe/cwe-079"], "help": "Apply input validation."},
            "most_recent_instance": {"state": state, "ref": "refs/heads/main",
                                     "message": {"text": "UNSAFE_SOURCE_SNIPPET"},
                                     "location": {"path": "src/synthetic.py", "start_line": 7,
                                                  "snippet": {"text": "UNSAFE_SOURCE_SNIPPET"}}}}


def dependency_alert(number=1, state="open"):
    return {"number": number, "state": state,
            "dependency": {"package": {"name": "synthetic-package", "ecosystem": "pip"},
                           "manifest_path": "requirements.txt"},
            "security_advisory": {"summary": "Synthetic dependency advisory", "severity": "high",
                                  "description": "UNNEEDED_REMOTE_BODY", "cve_id": "CVE-2099-0001",
                                  "cvss": {"score": 8.2}, "cwes": [{"cwe_id": "CWE-20"}]},
            "security_vulnerability": {"vulnerable_version_range": "< 2.0.0",
                                       "first_patched_version": {"identifier": "2.0.0"}}}


class Chunks(httpx.AsyncByteStream):
    def __init__(self, body):
        self.body = body

    async def __aiter__(self):
        for index in range(0, len(self.body), 71):
            yield self.body[index:index + 71]


def response(data=None, *, status=200, headers=None, raw=None):
    body = raw if raw is not None else json.dumps(data).encode()
    return httpx.Response(status, headers=headers or {}, stream=Chunks(body))


@pytest.fixture
def transport(monkeypatch):
    monkeypatch.setenv("GITHUB_SYNC_TOKEN", TOKEN)
    actual_client = httpx.AsyncClient
    requests, configurations = [], []

    def install(handler):
        requests.clear()
        configurations.clear()
        async def handle(request):
            requests.append(request)
            result = handler(request)
            return await result if asyncio.iscoroutine(result) else result

        def factory(**options):
            configurations.append(options)
            return actual_client(transport=httpx.MockTransport(handle), **options)

        monkeypatch.setattr(github.httpx, "AsyncClient", factory)
        return requests, configurations

    return install


def test_realistic_sources_default_branch_states_fields_and_transport(transport):
    def handle(request):
        data = [code_alert(1, "fixed"), code_alert(2, "dismissed")] if request.url.path == CODE_PATH else [
            dependency_alert(1, "auto_dismissed")]
        return response(data)

    requests, configs = transport(handle)
    alerts = github.fetch_alerts(REPOSITORY, ["code_scanning", "dependabot"])
    assert [alert.state for alert in alerts] == ["fixed", "dismissed", "auto_dismissed"]
    assert alerts[0].severity == "critical" and alerts[0].cvss_score is None
    assert alerts[0].cwe_id == 79 and alerts[0].line_number == 7
    dependency = alerts[2]
    assert dependency.component == "synthetic-package" and dependency.component_version == "< 2.0.0"
    assert dependency.cve_id == "CVE-2099-0001" and dependency.cwe_id == 20 and dependency.cvss_score == 8.2
    assert "2.0.0" in dependency.recommendation
    serialized = json.dumps([asdict(alert) for alert in alerts])
    assert "UNSAFE_SOURCE_SNIPPET" not in serialized and "UNNEEDED_REMOTE_BODY" not in serialized
    assert len(configs) == 1 and configs[0]["trust_env"] is False and configs[0]["follow_redirects"] is False
    assert configs[0]["timeout"] == 10
    assert {request.method for request in requests} == {"GET"}
    assert all(request.url.host == "api.github.com" and request.url.scheme == "https" for request in requests)
    assert all(dict(request.url.params) == {"per_page": "100"} for request in requests)
    assert all(request.headers["Authorization"] == f"Bearer {TOKEN}" for request in requests)
    assert all(request.headers["X-GitHub-Api-Version"] == "2026-03-10" for request in requests)


def test_cursor_and_page_pagination_preserve_fixed_destination(transport):
    def handle(request):
        code = request.url.path == CODE_PATH
        if "page" in request.url.params or "after" in request.url.params:
            return response([code_alert(2) if code else dependency_alert(2)])
        suffix = "page=2" if code else "after=synthetic%2Bcursor%3D%3D"
        link = f'<https://api.github.com{request.url.path}?per_page=100&{suffix}>; rel="next"'
        return response([code_alert() if code else dependency_alert()], headers={"Link": link})

    requests, _ = transport(handle)
    assert len(github.fetch_alerts(REPOSITORY, ["code_scanning", "dependabot"])) == 4
    assert len(requests) == 4
    assert requests[-1].url.params["after"] == "synthetic+cursor=="
    assert "page" not in requests[-1].url.params


@pytest.mark.parametrize("target", [
    "https://attacker.invalid/repos/synthetic-owner/synthetic-repo/dependabot/alerts?after=x",
    "http://api.github.com/repos/synthetic-owner/synthetic-repo/dependabot/alerts?after=x",
    f"https://api.github.com:443{DEPENDABOT_PATH}?after=x",
    f"https://user@api.github.com{DEPENDABOT_PATH}?after=x",
    "https://api.github.com/repos/other/repo/dependabot/alerts?after=x",
    f"https://api.github.com{DEPENDABOT_PATH}?after=x&before=y",
    f"https://api.github.com{DEPENDABOT_PATH}?after=x&after=y",
    f"https://api.github.com{DEPENDABOT_PATH}?page=2",
    f"https://api.github.com{DEPENDABOT_PATH}?after=x&ref=refs/heads/other",
    f"https://api.github.com{DEPENDABOT_PATH}?after=x&per_page=1",
    f"https://api.github.com{DEPENDABOT_PATH}?after=x#fragment",
    f"https://api.github.com{DEPENDABOT_PATH}?after=%ZZ",
    f"https://api.github.com{DEPENDABOT_PATH}?after=%00",
])
def test_unsafe_pagination_fails_without_following_link(transport, target):
    requests, _ = transport(lambda _: response([dependency_alert()], headers={"Link": f'<{target}>; rel="next"'}))
    with pytest.raises(github.GitHubFetchError, match="pagination"):
        github.fetch_alerts(REPOSITORY, ["dependabot"])
    assert len(requests) == 1


def test_redirect_never_forwards_credentials(transport):
    requests, _ = transport(lambda _: response(status=302, headers={"Location": "https://attacker.invalid"}))
    with pytest.raises(github.GitHubFetchError):
        github.fetch_alerts(REPOSITORY, ["dependabot"])
    assert len(requests) == 1


@pytest.mark.parametrize("status,headers,expected", [
    (401, {}, None), (403, {}, None), (404, {}, None),
    (429, {"Retry-After": "15"}, 15), (403, {"Retry-After": "900000"}, 86400),
    (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"}, 1),
    (429, {"Retry-After": "invalid"}, 60),
])
def test_actionable_safe_http_errors_and_bounded_retry(transport, status, headers, expected):
    transport(lambda _: response({"message": TOKEN + " private repository details"}, status=status, headers=headers))
    with pytest.raises(github.GitHubFetchError) as error:
        github.fetch_alerts(REPOSITORY, ["code_scanning"])
    assert error.value.retry_after == expected
    assert error.value.message == str(error.value)
    assert TOKEN not in str(error.value) and "private repository details" not in str(error.value)


def test_failure_in_second_source_returns_no_partial_success(transport):
    requests, _ = transport(lambda request: response([code_alert()]) if request.url.path == CODE_PATH
                            else response(status=503))
    with pytest.raises(github.GitHubFetchError):
        github.fetch_alerts(REPOSITORY, ["code_scanning", "dependabot"])
    assert len(requests) == 2


@pytest.mark.parametrize("data", [{}, [None], [{}], [{"number": True}], [code_alert(), code_alert()]])
def test_malformed_or_duplicate_alerts_fail_whole_fetch(transport, data):
    transport(lambda _: response(data))
    with pytest.raises(github.GitHubFetchError):
        github.fetch_alerts(REPOSITORY, ["code_scanning"])


@pytest.mark.parametrize("body", [b"[", b'[{"number":1,"number":2}]', b"[NaN]", b"\xff"])
def test_invalid_json_and_duplicate_keys_are_rejected(transport, body):
    transport(lambda _: response(raw=body))
    with pytest.raises(github.GitHubFetchError):
        github.fetch_alerts(REPOSITORY, ["dependabot"])


@pytest.mark.parametrize("field,value", [("state", []), ("severity", {}), ("title", "x" * 501),
                                         ("title", "bad\x00text"), ("title", "bad\ud800text"),
                                         ("number", 2**31)])
def test_normalized_fields_are_bounded_and_malformed_types_are_safe(transport, field, value):
    alert = code_alert()
    if field == "state":
        alert["most_recent_instance"]["state"] = value
    elif field == "severity":
        alert["rule"]["security_severity_level"] = value
    elif field == "title":
        alert["rule"]["description"] = value
    else:
        alert["number"] = value
    transport(lambda _: response([alert]))
    with pytest.raises(github.GitHubFetchError, match="malformed"):
        github.fetch_alerts(REPOSITORY, ["code_scanning"])


def test_credential_echo_is_redacted_from_every_normalized_text_field(transport):
    alert = dependency_alert()
    alert["security_advisory"]["summary"] = TOKEN
    alert["dependency"]["package"]["name"] = TOKEN
    alert["dependency"]["manifest_path"] = TOKEN
    alert["security_vulnerability"]["vulnerable_version_range"] = TOKEN
    alert["security_vulnerability"]["first_patched_version"]["identifier"] = TOKEN
    transport(lambda _: response([alert]))
    result = github.fetch_alerts(REPOSITORY, ["dependabot"])
    assert TOKEN not in json.dumps(asdict(result[0]))
    assert result[0].title == "[REDACTED]"


@pytest.mark.parametrize("cve", ["CVE-20-1234", "CVE-2099-12", "not-a-cve", "CVE-2099-1234\n"])
def test_nonempty_cve_must_have_standard_identifier_shape(transport, cve):
    alert = dependency_alert()
    alert["security_advisory"]["cve_id"] = cve
    transport(lambda _: response([alert]))
    with pytest.raises(github.GitHubFetchError, match="malformed"):
        github.fetch_alerts(REPOSITORY, ["dependabot"])


def test_missing_cve_and_legacy_cvss_fields_are_allowed(transport):
    alert = dependency_alert()
    alert["security_advisory"].update(cve_id=None, cvss=None, cvss_severities={"cvss_v4": {"score": 8.1}})
    transport(lambda _: response([alert]))
    result = github.fetch_alerts(REPOSITORY, ["dependabot"])[0]
    assert result.cve_id is None and result.cvss_score is None


def test_decoded_limit_is_shared_across_sources_and_bounds_compression(transport, monkeypatch):
    body = json.dumps([code_alert()]).encode()
    monkeypatch.setattr(github, "MAX_BYTES", len(body) + 1)
    transport(lambda _: response(raw=gzip.compress(body), headers={"Content-Encoding": "gzip"}))
    assert len(github.fetch_alerts(REPOSITORY, ["code_scanning"])) == 1
    with pytest.raises(github.GitHubFetchError, match="size limit"):
        github.fetch_alerts(REPOSITORY, ["code_scanning", "dependabot"])
    transport(lambda _: response(raw=gzip.compress(b"x" * 1_000_000), headers={"Content-Encoding": "gzip"}))
    with pytest.raises(github.GitHubFetchError, match="size limit"):
        github.fetch_alerts(REPOSITORY, ["code_scanning"])


def test_truncated_compressed_response_is_not_accepted(transport):
    body = gzip.compress(b"[]")[:-1]
    transport(lambda _: response(raw=body, headers={"Content-Encoding": "gzip"}))
    with pytest.raises(github.GitHubFetchError, match="incomplete compressed"):
        github.fetch_alerts(REPOSITORY, ["code_scanning"])


def test_deflate_response_and_nonsecurity_rule_severity(transport):
    alert = code_alert()
    alert["rule"]["security_severity_level"] = None
    transport(lambda _: response(raw=zlib.compress(json.dumps([alert]).encode()),
                                headers={"Content-Encoding": "deflate"}))
    assert github.fetch_alerts(REPOSITORY, ["code_scanning"])[0].severity == "medium"


def test_credential_echo_in_pagination_never_becomes_a_request_url(transport):
    requests, _ = transport(lambda _: response([dependency_alert()], headers={
        "Link": f'<https://api.github.com{DEPENDABOT_PATH}?after={TOKEN}>; rel="next"'}))
    with pytest.raises(github.GitHubFetchError) as error:
        github.fetch_alerts(REPOSITORY, ["dependabot"])
    assert len(requests) == 1 and TOKEN not in str(requests[0].url)
    assert TOKEN not in str(error.value)


@pytest.mark.parametrize("credential", ["x" * 31, "x" * 513, "x" * 31 + "\n", "é" * 40])
def test_invalid_credential_configuration_never_reaches_transport(transport, monkeypatch, credential):
    requests, _ = transport(lambda _: response([]))
    monkeypatch.setenv("GITHUB_SYNC_TOKEN", credential)
    with pytest.raises(github.GitHubFetchError, match="GITHUB_SYNC_TOKEN"):
        github.fetch_alerts(REPOSITORY, ["dependabot"])
    assert requests == []


def test_total_alert_and_page_limits_fail_instead_of_truncating(transport, monkeypatch):
    monkeypatch.setattr(github, "MAX_ALERTS", 1)
    transport(lambda _: response([code_alert(1), code_alert(2)]))
    with pytest.raises(github.GitHubFetchError, match="alert limit"):
        github.fetch_alerts(REPOSITORY, ["code_scanning"])
    monkeypatch.setattr(github, "MAX_ALERTS", 5000)
    monkeypatch.setattr(github, "MAX_PAGES", 1)
    requests, _ = transport(lambda _: response([dependency_alert()], headers={
        "Link": f'<https://api.github.com{DEPENDABOT_PATH}?after=next>; rel="next"'}))
    with pytest.raises(github.GitHubFetchError, match="page limit"):
        github.fetch_alerts(REPOSITORY, ["dependabot"])
    assert len(requests) == 1


def test_pagination_loop_and_duplicate_across_pages_fail(transport):
    link = f'<https://api.github.com{DEPENDABOT_PATH}?after=next>; rel="next"'
    requests, _ = transport(lambda _: response([dependency_alert()], headers={"Link": link}))
    with pytest.raises(github.GitHubFetchError, match="duplicate alerts"):
        github.fetch_alerts(REPOSITORY, ["dependabot"])
    assert len(requests) == 2
    requests, _ = transport(lambda request: response([dependency_alert(2 if "after" in request.url.params else 1)],
                                                    headers={"Link": link}))
    with pytest.raises(github.GitHubFetchError, match="pagination loop"):
        github.fetch_alerts(REPOSITORY, ["dependabot"])


def test_total_deadline_cancels_slow_request_and_safe_transport_error(transport, monkeypatch):
    async def slow(_):
        await asyncio.sleep(10)
        return response([])

    transport(slow)
    monkeypatch.setattr(github, "DEADLINE_SECONDS", 0.01)
    with pytest.raises(github.GitHubFetchError, match="timed out"):
        github.fetch_alerts(REPOSITORY, ["dependabot"])

    def broken(_):
        raise httpx.ReadError(TOKEN)

    transport(broken)
    with pytest.raises(github.GitHubFetchError) as error:
        github.fetch_alerts(REPOSITORY, ["dependabot"])
    assert TOKEN not in str(error.value)


@pytest.mark.parametrize("repository", ["https://github.com/owner/repo", "owner/..", "owner/%2e%2e", "owner/repo?x", "owner/repo/next", "owner\\repo"])
def test_repository_validation_precedes_network(transport, repository):
    requests, _ = transport(lambda _: response([]))
    with pytest.raises(github.GitHubFetchError, match="repository"):
        github.fetch_alerts(repository, ["dependabot"])
    assert requests == []


@pytest.mark.parametrize("sources", [[], ["secret_scanning"], ["dependabot", "dependabot"], "dependabot", [{}]])
def test_invalid_source_selection_never_fetches(transport, sources):
    requests, _ = transport(lambda _: response([]))
    with pytest.raises(github.GitHubFetchError, match="sources"):
        github.fetch_alerts(REPOSITORY, sources)
    assert requests == []


def test_missing_credential_and_empty_success_are_distinct(transport, monkeypatch):
    requests, _ = transport(lambda _: response([]))
    monkeypatch.delenv("GITHUB_SYNC_TOKEN")
    with pytest.raises(github.GitHubFetchError, match="GITHUB_SYNC_TOKEN"):
        github.fetch_alerts(REPOSITORY, ["dependabot"])
    assert requests == []
    monkeypatch.setenv("GITHUB_SYNC_TOKEN", TOKEN)
    assert github.fetch_alerts(REPOSITORY, ["code_scanning", "dependabot"]) == []
    assert len(requests) == 2
