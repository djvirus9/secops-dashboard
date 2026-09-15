"""Jira REST contracts use synthetic responses only; no live Jira requests."""
import json

import httpx
import pytest

from app.jira_sync import client as jira

TOKEN = "synthetic-jira-token-never-a-real-credential"


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://synthetic.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "synthetic@example.invalid")
    monkeypatch.setenv("JIRA_API_TOKEN", TOKEN)


class Chunks(httpx.SyncByteStream):
    def __init__(self, value):
        self.value = value

    def __iter__(self):
        for offset in range(0, len(self.value), 100):
            yield self.value[offset:offset + 100]


def response(data=None, status=200, headers=None):
    return httpx.Response(status, headers=headers or {}, stream=Chunks(json.dumps(data).encode()))


def issue(category="new", assignee=None):
    return {"key": "SEC-1", "fields": {
        "status": {"id": "100", "name": "To Do", "statusCategory": {"key": category}},
        "assignee": assignee, "updated": "2026-09-16T10:00:00.000+0000",
    }}


@pytest.fixture
def transport(monkeypatch):
    actual = httpx.Client
    requests, options = [], []

    def install(handler):
        def handle(request):
            requests.append(request)
            return handler(request)

        def factory(**kwargs):
            options.append(kwargs)
            return actual(transport=httpx.MockTransport(handle), **kwargs)
        monkeypatch.setattr(jira.httpx, "Client", factory)
        return requests, options
    return install


def test_minimum_fields_fixed_tenant_and_safe_transport(transport):
    calls, options = transport(lambda _: response(issue(assignee={"accountId": "123:abc", "displayName": "Analyst"})))
    result = jira.JiraClient().issue("SEC-1")
    assert result == {"status_id": "100", "status": "To Do", "category": "new",
                      "assignee_id": "123:abc", "assignee": "Analyst", "updated_at": "2026-09-16T10:00:00.000+0000"}
    assert len(calls) == 1
    assert calls[0].url.host == "synthetic.atlassian.net"
    assert calls[0].url.path == "/rest/api/3/issue/SEC-1"
    assert dict(calls[0].url.params) == {"fields": "status,assignee,updated"}
    assert options[0]["follow_redirects"] is False and options[0]["trust_env"] is False
    assert "Basic " in calls[0].headers["authorization"]


@pytest.mark.parametrize("value", [
    "http://synthetic.atlassian.net", "https://example.invalid", "https://127.0.0.1",
    "https://synthetic.atlassian.net.evil.invalid", "https://user:secret@synthetic.atlassian.net",
    "https://synthetic.atlassian.net:443", "https://synthetic.atlassian.net/path",
    "https://synthetic.atlassian.net?token=secret", "https://synthetic.atlassian.net#fragment",
    "https://synthetic.atlassian.net//", "https://synthetic.atlassian.net%2f.evil.invalid",
])
def test_invalid_base_rejected_before_network(monkeypatch, value):
    monkeypatch.setenv("JIRA_BASE_URL", value)
    assert not jira.configured()
    with pytest.raises(jira.JiraError):
        jira.JiraClient()


@pytest.mark.parametrize("key", ["../../other", "SEC-1?x=1", "SEC-1/path", "https://other.invalid", "SEC-0", "SEC-1#x"])
def test_invalid_issue_key_never_requested(transport, key):
    calls, _ = transport(lambda _: response(issue()))
    with pytest.raises(jira.JiraError):
        jira.JiraClient().issue(key)
    assert calls == []


def test_redirect_does_not_forward_credentials(transport):
    calls, _ = transport(lambda _: response({}, 302, {"Location": "https://example.invalid/secret"}))
    with pytest.raises(jira.JiraError):
        jira.JiraClient().issue("SEC-1")
    assert len(calls) == 1


@pytest.mark.parametrize("status,retry,uncertain", [(401, None, False), (404, None, False),
                                                    (429, 120, False), (503, None, True)])
def test_write_safe_errors_rate_limit_and_uncertain_outcome(transport, status, retry, uncertain):
    transport(lambda _: response({"error": TOKEN}, status, {"Retry-After": "120"}))
    with pytest.raises(jira.JiraError) as error:
        jira.JiraClient().assign("SEC-1", "abc:123")
    assert error.value.retry_after == retry and error.value.uncertain is uncertain
    assert TOKEN not in str(error.value)


def test_bounded_body_and_compression_rejected(transport):
    transport(lambda _: response({"payload": "x" * jira.MAX_BYTES}))
    with pytest.raises(jira.JiraError, match="safe limits"):
        jira.JiraClient().issue("SEC-1")


@pytest.mark.parametrize("data", [{}, {"key": "OTHER-1", "fields": {}}, issue("unexpected"),
                                   issue(assignee={"accountId": "../../other"})])
def test_malformed_issue_rejected(transport, data):
    transport(lambda _: response(data))
    with pytest.raises(jira.JiraError):
        jira.JiraClient().issue("SEC-1")


def test_transition_requires_one_matching_workflow_and_sends_only_id(transport):
    transition = {"id": "31", "to": {"statusCategory": {"key": "done"}}}
    calls, _ = transport(lambda request: response({"transitions": [transition]})
                         if request.method == "GET" else response({}, 204))
    jira.JiraClient().transition("SEC-1", "done")
    assert [item.method for item in calls] == ["GET", "POST"]
    assert json.loads(calls[1].content) == {"transition": {"id": "31"}}


@pytest.mark.parametrize("count", [0, 2])
def test_ambiguous_transition_is_not_guessed(transport, count):
    calls, _ = transport(lambda _: response({"transitions": [
        {"id": str(index), "to": {"statusCategory": {"key": "done"}}} for index in range(count)]}))
    with pytest.raises(jira.JiraError, match="unique"):
        jira.JiraClient().transition("SEC-1", "done")
    assert len(calls) == 1 and calls[0].method == "GET"


def test_assignee_put_uses_account_id_not_username(transport):
    calls, _ = transport(lambda _: response({}, 204))
    jira.JiraClient().assign("SEC-1", "abc:123")
    jira.JiraClient().assign("SEC-1", None)
    assert [json.loads(item.content) for item in calls] == [{"accountId": "abc:123"}, {"accountId": None}]


def test_retry_after_is_bounded():
    assert jira._retry_after("900000") == 86400
    assert jira._retry_after("-10") == 1
    assert jira._retry_after("nonsense") == 60
