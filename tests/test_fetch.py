"""HTTP retry/failure tests against a fake session."""

import pytest
import requests

from blocklists.fetch import USER_AGENT, FetchError, fetch


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class FakeSession:
    """Returns queued responses (or raises queued exceptions) in order."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def get(self, url, timeout=None, headers=None):
        self.calls.append({"url": url, "timeout": timeout, "headers": headers})
        outcome = self.outcomes.pop(0) if self.outcomes else FakeResponse(200, "")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def no_sleep(_seconds):
    return None


class TestSuccess:
    def test_returns_body(self):
        session = FakeSession(FakeResponse(200, "1.2.3.4\n"))
        assert fetch("https://example.test/list", session=session) == "1.2.3.4\n"

    def test_sends_user_agent_and_timeout(self):
        session = FakeSession(FakeResponse(200, "ok"))
        fetch("https://example.test/list", session=session, timeout=17)
        assert session.calls[0]["headers"]["User-Agent"] == USER_AGENT
        assert session.calls[0]["timeout"] == 17


class TestRetries:
    def test_recovers_after_a_transient_503(self):
        session = FakeSession(FakeResponse(503), FakeResponse(200, "1.2.3.4\n"))
        result = fetch("https://example.test/list", session=session, sleep=no_sleep)
        assert result == "1.2.3.4\n"
        assert len(session.calls) == 2

    def test_recovers_after_a_connection_error(self):
        session = FakeSession(
            requests.ConnectionError("reset"), FakeResponse(200, "1.2.3.4\n")
        )
        result = fetch("https://example.test/list", session=session, sleep=no_sleep)
        assert result == "1.2.3.4\n"

    def test_gives_up_after_exhausting_retries(self):
        session = FakeSession(FakeResponse(503), FakeResponse(503), FakeResponse(503))
        with pytest.raises(FetchError, match="after 3 attempt"):
            fetch("https://example.test/list", session=session, retries=3, sleep=no_sleep)
        assert len(session.calls) == 3

    def test_backs_off_between_attempts(self):
        delays = []
        session = FakeSession(FakeResponse(503), FakeResponse(200, "ok"))
        fetch("https://example.test/list", session=session, sleep=delays.append)
        assert delays == [2]


class TestPermanentFailures:
    def test_404_fails_immediately_without_retrying(self):
        session = FakeSession(FakeResponse(404), FakeResponse(200, "ok"))
        with pytest.raises(FetchError):
            fetch("https://example.test/gone", session=session, sleep=no_sleep)
        assert len(session.calls) == 1

    def test_error_message_includes_the_url(self):
        session = FakeSession(FakeResponse(404))
        with pytest.raises(FetchError, match="example.test/gone"):
            fetch("https://example.test/gone", session=session, sleep=no_sleep)
