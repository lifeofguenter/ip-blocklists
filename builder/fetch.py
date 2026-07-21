"""HTTP retrieval of upstream feeds, with retries and a hard failure mode."""

import time

import requests

USER_AGENT = "ip-blocklists (automated blocklist aggregator)"
DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
MAX_BACKOFF = 30


class FetchError(Exception):
    """A feed could not be retrieved. Always fatal to the build."""


def fetch(
    url,
    *,
    timeout=DEFAULT_TIMEOUT,
    retries=DEFAULT_RETRIES,
    session=None,
    sleep=time.sleep,
):
    """Return the body of ``url`` as text, retrying transient failures.

    Raises :class:`FetchError` once ``retries`` attempts are exhausted. A
    permanent status (e.g. 404) fails immediately: retrying will not help and
    the build should surface it straight away.
    """
    http = session if session is not None else requests.Session()
    attempts = max(retries, 1)
    last_error = None

    for attempt in range(1, attempts + 1):
        try:
            response = http.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            if response.status_code in RETRY_STATUSES:
                raise FetchError(f"HTTP {response.status_code}")
            response.raise_for_status()
            return response.text
        except (requests.RequestException, FetchError) as error:
            last_error = error
            if not _is_retryable(error) or attempt == attempts:
                break
            sleep(min(2**attempt, MAX_BACKOFF))

    raise FetchError(f"could not fetch {url} after {attempt} attempt(s): {last_error}")


def _is_retryable(error):
    """Transient transport errors and 5xx/429 are worth another attempt."""
    if isinstance(error, FetchError):
        return True
    response = getattr(error, "response", None)
    if response is None:
        return True  # connection reset, timeout, DNS failure, ...
    return response.status_code in RETRY_STATUSES
