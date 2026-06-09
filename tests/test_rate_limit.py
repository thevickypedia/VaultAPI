"""Tests for vaultapi/rate_limit.py — RateLimiter and _get_identifier."""

import time
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from vaultapi.models import RateLimit
from vaultapi.rate_limit import RateLimiter, _get_identifier


def _req(host="127.0.0.1", path="/test", forwarded=None):
    req = MagicMock()
    req.url.hostname = host
    req.url.path = path
    headers = {}
    if forwarded:
        headers["x-forwarded-for"] = forwarded
    req.headers.get = lambda k, d="": headers.get(k, d)
    return req


class TestGetIdentifier:
    def test_uses_url_hostname(self):
        assert _get_identifier(_req()) == "127.0.0.1:/test"

    def test_uses_forwarded_header(self):
        assert _get_identifier(_req(forwarded="10.0.0.1, 10.0.0.2")) == "10.0.0.1:/test"

    def test_path_included(self):
        ident = _get_identifier(_req(path="/api/data"))
        assert "/api/data" in ident


class TestRateLimiter:
    def test_allows_requests_under_limit(self):
        rl = RateLimiter(RateLimit(max_requests=5, seconds=10))
        req = _req()
        for _ in range(5):
            rl.init(req)  # must not raise

    def test_blocks_on_limit_exceeded(self):
        rl = RateLimiter(RateLimit(max_requests=3, seconds=10))
        req = _req()
        for _ in range(3):
            rl.init(req)
        with pytest.raises(HTTPException) as exc:
            rl.init(req)
        assert exc.value.status_code == 429
        assert "Retry-After" in exc.value.headers

    def test_window_expiry_resets_counter(self):
        rl = RateLimiter(RateLimit(max_requests=2, seconds=1))
        req = _req()
        for _ in range(2):
            rl.init(req)
        # Expire the window
        rl.requests[_get_identifier(req)] = [time.time() - 2]
        rl.init(req)  # should not raise — old entries cleaned up

    def test_different_paths_tracked_separately(self):
        rl = RateLimiter(RateLimit(max_requests=2, seconds=10))
        req_a = _req(path="/a")
        req_b = _req(path="/b")
        for _ in range(2):
            rl.init(req_a)
        # /b bucket is fresh — should not be blocked
        rl.init(req_b)

    def test_different_clients_tracked_separately(self):
        rl = RateLimiter(RateLimit(max_requests=2, seconds=10))
        for _ in range(2):
            rl.init(_req(host="1.2.3.4"))
        # Different host — independent bucket
        rl.init(_req(host="5.6.7.8"))
