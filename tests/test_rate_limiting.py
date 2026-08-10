"""DoS-1: per-IP rate limiting (Flask-Limiter), on by default. It runs BEFORE
the Basic-Auth hook, so an unauthenticated flood is bounded before the
expensive password-hash / audit write; /health stays exempt."""

import base64

import pytest

from app import create_app
from tests.conftest import TestConfig


class _RLConfig(TestConfig):
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_DEFAULT = "3/minute"


@pytest.fixture
def rl_client():
    return create_app(_RLConfig).test_client()


def test_rate_limit_trips_after_threshold(rl_client):
    codes = [rl_client.get("/public/ca/1.crt").status_code for _ in range(6)]
    assert 429 in codes
    assert codes.count(429) >= 3          # first 3 allowed, the rest limited


def test_health_is_exempt_from_rate_limit(rl_client):
    codes = [rl_client.get("/health").status_code for _ in range(10)]
    assert all(c == 200 for c in codes)   # monitoring is never throttled


def test_basic_auth_flood_is_bounded(rl_client):
    # The limiter runs before check_basic_auth, so a flood of bad Basic-Auth
    # credentials is cut off with 429 rather than an unbounded stream of KDF +
    # audit writes.
    hdr = {"Authorization": "Basic " + base64.b64encode(b"ghost:nope").decode()}
    codes = [rl_client.get("/ca/", headers=hdr).status_code for _ in range(6)]
    assert 429 in codes


def test_rate_limiting_off_in_default_testconfig(app):
    # The shared suite app pins it off, so app.limiter is None (no throttling).
    assert getattr(app, "limiter", None) is None
