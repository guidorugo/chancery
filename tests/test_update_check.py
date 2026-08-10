"""Opt-in "update available" footer check (app/services/update_service.py)."""

import time

import pytest

from app import create_app
from app._version import __version__
from app.services import update_service

from tests.conftest import TestConfig


class _EnabledConfig(TestConfig):
    UPDATE_CHECK_ENABLED = True
    UPDATE_CHECK_INTERVAL_SECONDS = 3600
    UPDATE_CHECK_TIMEOUT_SECONDS = 1


@pytest.fixture(autouse=True)
def _clean_cache():
    update_service._reset_cache_for_tests()
    yield
    update_service._reset_cache_for_tests()


def _seed(latest):
    """Seed a *fresh* cache so check() reads it without spawning a refresh
    thread (keeps tests offline and deterministic)."""
    with update_service._LOCK:
        update_service._STATE.update(
            latest=latest, checked_at=time.time(), refreshing=False
        )


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("v2.2.0", (2, 2, 0)),
        ("2.2.0", (2, 2, 0)),
        ("v2.10.3", (2, 10, 3)),
        ("2.2.0-rc1", (2, 2, 0)),
        ("2.2.0+build.5", (2, 2, 0)),
        ("", None),
        (None, None),
        ("nightly", None),
    ],
)
def test_parse_version(raw, expected):
    assert update_service._parse_version(raw) == expected


def test_disabled_returns_no_update_even_if_newer_cached():
    _seed("v99.0.0")
    assert update_service.check({"UPDATE_CHECK_ENABLED": False}) == (False, None)


def test_enabled_newer_available():
    _seed("v99.0.0")
    available, latest = update_service.check(
        {"UPDATE_CHECK_ENABLED": True, "UPDATE_CHECK_INTERVAL_SECONDS": 3600}
    )
    assert available is True
    assert latest == "v99.0.0"


def test_enabled_up_to_date():
    _seed(f"v{__version__}")
    assert update_service.check(
        {"UPDATE_CHECK_ENABLED": True, "UPDATE_CHECK_INTERVAL_SECONDS": 3600}
    ) == (False, None)


def test_enabled_empty_cache_no_badge_no_network():
    # Fresh timestamp but nothing fetched yet → no badge, and no refresh thread.
    _seed(None)
    assert update_service.check(
        {"UPDATE_CHECK_ENABLED": True, "UPDATE_CHECK_INTERVAL_SECONDS": 3600}
    ) == (False, None)


def test_refresh_success_updates_cache(monkeypatch):
    monkeypatch.setattr(update_service, "_fetch_latest_tag", lambda repo, timeout: "v9.9.9")
    update_service._refresh("owner/repo", 1)
    assert update_service._STATE["latest"] == "v9.9.9"
    assert update_service._STATE["refreshing"] is False


def test_refresh_failure_is_swallowed(monkeypatch):
    def boom(repo, timeout):
        raise OSError("network unreachable")

    monkeypatch.setattr(update_service, "_fetch_latest_tag", boom)
    update_service._refresh("owner/repo", 1)  # must not raise
    assert update_service._STATE["latest"] is None
    assert update_service._STATE["refreshing"] is False


def test_footer_badge_shown_when_update_available():
    _seed("v99.0.0")
    resp = create_app(_EnabledConfig).test_client().get("/auth/login")
    assert resp.status_code == 200
    assert b"Update available" in resp.data
    assert b"v99.0.0" in resp.data


def test_footer_no_badge_when_up_to_date():
    _seed(f"v{__version__}")
    resp = create_app(_EnabledConfig).test_client().get("/auth/login")
    assert resp.status_code == 200
    assert b"Update available" not in resp.data


def test_footer_no_badge_when_check_disabled():
    _seed("v99.0.0")
    # TestConfig pins UPDATE_CHECK_ENABLED=False (the ship default is now True).
    resp = create_app(TestConfig).test_client().get("/auth/login")
    assert resp.status_code == 200
    assert b"Update available" not in resp.data


def test_update_check_on_by_default():
    """The shipped Config default enables the check (unless the env overrides)."""
    import os
    from app.config import Config
    if "UPDATE_CHECK_ENABLED" not in os.environ:
        assert Config.UPDATE_CHECK_ENABLED is True
