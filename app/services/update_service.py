"""Best-effort "is a newer release available?" check against GitHub Releases.

Design goals for a security-sensitive CA server:

* **Opt-in** — does nothing unless ``UPDATE_CHECK_ENABLED`` is true, so a
  hardened / air-gapped deployment never makes an outbound call.
* **Server-side + cached** — the GitHub API is queried at most once per
  interval (per worker), not per request, and never from the client's browser
  (no CSP relaxation needed).
* **Non-blocking** — a stale cache triggers a background refresh; the request
  always returns the currently-cached answer immediately.
* **Never breaks a page** — any network / parse error is swallowed and simply
  yields "no update info".
"""

import json
import threading
import time
import urllib.request
from urllib.error import URLError

from .._version import __version__

# Module-level cache, shared across requests in a worker process. Each gunicorn
# worker keeps its own copy; with the default 6h interval that is a negligible
# number of GitHub calls.
_LOCK = threading.Lock()
_STATE = {"latest": None, "checked_at": 0.0, "refreshing": False}

_DEFAULT_REPO = "guidorugo/cert-manager"


def _parse_version(value):
    """Parse ``v2.2.0`` / ``2.2.0`` into a comparable tuple, else None.

    Pre-release / build suffixes (``2.2.0-rc1``, ``2.2.0+meta``) are dropped so a
    stable release compares cleanly; anything non-numeric yields None (which
    disables the comparison rather than guessing).
    """
    if not value:
        return None
    core = value.strip().lstrip("vV").split("-")[0].split("+")[0]
    parts = core.split(".")
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, TypeError):
        return None


def _fetch_latest_tag(repo, timeout):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "cert-manager-update-check",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 (https)
        data = json.load(resp)
    # CORE-4: a non-object body (array/string) would make `.get` raise; guard it.
    return data.get("tag_name") if isinstance(data, dict) else None


def _refresh(repo, timeout):
    """Fetch the latest tag and update the cache. Runs in a background thread."""
    latest = None
    try:
        latest = _fetch_latest_tag(repo, timeout)
    except Exception:
        # CORE-4: swallow ANY error and always fall through to the finally —
        # the refresh must never leave `refreshing` stuck True, or this worker
        # would stop checking for updates for the rest of its lifetime.
        latest = None
    finally:
        with _LOCK:
            if latest:
                _STATE["latest"] = latest
            _STATE["checked_at"] = time.time()
            _STATE["refreshing"] = False


def check(config):
    """Return ``(update_available: bool, latest_version: str | None)``.

    Never raises. Reads the cached latest release, kicking off a non-blocking
    background refresh when the cache is older than the configured interval.
    """
    if not config.get("UPDATE_CHECK_ENABLED"):
        return (False, None)

    repo = config.get("UPDATE_CHECK_REPO") or _DEFAULT_REPO
    interval = config.get("UPDATE_CHECK_INTERVAL_SECONDS", 21600)
    timeout = config.get("UPDATE_CHECK_TIMEOUT_SECONDS", 4)

    now = time.time()
    with _LOCK:
        latest = _STATE["latest"]
        stale = (now - _STATE["checked_at"]) >= interval
        if stale and not _STATE["refreshing"]:
            _STATE["refreshing"] = True
            threading.Thread(
                target=_refresh, args=(repo, timeout), daemon=True
            ).start()

    current = _parse_version(__version__)
    newest = _parse_version(latest)
    available = bool(current and newest and newest > current)
    return (available, latest if available else None)


def _reset_cache_for_tests():
    """Test helper: clear the module cache so tests are order-independent."""
    with _LOCK:
        _STATE.update(latest=None, checked_at=0.0, refreshing=False)
