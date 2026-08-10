"""TMPL-1: CSP script-src uses a per-request nonce (no 'unsafe-inline'); the
rendered pages carry the matching nonce and no inline on* handlers.

NOTE: pytest can't execute the page JavaScript, so this verifies the CSP
plumbing (nonce present, matches, per-request, handlers removed). The form
interactions themselves still warrant a manual browser smoke-test.
"""

import re


def _script_src(resp):
    csp = resp.headers["Content-Security-Policy"]
    return next(d for d in csp.split(";") if d.strip().startswith("script-src"))


def _nonce(resp):
    m = re.search(r"'nonce-([^']+)'", resp.headers["Content-Security-Policy"])
    return m.group(1) if m else None


def test_script_src_uses_nonce_not_unsafe_inline(auth_admin):
    src = _script_src(auth_admin.get("/"))
    assert "'nonce-" in src
    assert "'unsafe-inline'" not in src


def test_page_nonce_matches_csp_header(auth_admin):
    r = auth_admin.get("/certificates/create")
    nonce = _nonce(r)
    assert nonce
    # the inline scripts carry the same nonce -> they will execute under CSP
    assert f'<script nonce="{nonce}">'.encode() in r.data


def test_nonce_is_fresh_per_request(auth_admin):
    assert _nonce(auth_admin.get("/")) != _nonce(auth_admin.get("/"))


def test_create_pages_have_no_inline_event_handlers(auth_admin):
    for path in ("/certificates/create", "/ca/create", "/csr/create"):
        data = auth_admin.get(path).data
        assert b"onchange=" not in data
        assert b"onclick=" not in data
