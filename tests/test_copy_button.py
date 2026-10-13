"""The shared copy-to-clipboard handler (base.html) must work on a plain-HTTP
deployment: `navigator.clipboard` exists only in secure contexts (HTTPS or
localhost), so the handler needs the execCommand fallback and a visible
"press Ctrl+C" outcome when both are refused. Found on the 3.8.0 review build
(the API-token page's *Copy token* did nothing over http://10.0.0.82)."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _handler():
    html = (ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    start = html.index("function copyText(")
    return html[start:start + 3000]


def test_clipboard_api_is_gated_on_secure_context():
    handler = _handler()
    assert "navigator.clipboard && window.isSecureContext" in handler
    assert "document.execCommand('copy')" in handler


def test_fallback_selects_text_and_tells_the_user():
    handler = _handler()
    assert "selectNodeContents(el)" in handler
    assert "press Ctrl+C" in handler
    # the silent early return that swallowed the click on HTTP is gone
    assert "!navigator.clipboard) return" not in handler


def test_copy_buttons_still_rendered(auth_admin, admin_user):
    r = auth_admin.post("/users/api-tokens", data={"name": "copy-check", "expires_in_days": "5", "scope_read": "on"})
    assert r.status_code == 200
    assert re.search(rb'data-copy-target="#new-token"', r.data)
    assert b"function copyText(" in r.data
