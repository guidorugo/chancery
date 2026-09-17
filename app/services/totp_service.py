"""TOTP second factor (F13, 2.27.0) — RFC 6238 on RFC 4226, stdlib only.

- `generate_secret()` → base32 secret (160 bits) for the authenticator app;
  stored Fernet-wrapped under MASTER_PASSPHRASE (`users.totp_secret_enc`,
  registered in passphrase_service).
- `verify(secret, code, last_step)` accepts the current 30-second step and one
  step either side (clock drift), and never a step at or before the last one
  accepted for that user (`users.totp_last_step`) — a captured code cannot be
  replayed inside its window.
- Recovery codes: eight 10-character codes shown once, stored as werkzeug
  hashes, each usable once.
- The enrolment page shows an inline SVG QR (segno) of the otpauth URL plus
  the secret for manual entry.
"""
import base64
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from werkzeug.security import check_password_hash, generate_password_hash

STEP_SECONDS = 30
DIGITS = 6
WINDOW = 1                 # steps either side of "now"
RECOVERY_CODES = 8
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I


def generate_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_b32):
    padded = secret_b32.strip().replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    return base64.b32decode(padded, casefold=True)


def hotp(secret_b32, counter, digits=DIGITS):
    """RFC 4226 HOTP-SHA1 for a counter value."""
    digest = hmac.new(_key(secret_b32), struct.pack(">Q", counter), "sha1").digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def current_step(now=None):
    return int((now if now is not None else time.time()) // STEP_SECONDS)


def totp(secret_b32, now=None, digits=DIGITS):
    return hotp(secret_b32, current_step(now), digits)


def verify(secret_b32, code, last_step=None, now=None, window=WINDOW):
    """The step the code matched, or None. Codes for steps at or before
    `last_step` are refused (replay)."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != DIGITS:
        return None
    step = current_step(now)
    for candidate in range(step - window, step + window + 1):
        if last_step is not None and candidate <= last_step:
            continue
        if hmac.compare_digest(hotp(secret_b32, candidate), code):
            return candidate
    return None


def otpauth_url(issuer, username, secret_b32):
    label = quote(f"{issuer}:{username}", safe="")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}")


def qr_svg(url):
    """Inline SVG for the enrolment page (segno is a pure-Python dependency);
    None if it is unavailable — the page then shows the URL and secret only."""
    try:
        import io
        import segno
        buf = io.BytesIO()
        segno.make(url, error="m").save(buf, kind="svg", scale=4, border=2, xmldecl=False, svgclass=None, lineclass=None)
        return buf.getvalue().decode()
    except Exception:
        return None


def generate_recovery_codes(n=RECOVERY_CODES):
    """(plaintext codes, werkzeug hashes). Codes look like ABCDE-FGHJK."""
    codes = []
    for _ in range(n):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, [generate_password_hash(c) for c in codes]


def normalise_recovery_code(code):
    raw = (code or "").strip().upper().replace("-", "").replace(" ", "")
    return f"{raw[:5]}-{raw[5:]}" if len(raw) == 10 else None


def consume_recovery_code(hashes, code):
    """(remaining hashes, True) when `code` matched one of `hashes` (which is
    then removed), else (hashes, False)."""
    normalised = normalise_recovery_code(code)
    if normalised is None:
        return hashes, False
    for i, h in enumerate(hashes or []):
        if check_password_hash(h, normalised):
            return hashes[:i] + hashes[i + 1:], True
    return hashes, False


# --- enforcement (2.28.0) ----------------------------------------------------
ENFORCEMENT_MODES = ("off", "admins", "all")


def enforcement_mode(config):
    """`REQUIRE_2FA`: off (default), admins, all. The 2.27 boolean
    `REQUIRE_2FA_FOR_ADMINS=true` still means `admins`."""
    mode = (config.get("REQUIRE_2FA") or "off").lower()
    if mode == "off" and config.get("REQUIRE_2FA_FOR_ADMINS"):
        mode = "admins"
    return mode


def enforced_for(user, config):
    """True when `user` must have a second factor enrolled to use the app."""
    mode = enforcement_mode(config)
    if mode == "all":
        return True
    if mode == "admins":
        return bool(getattr(user, "is_admin", False))
    return False
