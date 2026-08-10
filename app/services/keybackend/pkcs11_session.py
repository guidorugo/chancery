"""Process-wide PKCS#11 session management for the SoftHSM backend (A1).

PKCS#11 initialises the underlying library once per process (C_Initialize) and
its sessions are not reliably thread-safe. We therefore keep a single logged-in
session per process and serialise every token operation through a lock. gunicorn
runs several worker processes; each gets its own session, which is fine.

This module is only imported when `KEY_BACKEND=softhsm` (or a CA is HSM-backed),
so `import pkcs11` never runs in the default software deployment.
"""
import threading
from contextlib import contextmanager

from flask import current_app

_lib = None
_lib_path = None
_lib_lock = threading.Lock()

_session = None
_session_lock = threading.RLock()


def _get_lib():
    global _lib, _lib_path
    import pkcs11
    path = current_app.config["PKCS11_MODULE"]
    with _lib_lock:
        if _lib is None:
            _lib = pkcs11.lib(path)
            _lib_path = path
        elif _lib_path != path:
            # C_Initialize is per-process; SoftHSM also reads SOFTHSM2_CONF once.
            raise RuntimeError(
                f"PKCS#11 library already initialised with {_lib_path!r}; "
                f"cannot switch to {path!r} in the same process."
            )
        return _lib


def _open_session():
    label = current_app.config["PKCS11_TOKEN_LABEL"]
    pin = current_app.config.get("PKCS11_USER_PIN")
    token = _get_lib().get_token(token_label=label)
    return token.open(rw=True, user_pin=pin)


@contextmanager
def session_scope():
    """Yield the process's logged-in session, serialised by a lock.

    The lock is held for the whole operation because PKCS#11 sessions are not
    thread-safe; at homelab / small-company scale, serialising CA signing is an
    acceptable trade for correctness.
    """
    global _session
    with _session_lock:
        if _session is None:
            _session = _open_session()
        try:
            yield _session
        except Exception:
            # HSM-3: a token/session error (e.g. CKR_SESSION_HANDLE_INVALID after
            # the token was re-initialised or the store replaced) leaves the
            # cached handle dead. Drop it so the next call re-opens a fresh
            # session instead of failing for the rest of the worker's lifetime.
            try:
                _session.close()
            except Exception:
                pass
            _session = None
            raise


def reset():
    """Drop the cached library/session. Tests only."""
    global _lib, _lib_path, _session
    with _session_lock:
        if _session is not None:
            try:
                _session.close()
            except Exception:
                pass
        _session = None
    with _lib_lock:
        _lib = None
        _lib_path = None
