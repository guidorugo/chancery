"""Master-passphrase rotation (F18, assessment G13-2).

Every secret at rest is wrapped under `MASTER_PASSPHRASE` with the same
salt + PBKDF2-600k + Fernet format (`crypto_utils`). Rotating the passphrase
means re-wrapping every such ciphertext, which needs a registry of where
they live — `ENCRYPTED_COLUMNS`. A feature that adds a new `*_enc` column
must register it here; `tests/test_passphrase_rotation.py` fails otherwise.

`rotate()` verifies the current passphrase against one blob per column
before touching anything, re-wraps every blob with a fresh salt, verifies
each new blob decrypts, and leaves the session flushed but uncommitted so
the caller (the CLI) can commit together with its audit row — or roll back
for a dry run. HSM-backed and certificate-only CAs hold the empty-bytes
sentinel and are skipped; NULL columns are skipped.
"""
import importlib

from cryptography.fernet import InvalidToken

from ..extensions import db
from . import crypto_utils

# (module, class, column, kind) — kind is documentation only; both kinds
# share the wrapping format.
ENCRYPTED_COLUMNS = (
    ("app.models.ca", "CertificateAuthority", "private_key_enc", "CA private key"),
    ("app.models.ca", "CertificateAuthority", "ocsp_responder_key_enc", "OCSP responder private key"),
    ("app.models.certificate", "Certificate", "private_key_enc", "escrowed leaf private key"),
    ("app.models.ldap_settings", "LdapSettings", "bind_password_enc", "LDAP bind password"),
    ("app.models.webhook_settings", "WebhookSettings", "secret_enc", "webhook signing secret"),
    ("app.models.user", "User", "totp_secret_enc", "TOTP secret"),
)

MIN_NEW_PASSPHRASE_LEN = 12


class PassphraseError(ValueError):
    """Wrong current passphrase or an unusable new one — nothing was written."""


def registered():
    """Yield (model_class, column_attr, column_name, kind) for the registry."""
    for module_name, class_name, column, kind in ENCRYPTED_COLUMNS:
        model = getattr(importlib.import_module(module_name), class_name)
        yield model, getattr(model, column), column, kind


def _rows_with_ciphertext(model, column_attr):
    return model.query.filter(column_attr.isnot(None), column_attr != b"").order_by(model.id).all()


def check(passphrase):
    """Try to decrypt one blob per registered column with `passphrase`.

    Returns a list of dicts: {table, column, kind, rows, ok} — `ok` is None
    when the column holds no ciphertext at all.
    """
    report = []
    for model, column_attr, column, kind in registered():
        rows = _rows_with_ciphertext(model, column_attr)
        ok = None
        if rows:
            ok = crypto_utils.can_decrypt(getattr(rows[0], column), passphrase)
        report.append({"table": model.__tablename__, "column": column, "kind": kind,
                       "rows": len(rows), "ok": ok})
    return report


def validate_new_passphrase(new, current):
    text = (new or "").strip()
    if not text:
        raise PassphraseError("The new passphrase is empty.")
    if len(text) < MIN_NEW_PASSPHRASE_LEN:
        raise PassphraseError(f"The new passphrase must be at least {MIN_NEW_PASSPHRASE_LEN} characters "
                              "(scripts/init-secrets.sh generates 32).")
    if text == "dev-passphrase":
        raise PassphraseError("The new passphrase is the insecure development default.")
    if text == current:
        raise PassphraseError("The new passphrase is identical to the current one.")
    return text


def rotate(current, new):
    """Re-wrap every registered ciphertext from `current` to `new`.

    Flushes, does NOT commit: the caller commits (with its audit row) or
    rolls back. Raises PassphraseError before any write if `current` fails
    to decrypt a column; any later failure rolls the session back and
    re-raises, so the database is never left half-rotated.
    Returns {table.column: rows re-wrapped}.
    """
    # 1. Cheap gate: the current passphrase must open one blob per column
    #    that has any. Catches a wrong MASTER_PASSPHRASE before the long loop.
    for model, column_attr, column, kind in registered():
        rows = _rows_with_ciphertext(model, column_attr)
        if rows and not crypto_utils.can_decrypt(getattr(rows[0], column), current):
            raise PassphraseError(
                f"The current passphrase does not decrypt {model.__tablename__}.{column} "
                "— refusing to rotate (is MASTER_PASSPHRASE the one the database was written with?).")

    # 2. Re-wrap everything in one transaction; verify each new blob.
    stats = {}
    try:
        for model, column_attr, column, kind in registered():
            count = 0
            for row in _rows_with_ciphertext(model, column_attr):
                old_blob = getattr(row, column)
                new_blob = crypto_utils.rewrap(old_blob, current, new)
                if crypto_utils.decrypt_payload(new_blob, new) != crypto_utils.decrypt_payload(old_blob, current):
                    raise RuntimeError(f"Verification of the re-wrapped {model.__tablename__}.{column} "
                                       f"row {row.id} failed.")
                setattr(row, column, new_blob)
                count += 1
            stats[f"{model.__tablename__}.{column}"] = count
        db.session.flush()
    except InvalidToken as exc:
        db.session.rollback()
        raise PassphraseError("A ciphertext could not be decrypted with the current passphrase; "
                              "nothing was changed.") from exc
    except Exception:
        db.session.rollback()
        raise
    return stats
