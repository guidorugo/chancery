"""Dedicated /metrics bearer tokens: hashed-at-rest secret, expiry/revocation,
audit, throttled last-used, and the `flask metrics-token` CLI."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.metrics_token import MetricsToken
from app.services import metrics_token_service


def _exp(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(tzinfo=None)


def test_create_returns_plaintext_and_stores_only_hash(app, db):
    with app.app_context():
        pt, row = metrics_token_service.create("t1", _exp(30))
        assert pt.startswith("cmt_")
        secret = pt.split("_", 2)[2]
        # The secret is never persisted — only its SHA-256.
        assert row.token_hash == MetricsToken.hash_secret(secret)
        assert row.token_hash != secret
        assert len(row.token_hash) == 64
        # Serialisation never leaks the hash or the secret.
        d = row.to_dict()
        assert "token_hash" not in d
        assert secret not in str(d)


def test_verify_accepts_valid_rejects_tampered(app, db):
    with app.app_context():
        pt, _ = metrics_token_service.create("t2", _exp(30))
        assert metrics_token_service.verify(pt) is not None
        flipped = pt[:-1] + ("0" if pt[-1] != "0" else "1")
        assert metrics_token_service.verify(flipped) is None
        assert metrics_token_service.verify("garbage") is None
        assert metrics_token_service.verify("cmt_deadbeefdeadbeef_" + "0" * 64) is None


def test_verify_rejects_expired_and_revoked(app, db):
    with app.app_context():
        pt_exp, _ = metrics_token_service.create("exp", _exp(-1))
        assert metrics_token_service.verify(pt_exp) is None
        pt_rev, row = metrics_token_service.create("rev", _exp(30))
        metrics_token_service.revoke(row.id)
        assert metrics_token_service.verify(pt_rev) is None


def test_duplicate_name_rejected(app, db):
    with app.app_context():
        metrics_token_service.create("dup", _exp(30))
        with pytest.raises(ValueError):
            metrics_token_service.create("dup", _exp(30))


def test_missing_name_or_expiry_rejected(app, db):
    with app.app_context():
        with pytest.raises(ValueError):
            metrics_token_service.create("", _exp(30))
        with pytest.raises(ValueError):
            metrics_token_service.create("noexp", None)


def test_create_and_revoke_are_audited(app, db):
    from app.models.audit_log import AuditLog
    with app.app_context():
        _, row = metrics_token_service.create("aud", _exp(30))
        metrics_token_service.revoke(row.id)
        actions = {a.action for a in AuditLog.query.all()}
        assert "metrics_token_created" in actions
        assert "metrics_token_revoked" in actions


def test_touch_is_throttled(app, db):
    with app.app_context():
        _, row = metrics_token_service.create("touch", _exp(30))
        assert row.last_used_at is None
        metrics_token_service.touch(row)
        first = row.last_used_at
        assert first is not None
        metrics_token_service.touch(row)      # within the throttle window
        assert row.last_used_at == first       # unchanged


def test_status_property(app, db):
    with app.app_context():
        _, active = metrics_token_service.create("a", _exp(30))
        assert active.status == "active"
        _, expired = metrics_token_service.create("e", _exp(-1))
        assert expired.status == "expired"
        _, revoked = metrics_token_service.create("r", _exp(30))
        metrics_token_service.revoke(revoked.id)
        assert revoked.status == "revoked"


# ---- CLI ------------------------------------------------------------------

def test_cli_create_list_revoke(app, db):
    runner = app.test_cli_runner()
    res = runner.invoke(args=["metrics-token", "create", "--name", "cli1",
                              "--expires-in-days", "30"])
    assert res.exit_code == 0, res.output
    assert "cmt_" in res.output               # secret shown once

    lst = runner.invoke(args=["metrics-token", "list"])
    assert "cli1" in lst.output
    assert "cmt_" not in lst.output           # list never shows the secret

    rev = runner.invoke(args=["metrics-token", "revoke", "cli1", "--yes"])
    assert rev.exit_code == 0
    assert "Revoked" in rev.output
    with app.app_context():
        assert metrics_token_service.get("cli1").revoked is True


def test_cli_create_rejects_nonpositive_expiry(app, db):
    runner = app.test_cli_runner()
    res = runner.invoke(args=["metrics-token", "create", "--name", "bad",
                              "--expires-in-days", "0"])
    assert res.exit_code != 0
