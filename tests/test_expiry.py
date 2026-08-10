"""Certificate/CA expiration: computed status, the PKI-3 clamp fix, dashboard
counts, JSON API fields, and the `flask certs` CLI."""

from datetime import datetime, timedelta, timezone

from cryptography import x509

from app.services import ca_service, cert_service
from app.models.certificate import Certificate
from app.models.ca import CertificateAuthority


def _naive_utc(days_from_now):
    """Naive-UTC datetime N days from now (matches how notAfter is stored)."""
    return (datetime.now(timezone.utc) + timedelta(days=days_from_now)).replace(tzinfo=None)


def _ca(name, validity_days=3650):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name, "O": "Test"},
        key_type="RSA", key_size=2048, validity_days=validity_days,
        passphrase="test-passphrase",
    )


def _cert(ca, cn="leaf.example.com", validity_days=365):
    return cert_service.create_certificate(
        ca=ca, subject_attrs={"CN": cn}, san_list=[],
        validity_days=validity_days, passphrase="test-passphrase",
    )


# ---- computed status ------------------------------------------------------

def test_expiry_status_and_days(app):
    with app.app_context():
        c = Certificate()
        c.not_after = _naive_utc(200)
        assert c.expiry_status == "valid"
        assert c.days_until_expiry >= 199
        c.not_after = _naive_utc(10)
        assert c.expiry_status == "expiring_soon"
        c.not_after = _naive_utc(-5)
        assert c.expiry_status == "expired"
        assert c.days_until_expiry < 0
        c.not_after = None
        assert c.expiry_status == "unknown"
        assert c.days_until_expiry is None


def test_ca_has_expiry_status(app, db):
    with app.app_context():
        ca = _ca("StatusCA", validity_days=3650)
        assert ca.expiry_status == "valid"
        ca.not_after = _naive_utc(5)
        assert ca.expiry_status == "expiring_soon"


def test_warning_threshold_is_configurable(app):
    with app.app_context():
        app.config["CERT_EXPIRY_WARNING_DAYS"] = 3
        c = Certificate()
        c.not_after = _naive_utc(10)
        assert c.expiry_status == "valid"   # 10 > 3
        app.config["CERT_EXPIRY_WARNING_DAYS"] = 30


# ---- PKI-3: stored notAfter is the real (clamped) value -------------------

def test_stored_not_after_is_clamped_to_ca(app, db):
    with app.app_context():
        ca = _ca("ShortCA", validity_days=30)              # ~30 days of life
        cert = _cert(ca, cn="clamped.example.com", validity_days=825)
        real = x509.load_pem_x509_certificate(
            cert.certificate_pem.encode()).not_valid_after_utc.replace(tzinfo=None)
        # DB stores the certificate's ACTUAL notAfter (clamped + truncated),
        # not the requested 825-day window.
        assert cert.not_after == real
        assert cert.days_until_expiry <= 31


# ---- dashboard counts -----------------------------------------------------

def test_dashboard_expiry_counts(app, auth_admin, db):
    with app.app_context():
        ca = _ca("DashCA")
        _cert(ca, cn="valid.example.com")                  # ~365d -> valid
        soon = _cert(ca, cn="soon.example.com")
        soon.not_after = _naive_utc(10)                    # expiring soon
        expired = _cert(ca, cn="expired.example.com")
        expired.not_after = _naive_utc(-3)                 # expired
        revoked = _cert(ca, cn="revoked.example.com")
        revoked.not_after = _naive_utc(5)
        revoked.is_revoked = True                          # excluded from both
        db.session.commit()
    stats = auth_admin.get("/", headers={"Accept": "application/json"}).get_json()["stats"]
    assert stats["cert_expiring_soon"] == 1
    assert stats["cert_expired"] == 1


# ---- JSON API -------------------------------------------------------------

def test_to_dict_has_expiry_fields(app, db):
    with app.app_context():
        ca = _ca("DictCA")
        cert = _cert(ca)
        d = cert.to_dict()
        assert "days_until_expiry" in d
        assert d["expiry_status"] in ("valid", "expiring_soon", "expired", "unknown")
        assert "expiry_status" in ca.to_dict()


# ---- CLI ------------------------------------------------------------------

def test_cli_expiring_lists_and_json(app, db):
    with app.app_context():
        ca = _ca("CliCA")
        cert = _cert(ca, cn="cli-expiring.example.com")
        cert.not_after = _naive_utc(7)
        db.session.commit()
    runner = app.test_cli_runner()
    text = runner.invoke(args=["certs", "expiring", "--days", "30"])
    assert text.exit_code == 0
    assert "cli-expiring.example.com" in text.output
    js = runner.invoke(args=["certs", "expiring", "--json"])
    assert js.exit_code == 0
    assert '"cli-expiring.example.com"' in js.output


def test_cli_recompute_expiry_fixes_wrong_row(app, db):
    with app.app_context():
        ca = _ca("RecomputeCA")
        cert = _cert(ca, cn="recompute.example.com")
        cid = cert.id
        real = x509.load_pem_x509_certificate(
            cert.certificate_pem.encode()).not_valid_after_utc.replace(tzinfo=None)
        cert.not_after = _naive_utc(9999)   # simulate an old, overstated row
        db.session.commit()
    result = app.test_cli_runner().invoke(args=["certs", "recompute-expiry"])
    assert result.exit_code == 0
    with app.app_context():
        assert db.session.get(Certificate, cid).not_after == real


def test_dashboard_recent_certs_show_expires_and_highlight_near_expiry(app, auth_admin, db):
    with app.app_context():
        cert = _cert(_ca("DashRowCA"), cn="soon-row.example.com")
        cert.not_after = _naive_utc(10)          # within 15 days
        db.session.commit()
    r = auth_admin.get("/")
    assert b"<th>Expires</th>" in r.data          # new expiration column
    assert b"table-warning" in r.data             # near-expiry row highlighted
