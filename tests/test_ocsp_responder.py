"""F7: delegated OCSP responder certificates — issuance/rotation rules, the
delegated response (responder ID by key hash, embedded certificate, verifies
with openssl when available), cache keying by signer, lazy renewal on the
request path, fallback to the CA key, scheduler job, CLI, route and the
passphrase-rotation registry."""
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy import inspect as sa_inspect

from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.services import (ca_service, cert_service, crl_service, crypto_utils, ocsp_service,
                          passphrase_service, scheduler_service)

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}


@pytest.fixture(autouse=True)
def _fresh_caches():
    ocsp_service._response_cache.clear()
    with ocsp_service._responder_key_lock:
        ocsp_service._responder_key_cache.clear()
    scheduler_service._state.update({"lease_held": False, "last_tick": None, "last_summary": None})
    yield
    ocsp_service._response_cache.clear()


@pytest.fixture
def delegated(app, monkeypatch):
    monkeypatch.setitem(app.config, "OCSP_DELEGATED_RESPONDER", True)
    return app


def _root(name="Resp Root", key_type="RSA", key_size=2048):
    return ca_service.create_root_ca(name=name, subject_attrs={"CN": name}, key_type=key_type,
                                     key_size=key_size, validity_days=3650, passphrase=PASSPHRASE)


def _leaf(ca, cn="leaf.example"):
    return cert_service.create_certificate(ca, {"CN": cn}, [cn], 30, PASSPHRASE, key_type="EC", key_size=256)


def _x(model):
    return x509.load_pem_x509_certificate(model.certificate_pem.encode())


def _request(ca, cert, algorithm=hashes.SHA256()):
    return ocsp.OCSPRequestBuilder().add_certificate(_x(cert), _x(ca), algorithm).build()


def _respond(ca, cert, algorithm=hashes.SHA256()):
    der = ocsp_service.build_ocsp_response(_request(ca, cert, algorithm).public_bytes(serialization.Encoding.DER),
                                           ca, PASSPHRASE)
    return ocsp.load_der_ocsp_response(der), der


def _verify(resp, public_key):
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(resp.signature, resp.tbs_response_bytes, ec.ECDSA(resp.signature_hash_algorithm))
    else:
        public_key.verify(resp.signature, resp.tbs_response_bytes, padding.PKCS1v15(), resp.signature_hash_algorithm)


# ---------------------------------------------------------------------------
# responder certificate
# ---------------------------------------------------------------------------

class TestResponderCertificate:
    def test_ensure_issues_a_proper_responder_and_is_idempotent(self, app, db):
        with app.app_context():
            root = _root()
            assert ocsp_service.responder_status(root) is None
            assert ocsp_service.ensure_responder(root, PASSPHRASE) is True
            db.session.commit()
            cert = ocsp_service.responder_certificate(root)
            cert.verify_directly_issued_by(_x(root))
            assert cert.subject.rfc4514_string() == "CN=Resp Root OCSP Responder"
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
            assert ku.critical and ku.value.digital_signature and not ku.value.key_encipherment and not ku.value.key_cert_sign
            assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.OCSP_SIGNING]
            cert.extensions.get_extension_for_class(x509.OCSPNoCheck)
            assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            assert 29 <= (cert.not_valid_after_utc - cert.not_valid_before_utc).days <= 30
            key = crypto_utils.decrypt_private_key(root.ocsp_responder_key_enc, PASSPHRASE)
            assert key.public_key().public_numbers() == cert.public_key().public_numbers()
            status = ocsp_service.responder_status(root)
            assert status["valid"] and 28 <= status["days_left"] <= 30 and status["key_type"] == "RSA"
            assert root.to_dict(detail=True)["ocsp_responder"] == status
            # fresh → no new one unless forced
            assert ocsp_service.ensure_responder(root, PASSPHRASE) is False
            serial = status["serial_number"]
            assert ocsp_service.ensure_responder(root, PASSPHRASE, force=True) is True
            assert ocsp_service.responder_status(root)["serial_number"] != serial

    def test_renewal_window_and_expiry(self, app, db, monkeypatch):
        with app.app_context():
            root = _root("Renew Root")
            past = datetime.now(timezone.utc) - timedelta(days=25)
            ocsp_service.ensure_responder(root, PASSPHRASE, now=past)      # 5 days left
            db.session.commit()
            assert ocsp_service.responder_needs_rotation(root) is True    # < 7-day window
            monkeypatch.setitem(app.config, "OCSP_RESPONDER_RENEW_BEFORE_DAYS", 2)
            assert ocsp_service.responder_needs_rotation(root) is False
            ocsp_service.ensure_responder(root, PASSPHRASE, now=datetime.now(timezone.utc) - timedelta(days=40), force=True)
            db.session.commit()
            assert ocsp_service.responder_status(root)["valid"] is False
            assert ocsp_service.responder_needs_rotation(root) is True
            # a responder is bounded by the CA's own expiry
            short = ca_service.create_root_ca(name="Short CA", subject_attrs={"CN": "Short CA"}, key_type="EC",
                                              key_size=256, validity_days=10, passphrase=PASSPHRASE)
            ocsp_service.ensure_responder(short, PASSPHRASE)
            assert ocsp_service.responder_status(short)["days_left"] <= 10

    def test_refusals(self, app, db):
        with app.app_context():
            from cryptography.hazmat.primitives import serialization as ser
            from tests.test_ca_import import _self_signed_ca
            _k, cert = _self_signed_ca("Offline")
            keyless = ca_service.import_ca("Offline", cert.public_bytes(ser.Encoding.PEM).decode(), None, PASSPHRASE)
            with pytest.raises(ValueError, match="no private key"):
                ocsp_service.ensure_responder(keyless, PASSPHRASE)
            gone = _root("Gone")
            crl_service.revoke_ca(gone.id, "cessation_of_operation", passphrase=PASSPHRASE)
            with pytest.raises(ValueError, match="revoked"):
                ocsp_service.ensure_responder(gone, PASSPHRASE)


# ---------------------------------------------------------------------------
# responses
# ---------------------------------------------------------------------------

class TestDelegatedResponses:
    def test_delegated_response_is_signed_by_the_responder(self, delegated, db):
        with delegated.app_context():
            root = _root()
            leaf = _leaf(root)
            resp, der = _respond(root, leaf)                               # lazily issues the responder
            responder = ocsp_service.responder_certificate(root)
            assert responder is not None
            assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
            assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD
            assert resp.responder_key_hash == x509.SubjectKeyIdentifier.from_public_key(responder.public_key()).digest
            assert resp.responder_key_hash != x509.SubjectKeyIdentifier.from_public_key(_x(root).public_key()).digest
            assert resp.certificates == [responder]
            _verify(resp, responder.public_key())
            row = AuditLog.query.filter_by(action="ocsp_responder_rotated", target_id=root.id).one()
            assert row.username == "system"
            if shutil.which("openssl"):
                # openssl matches statuses by CertID with its default SHA-1 digest, so
                # verify a SHA-1 request/response pair
                sha1_resp, sha1_der = _respond(root, leaf, hashes.SHA1())
                assert sha1_resp.certificates == [responder]
                with tempfile.TemporaryDirectory() as d:
                    open(os.path.join(d, "ca.pem"), "w").write(root.certificate_pem)
                    open(os.path.join(d, "leaf.pem"), "w").write(leaf.certificate_pem)
                    open(os.path.join(d, "req.der"), "wb").write(_request(root, leaf, hashes.SHA1()).public_bytes(serialization.Encoding.DER))
                    open(os.path.join(d, "resp.der"), "wb").write(sha1_der)
                    r = subprocess.run(["openssl", "ocsp", "-reqin", os.path.join(d, "req.der"), "-respin", os.path.join(d, "resp.der"),
                                        "-CAfile", os.path.join(d, "ca.pem"), "-issuer", os.path.join(d, "ca.pem"),
                                        "-cert", os.path.join(d, "leaf.pem"), "-no_nonce"], capture_output=True, text=True)
                    assert "Response verify OK" in r.stderr + r.stdout, r.stderr + r.stdout
                    assert "leaf.pem: good" in r.stdout

    def test_direct_path_when_delegation_is_off(self, app, db):
        with app.app_context():
            assert not ocsp_service.delegated_enabled()
            root = _root()
            leaf = _leaf(root)
            resp, _ = _respond(root, leaf)
            assert resp.responder_key_hash == x509.SubjectKeyIdentifier.from_public_key(_x(root).public_key()).digest
            assert resp.certificates == []
            assert ocsp_service.responder_status(root) is None          # nothing issued lazily

    def test_revoked_status_and_signer_are_part_of_the_cache_key(self, delegated, db, monkeypatch):
        with delegated.app_context():
            monkeypatch.setitem(delegated.config, "OCSP_RESPONSE_CACHE_TTL_SECONDS", 300)
            root = _root()
            leaf = _leaf(root)
            resp, _ = _respond(root, leaf)
            assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD
            crl_service.revoke_certificate(leaf.id, "key_compromise", passphrase=PASSPHRASE)
            resp, _ = _respond(root, leaf)
            assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED       # never GOOD from cache
            first = ocsp_service.responder_status(root)["serial_number"]
            ocsp_service.ensure_responder(root, PASSPHRASE, force=True)
            db.session.commit()
            resp, _ = _respond(root, leaf)
            assert resp.certificates[0].serial_number == int(ocsp_service.responder_status(root)["serial_number"], 16) != int(first, 16)
            monkeypatch.setitem(delegated.config, "OCSP_DELEGATED_RESPONDER", False)
            resp, _ = _respond(root, leaf)
            assert resp.certificates == []                                       # direct signer, not the cached delegated one

    def test_expired_responder_is_renewed_lazily_and_failure_falls_back(self, delegated, db, monkeypatch):
        with delegated.app_context():
            root = _root()
            leaf = _leaf(root)
            ocsp_service.ensure_responder(root, PASSPHRASE, now=datetime.now(timezone.utc) - timedelta(days=60))
            db.session.commit()
            old_serial = ocsp_service.responder_status(root)["serial_number"]
            resp, _ = _respond(root, leaf)
            assert ocsp_service.responder_status(root)["serial_number"] != old_serial
            assert resp.certificates[0] == ocsp_service.responder_certificate(root)
            # the request path never fails because delegation does: fall back to the CA key
            monkeypatch.setattr(ocsp_service, "ensure_responder", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("token gone")))
            root.ocsp_responder_cert_pem = None
            root.ocsp_responder_key_enc = None
            db.session.commit()
            resp, _ = _respond(root, leaf)
            assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL and resp.certificates == []

    def test_get_form_and_ec_ca(self, delegated, client, db):
        with delegated.app_context():
            import base64
            from urllib.parse import quote
            root = _root("EC Resp", "EC", 384)
            leaf = _leaf(root)
            encoded = quote(base64.b64encode(_request(root, leaf, hashes.SHA1()).public_bytes(serialization.Encoding.DER)).decode(), safe="")
            r = client.get(f"/public/ocsp/{root.id}/{encoded}")
            assert r.status_code == 200 and r.mimetype == "application/ocsp-response"
            resp = ocsp.load_der_ocsp_response(r.data)
            assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD and resp.hash_algorithm.name == "sha1"
            responder = resp.certificates[0]
            assert isinstance(responder.public_key(), ec.EllipticCurvePublicKey) and responder.public_key().curve.key_size == 384
            _verify(resp, responder.public_key())
            r = client.post(f"/public/ocsp/{root.id}", data=_request(root, leaf).public_bytes(serialization.Encoding.DER),
                            content_type="application/ocsp-request")
            assert ocsp.load_der_ocsp_response(r.data).certificates[0] == responder


# ---------------------------------------------------------------------------
# scheduler, CLI, route, registry
# ---------------------------------------------------------------------------

class TestOperations:
    def test_scheduler_job_rotates_when_due(self, delegated, db):
        with delegated.app_context():
            root = _root()
            due = _root("Due Root")
            ocsp_service.ensure_responder(due, PASSPHRASE, now=datetime.now(timezone.utc) - timedelta(days=26))
            fresh = _root("Fresh Root")
            ocsp_service.ensure_responder(fresh, PASSPHRASE)
            db.session.commit()
            job = scheduler_service.tick(force=True)["jobs"]["ocsp_responders"]
            assert sorted(job["rotated"]) == sorted([root.id, due.id]) and job["failed"] == [] and job["fresh"] == 1
            assert AuditLog.query.filter_by(action="ocsp_responder_rotated", username="scheduler").count() == 2
            assert ("ocsp_responders", scheduler_service.job_ocsp_responders, 3600) in scheduler_service.JOBS

    def test_scheduler_job_is_inert_when_disabled(self, app, db):
        with app.app_context():
            _root()
            job = scheduler_service.tick(force=True)["jobs"]["ocsp_responders"]
            assert job == {"disabled": True}
            assert AuditLog.query.filter_by(action="ocsp_responder_rotated").count() == 0

    def test_cli_and_route(self, delegated, auth_admin, db):
        with delegated.app_context():
            root = _root()
            r = delegated.test_cli_runner().invoke(args=["ocsp", "rotate-responders"])
            assert r.exit_code == 0 and "Rotated 1 responder(s)" in r.output, r.output
            first = ocsp_service.responder_status(root)["serial_number"]
            r = delegated.test_cli_runner().invoke(args=["ocsp", "rotate-responders", "--ca-id", str(root.id)])
            assert "still fresh" in r.output
            r = delegated.test_cli_runner().invoke(args=["ocsp", "rotate-responders", "--ca-id", str(root.id), "--force"])
            assert "new responder" in r.output
            db.session.expire_all()
            assert ocsp_service.responder_status(db.session.get(CertificateAuthority, root.id))["serial_number"] != first
            page = auth_admin.get(f"/ca/{root.id}").get_data(as_text=True)
            assert "Delegated responder" in page and "Rotate responder" in page and "days left" in page
            r = auth_admin.post(f"/ca/{root.id}/ocsp-responder/rotate", headers=JSON)
            assert r.status_code == 200 and r.get_json()["ocsp_responder"]["valid"] is True
            assert AuditLog.query.filter_by(action="ocsp_responder_rotated").filter(AuditLog.user_id.isnot(None)).count() == 1
            assert auth_admin.post("/ca/999999/ocsp-responder/rotate", headers=JSON).status_code == 404

    def test_metrics_migration_and_passphrase_registry(self, delegated, client, db, monkeypatch):
        with delegated.app_context():
            root = _root()
            ocsp_service.ensure_responder(root, PASSPHRASE)
            db.session.commit()
            monkeypatch.setitem(delegated.config, "METRICS_ENABLED", True)
            monkeypatch.setitem(delegated.config, "METRICS_ALLOW_UNAUTHENTICATED", True)
            body = client.get("/metrics").get_data(as_text=True)
            assert f'chancery_ca_ocsp_responder_expiry_timestamp_seconds{{ca_id="{root.id}"}}' in body
            from app import _migrate_schema
            _migrate_schema()
            cols = {c["name"] for c in sa_inspect(_db.engine).get_columns("certificate_authorities")}
            assert {"ocsp_responder_cert_pem", "ocsp_responder_key_enc"} <= cols
            assert any(c == "ocsp_responder_key_enc" for _m, _c, c, _k in passphrase_service.ENCRYPTED_COLUMNS)
            report = passphrase_service.rotate(PASSPHRASE, "a-brand-new-passphrase-xyz")
            db.session.commit()
            assert crypto_utils.can_decrypt(root.ocsp_responder_key_enc, "a-brand-new-passphrase-xyz")
            assert not crypto_utils.can_decrypt(root.ocsp_responder_key_enc, PASSPHRASE)
            passphrase_service.rotate("a-brand-new-passphrase-xyz", PASSPHRASE)
            db.session.commit()
