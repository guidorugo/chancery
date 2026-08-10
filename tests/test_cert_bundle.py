"""Cert bundle download: fullchain (leaf -> intermediates -> root) and chain
(issuing CA chain only), both key-free PEM served over GET to the owner/admin."""

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.services import ca_service, cert_service
from app.models.audit_log import AuditLog


def _root_ca(name="Bundle Root", passphrase="test-passphrase"):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name, "O": "Test"},
        key_type="RSA", key_size=2048, validity_days=3650, passphrase=passphrase,
    )


def _issue(ca, cn="leaf.example.com", passphrase="test-passphrase"):
    return cert_service.create_certificate(
        ca=ca, subject_attrs={"CN": cn, "O": "Test"}, san_list=[cn],
        validity_days=365, passphrase=passphrase,
    )


def _cns(pem_bytes):
    certs = x509.load_pem_x509_certificates(pem_bytes)
    return [c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value for c in certs]


def test_fullchain_root_issued(app, auth_admin, db):
    with app.app_context():
        cert = _issue(_root_ca())
        cid = cert.id
    r = auth_admin.get(f"/certificates/{cid}/download?format=fullchain")
    assert r.status_code == 200
    assert r.mimetype == "application/x-pem-file"
    assert "-fullchain.pem" in r.headers["Content-Disposition"]
    # leaf first, then the (root) CA
    assert _cns(r.data) == ["leaf.example.com", "Bundle Root"]


def test_chain_root_issued(app, auth_admin, db):
    with app.app_context():
        cert = _issue(_root_ca(name="Chain Root"))
        cid = cert.id
    r = auth_admin.get(f"/certificates/{cid}/download?format=chain")
    assert r.status_code == 200
    assert "-chain.pem" in r.headers["Content-Disposition"]
    # CA chain only, no leaf
    assert _cns(r.data) == ["Chain Root"]


def test_fullchain_intermediate(app, auth_admin, db):
    with app.app_context():
        root = _root_ca(name="Deep Root")
        inter = ca_service.create_intermediate_ca(
            name="Deep Inter", parent_ca=root,
            subject_attrs={"CN": "Deep Inter", "O": "Test"},
            key_type="RSA", key_size=2048, validity_days=1825,
            passphrase="test-passphrase",
        )
        cert = _issue(inter, cn="deep.example.com")
        cid = cert.id
    full = auth_admin.get(f"/certificates/{cid}/download?format=fullchain")
    assert _cns(full.data) == ["deep.example.com", "Deep Inter", "Deep Root"]
    chain = auth_admin.get(f"/certificates/{cid}/download?format=chain")
    assert _cns(chain.data) == ["Deep Inter", "Deep Root"]


def test_bundle_is_key_free(app, auth_admin, db):
    with app.app_context():
        cert = _issue(_root_ca(name="Nokey Root"))
        cid = cert.id
    for fmt in ("fullchain", "chain"):
        r = auth_admin.get(f"/certificates/{cid}/download?format={fmt}")
        assert b"PRIVATE KEY" not in r.data


def test_bundle_ownership_denied(app, auth_csr_requester, db):
    # create_certificate leaves requested_by=None, so a csr_requester owns nothing here
    with app.app_context():
        cert = _issue(_root_ca(name="Owner Root"))
        cid = cert.id
    r = auth_csr_requester.get(f"/certificates/{cid}/download?format=fullchain")
    assert r.status_code == 302  # redirected away, not handed the bundle


def test_bundle_audit_logged(app, auth_admin, db):
    with app.app_context():
        cert = _issue(_root_ca(name="Audit Root"))
        cid = cert.id
    auth_admin.get(f"/certificates/{cid}/download?format=fullchain")
    with app.app_context():
        entry = (AuditLog.query.filter_by(action="download_certificate")
                 .order_by(AuditLog.id.desc()).first())
        assert entry is not None
        assert "fullchain" in (entry.details or "")
