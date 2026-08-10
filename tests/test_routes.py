"""Comprehensive route-level tests covering public endpoints, downloads,
dashboard, user management, CSR workflows, CRL generation, OCSP, and
edge cases."""

import base64
import json
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp

from app.extensions import db
from app.models.ca import CertificateAuthority
from app.models.certificate import Certificate
from app.models.csr import CertificateSigningRequest
from app.models.user import User
from app.services import ca_service, cert_service, csr_service, crl_service


PASSPHRASE = "test-passphrase"


def _basic_auth_headers(username, password):
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


def _create_test_ca(name="Route Test CA"):
    return ca_service.create_root_ca(
        name=name,
        subject_attrs={"CN": name, "O": "Test"},
        key_type="RSA",
        key_size=2048,
        validity_days=3650,
        passphrase=PASSPHRASE,
    )


def _create_test_cert(ca, cn="route-test.example.com", requested_by=None):
    cert = cert_service.create_certificate(
        ca=ca,
        subject_attrs={"CN": cn},
        san_list=[cn],
        validity_days=365,
        passphrase=PASSPHRASE,
    )
    if requested_by is not None:
        cert.requested_by = requested_by
        db.session.commit()
    return cert


def _build_ocsp_request(cert, ca):
    """Build a DER-encoded OCSP request for a certificate."""
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    ee_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(ee_cert, ca_cert, hashes.SHA256())
    return builder.build().public_bytes(serialization.Encoding.DER)


# =============================================================================
# Public endpoints (no auth)
# =============================================================================


class TestPublicCACertDownload:
    def test_download_ca_cert(self, app, db):
        with app.app_context():
            ca = _create_test_ca()
            with app.test_client() as c:
                resp = c.get(f"/public/ca/{ca.id}.crt")
                assert resp.status_code == 200
                assert resp.mimetype == "application/x-pem-file"
                assert b"BEGIN CERTIFICATE" in resp.data

    def test_download_ca_cert_not_found(self, client):
        resp = client.get("/public/ca/99999.crt")
        assert resp.status_code == 404

    def test_ca_cert_has_content_disposition(self, app, db):
        with app.app_context():
            ca = _create_test_ca()
            with app.test_client() as c:
                resp = c.get(f"/public/ca/{ca.id}.crt")
                assert "Content-Disposition" in resp.headers
                assert ".crt" in resp.headers["Content-Disposition"]


class TestPublicCRLDownload:
    def test_crl_der_download(self, app, db):
        with app.app_context():
            ca = _create_test_ca()
            crl_service.generate_crl(ca, PASSPHRASE)
            with app.test_client() as c:
                resp = c.get(f"/public/crl/{ca.id}.crl")
                assert resp.status_code == 200
                assert resp.mimetype == "application/pkix-crl"

    def test_crl_pem_download(self, app, db):
        with app.app_context():
            ca = _create_test_ca()
            crl_service.generate_crl(ca, PASSPHRASE)
            with app.test_client() as c:
                resp = c.get(f"/public/crl/{ca.id}.pem")
                assert resp.status_code == 200
                assert b"BEGIN X509 CRL" in resp.data

    def test_crl_not_found(self, client):
        resp = client.get("/public/crl/99999.crl")
        assert resp.status_code == 404

    def test_crl_cached_after_generation(self, app, db):
        """CRL is cached on the CA model. A keyed CA gets an initial CRL at
        creation, and regeneration refreshes the cache."""
        with app.app_context():
            ca = _create_test_ca()
            assert ca.crl_pem is not None  # initial CRL published at creation
            assert "BEGIN X509 CRL" in ca.crl_pem
            first_number = ca.crl_number
            crl_service.generate_crl(ca, PASSPHRASE)
            assert ca.crl_pem is not None
            assert ca.crl_number == first_number + 1


class TestPublicOCSP:
    def test_ocsp_good_response(self, app, db):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca)
            ocsp_req_der = _build_ocsp_request(cert, ca)

            with app.test_client() as c:
                resp = c.post(
                    f"/public/ocsp/{ca.id}",
                    data=ocsp_req_der,
                    content_type="application/ocsp-request",
                )
                assert resp.status_code == 200
                assert resp.mimetype == "application/ocsp-response"

                ocsp_resp = ocsp.load_der_ocsp_response(resp.data)
                assert ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
                assert ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD

    def test_ocsp_revoked_response(self, app, db):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca)
            crl_service.revoke_certificate(cert.id, "key_compromise")
            ocsp_req_der = _build_ocsp_request(cert, ca)

            with app.test_client() as c:
                resp = c.post(
                    f"/public/ocsp/{ca.id}",
                    data=ocsp_req_der,
                    content_type="application/ocsp-request",
                )
                assert resp.status_code == 200
                ocsp_resp = ocsp.load_der_ocsp_response(resp.data)
                assert ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
                assert ocsp_resp.revocation_reason == x509.ReasonFlags.key_compromise

    def test_ocsp_next_update_present(self, app, db):
        """OCSP response should include next_update."""
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca)
            ocsp_req_der = _build_ocsp_request(cert, ca)

            with app.test_client() as c:
                resp = c.post(
                    f"/public/ocsp/{ca.id}",
                    data=ocsp_req_der,
                    content_type="application/ocsp-request",
                )
                ocsp_resp = ocsp.load_der_ocsp_response(resp.data)
                assert ocsp_resp.next_update_utc is not None

    def test_ocsp_unknown_serial(self, app, db):
        """OCSP request for unknown serial should return UNAUTHORIZED."""
        with app.app_context():
            ca = _create_test_ca()
            # Build a request for a cert that doesn't exist in the DB
            cert = _create_test_cert(ca)
            ocsp_req_der = _build_ocsp_request(cert, ca)
            # Delete the certificate so it's unknown
            db.session.delete(cert)
            db.session.commit()

            with app.test_client() as c:
                resp = c.post(
                    f"/public/ocsp/{ca.id}",
                    data=ocsp_req_der,
                    content_type="application/ocsp-request",
                )
                assert resp.status_code == 200
                ocsp_resp = ocsp.load_der_ocsp_response(resp.data)
                assert ocsp_resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED

    def test_ocsp_invalid_request_returns_500(self, app, db):
        with app.app_context():
            ca = _create_test_ca()
            with app.test_client() as c:
                resp = c.post(
                    f"/public/ocsp/{ca.id}",
                    data=b"not-a-valid-ocsp-request",
                    content_type="application/ocsp-request",
                )
                assert resp.status_code == 500
                assert b"Internal server error" in resp.data

    def test_ocsp_ca_not_found(self, client):
        resp = client.post(
            "/public/ocsp/99999",
            data=b"anything",
            content_type="application/ocsp-request",
        )
        assert resp.status_code == 404


# =============================================================================
# Certificate downloads (auth required)
# =============================================================================


class TestCertificateDownloads:
    def test_download_pem(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/certificates/{cert.id}/download?format=pem")
                assert resp.status_code == 200
                assert resp.mimetype == "application/x-pem-file"
                assert b"BEGIN CERTIFICATE" in resp.data

    def test_download_der(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/certificates/{cert.id}/download?format=der")
                assert resp.status_code == 200
                assert resp.mimetype == "application/x-x509-ca-cert"
                assert len(resp.data) > 0

    def test_download_pkcs12(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/certificates/{cert.id}/download",
                              data={"format": "pkcs12", "password": "testpw"})
                assert resp.status_code == 200
                assert resp.mimetype == "application/x-pkcs12"
                assert len(resp.data) > 0

    def test_download_not_found(self, auth_admin):
        resp = auth_admin.get("/certificates/99999/download")
        assert resp.status_code == 302  # redirect to list

    def test_download_forbidden_for_non_owner(self, app, db, admin_user, csr_requester):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testrequester", "password": "requesterpass"
                })
                resp = c.get(f"/certificates/{cert.id}/download", follow_redirects=True)
                assert b"do not have permission" in resp.data

    def test_download_allowed_for_owner(self, app, db, csr_requester):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=csr_requester.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testrequester", "password": "requesterpass"
                })
                resp = c.get(f"/certificates/{cert.id}/download?format=pem")
                assert resp.status_code == 200
                assert b"BEGIN CERTIFICATE" in resp.data


class TestPrivateKeyDownload:
    def test_admin_can_download_key(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/certificates/{cert.id}/download-key")
                assert resp.status_code == 200
                assert b"BEGIN PRIVATE KEY" in resp.data

    def test_key_download_requires_admin(self, app, db, csr_requester):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=csr_requester.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testrequester", "password": "requesterpass"
                })
                resp = c.post(f"/certificates/{cert.id}/download-key", follow_redirects=True)
                assert b"do not have permission" in resp.data

    def test_key_download_not_found(self, auth_admin):
        resp = auth_admin.post("/certificates/99999/download-key")
        assert resp.status_code == 302

    def test_key_download_no_key(self, app, db, admin_user):
        """Certificate with no private key should flash error."""
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca)
            # Remove the private key
            cert.private_key_enc = None
            db.session.commit()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/certificates/{cert.id}/download-key", follow_redirects=True)
                assert b"No private key" in resp.data


# =============================================================================
# Dashboard
# =============================================================================


class TestDashboard:
    def test_admin_dashboard(self, auth_admin):
        resp = auth_admin.get("/")
        assert resp.status_code == 200

    def test_csr_requester_dashboard(self, auth_csr_requester):
        resp = auth_csr_requester.get("/")
        assert resp.status_code == 200

    def test_unauthenticated_redirects(self, client):
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]


# =============================================================================
# CA routes
# =============================================================================


class TestCARoutes:
    def test_create_root_ca(self, app, db, admin_user):
        with app.app_context():
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/ca/create", data={
                    "mode": "generate",
                    "name": "My Root CA",
                    "cn": "My Root CA",
                    "key_type": "RSA",
                    "key_size": "2048",
                    "validity_days": "3650",
                    "ca_type": "root",
                }, follow_redirects=True)
                assert resp.status_code == 200
                ca = CertificateAuthority.query.filter_by(name="My Root CA").first()
                assert ca is not None
                assert ca.is_root is True

    def test_create_intermediate_ca(self, app, db, admin_user):
        with app.app_context():
            root_ca = _create_test_ca("Root For Intermediate")
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/ca/create", data={
                    "mode": "generate",
                    "name": "My Intermediate CA",
                    "cn": "My Intermediate CA",
                    "key_type": "RSA",
                    "key_size": "2048",
                    "validity_days": "1825",
                    "ca_type": "intermediate",
                    "parent_id": str(root_ca.id),
                }, follow_redirects=True)
                assert resp.status_code == 200
                ica = CertificateAuthority.query.filter_by(name="My Intermediate CA").first()
                assert ica is not None
                assert ica.is_root is False
                assert ica.parent_id == root_ca.id

    def test_ca_detail(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/ca/{ca.id}")
                assert resp.status_code == 200

    def test_ca_detail_not_found(self, auth_admin):
        resp = auth_admin.get("/ca/99999", follow_redirects=True)
        assert b"CA not found" in resp.data

    def test_revoke_ca(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca("Revoke Me CA")
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/ca/{ca.id}/revoke", data={
                    "reason": "key_compromise",
                }, follow_redirects=True)
                assert resp.status_code == 200
                db.session.refresh(ca)
                assert ca.is_revoked is True

    def test_revoke_already_revoked_ca(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca("Already Revoked CA")
            ca.is_revoked = True
            ca.revoked_at = datetime.now(timezone.utc)
            db.session.commit()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/ca/{ca.id}/revoke", follow_redirects=True)
                assert b"already revoked" in resp.data

    def test_generate_crl_route(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca("CRL Gen CA")
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/ca/{ca.id}/crl", follow_redirects=True)
                assert resp.status_code == 200
                db.session.refresh(ca)
                assert ca.crl_number >= 1

    def test_generate_crl_revoked_ca(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca("Revoked CRL CA")
            ca.is_revoked = True
            ca.revoked_at = datetime.now(timezone.utc)
            db.session.commit()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/ca/{ca.id}/crl", follow_redirects=True)
                assert b"Cannot generate CRL for a revoked CA" in resp.data

    def test_detect_parent_route(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca("Detect Parent CA")
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/ca/detect-parent", data={
                    "cert_pem": ca.certificate_pem,
                })
                assert resp.status_code == 200
                data = json.loads(resp.data)
                # Self-signed cert
                assert data["is_self_signed"] is True

    def test_detect_parent_empty_pem(self, auth_admin):
        resp = auth_admin.post("/ca/detect-parent", data={"cert_pem": ""})
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["is_self_signed"] is None


# =============================================================================
# Certificate routes
# =============================================================================


class TestCertificateRoutes:
    def test_create_certificate_route(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/certificates/create", data={
                    "ca_id": str(ca.id),
                    "cn": "route-created.example.com",
                    "validity_days": "365",
                    "key_type": "RSA",
                    "key_size": "2048",
                }, follow_redirects=True)
                assert resp.status_code == 200
                cert = Certificate.query.filter_by(common_name="route-created.example.com").first()
                assert cert is not None

    def test_create_certificate_missing_cn(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/certificates/create", data={
                    "ca_id": str(ca.id),
                    "cn": "",
                    "validity_days": "365",
                    "key_type": "RSA",
                    "key_size": "2048",
                }, follow_redirects=True)
                assert b"Common Name is required" in resp.data

    def test_create_certificate_revoked_ca(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca("Revoked For Cert CA")
            ca.is_revoked = True
            db.session.commit()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/certificates/create", data={
                    "ca_id": str(ca.id),
                    "cn": "test.example.com",
                    "validity_days": "365",
                    "key_type": "RSA",
                    "key_size": "2048",
                }, follow_redirects=True)
                assert b"Cannot issue certificates from a revoked CA" in resp.data

    def test_certificate_detail(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/certificates/{cert.id}")
                assert resp.status_code == 200

    def test_certificate_detail_not_found(self, auth_admin):
        resp = auth_admin.get("/certificates/99999", follow_redirects=True)
        assert b"Certificate not found" in resp.data

    def test_revoke_certificate_route(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/certificates/{cert.id}/revoke", data={
                    "reason": "superseded",
                }, follow_redirects=True)
                assert resp.status_code == 200
                db.session.refresh(cert)
                assert cert.is_revoked is True
                assert cert.revocation_reason == "superseded"

    def test_revoke_certificate_get(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/certificates/{cert.id}/revoke")
                assert resp.status_code == 200


# =============================================================================
# CSR routes
# =============================================================================


class TestCSRRoutes:
    def test_create_csr_generate(self, app, db, admin_user):
        with app.app_context():
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/csr/create", data={
                    "mode": "generate",
                    "cn": "gen-csr.example.com",
                    "key_type": "RSA",
                    "key_size": "2048",
                }, follow_redirects=True)
                assert resp.status_code == 200
                csr = CertificateSigningRequest.query.filter_by(
                    common_name="gen-csr.example.com"
                ).first()
                assert csr is not None

    def test_create_csr_upload(self, app, db, admin_user):
        """Upload a valid CSR PEM."""
        with app.app_context():
            # Generate a CSR programmatically to get valid PEM
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "upload.example.com"),
                ]))
                .sign(key, hashes.SHA256())
            )
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/csr/create", data={
                    "mode": "upload",
                    "csr_pem": csr_pem,
                }, follow_redirects=True)
                assert resp.status_code == 200

    def test_sign_csr_route(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca()
            csr_model, _, _ = csr_service.create_csr(
                subject_attrs={"CN": "sign-route.example.com"},
                san_list=["sign-route.example.com"],
                key_type="RSA", key_size=2048,
                created_by=admin_user.id,
            )
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/csr/{csr_model.id}/sign", data={
                    "ca_id": str(ca.id),
                    "validity_days": "365",
                }, follow_redirects=True)
                assert resp.status_code == 200
                db.session.refresh(csr_model)
                assert csr_model.status == "approved"

    def test_sign_already_processed_csr(self, app, db, admin_user):
        with app.app_context():
            csr_model = CertificateSigningRequest(
                common_name="processed-csr",
                subject_json='{"CN": "processed-csr"}',
                csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
                status="approved",
            )
            db.session.add(csr_model)
            db.session.commit()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/csr/{csr_model.id}/sign", follow_redirects=True)
                assert b"already been processed" in resp.data

    def test_reject_csr_route(self, app, db, admin_user):
        with app.app_context():
            csr_model = CertificateSigningRequest(
                common_name="reject-me",
                subject_json='{"CN": "reject-me"}',
                csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
                status="pending",
            )
            db.session.add(csr_model)
            db.session.commit()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/csr/{csr_model.id}/reject", follow_redirects=True)
                assert resp.status_code == 200
                db.session.refresh(csr_model)
                assert csr_model.status == "rejected"

    def test_reject_csr_not_found(self, auth_admin):
        resp = auth_admin.post("/csr/99999/reject", follow_redirects=True)
        assert b"CSR not found" in resp.data

    def test_sign_csr_with_revoked_ca(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca("Revoked Sign CA")
            ca.is_revoked = True
            db.session.commit()
            csr_model, _, _ = csr_service.create_csr(
                subject_attrs={"CN": "revoked-sign.example.com"},
                san_list=[], key_type="RSA", key_size=2048,
            )
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/csr/{csr_model.id}/sign", data={
                    "ca_id": str(ca.id),
                    "validity_days": "365",
                }, follow_redirects=True)
                assert b"Cannot sign CSR with a revoked CA" in resp.data


# =============================================================================
# User management routes
# =============================================================================


class TestUserManagementRoutes:
    def test_create_user(self, auth_admin):
        resp = auth_admin.post("/users/create", data={
            "username": "newuser",
            "password": "newpass123",
            "role": "csr_requester",
        }, follow_redirects=True)
        assert b"newuser" in resp.data
        user = User.query.filter_by(username="newuser").first()
        assert user is not None
        assert user.role == "csr_requester"

    def test_create_user_duplicate(self, auth_admin, admin_user):
        resp = auth_admin.post("/users/create", data={
            "username": "testadmin",
            "password": "anotherpass",
            "role": "admin",
        }, follow_redirects=True)
        assert b"already exists" in resp.data

    def test_create_user_empty_fields(self, auth_admin):
        resp = auth_admin.post("/users/create", data={
            "username": "",
            "password": "",
            "role": "admin",
        }, follow_redirects=True)
        assert b"required" in resp.data

    def test_create_user_invalid_role(self, auth_admin):
        resp = auth_admin.post("/users/create", data={
            "username": "badrole",
            "password": "pass123",
            "role": "superadmin",
        }, follow_redirects=True)
        assert b"Invalid role" in resp.data

    def test_edit_user_role(self, auth_admin, db):
        user = User(username="editme", role="csr_requester")
        user.set_password("pass123")
        db.session.add(user)
        db.session.commit()

        resp = auth_admin.post(f"/users/{user.id}/edit", data={
            "role": "admin",
        }, follow_redirects=True)
        assert b"updated" in resp.data.lower()
        db.session.refresh(user)
        assert user.role == "admin"

    def test_edit_user_not_found(self, auth_admin):
        resp = auth_admin.get("/users/99999/edit", follow_redirects=True)
        assert b"User not found" in resp.data

    def test_reset_password(self, auth_admin, db):
        user = User(username="resetme", role="csr_requester")
        user.set_password("oldpass")
        db.session.add(user)
        db.session.commit()

        resp = auth_admin.post(f"/users/{user.id}/reset-password", data={
            "password": "newpass123",
        }, follow_redirects=True)
        assert b"has been reset" in resp.data
        db.session.refresh(user)
        assert user.check_password("newpass123")

    def test_reset_password_empty(self, auth_admin, db):
        user = User(username="resetempty", role="csr_requester")
        user.set_password("oldpass")
        db.session.add(user)
        db.session.commit()

        resp = auth_admin.post(f"/users/{user.id}/reset-password", data={
            "password": "",
        }, follow_redirects=True)
        assert b"required" in resp.data

    def test_toggle_active(self, auth_admin, db):
        user = User(username="toggleme", role="csr_requester")
        user.set_password("pass123")
        db.session.add(user)
        db.session.commit()
        assert user.is_active_user is True

        resp = auth_admin.post(f"/users/{user.id}/toggle-active", follow_redirects=True)
        assert b"deactivated" in resp.data
        db.session.refresh(user)
        assert user.is_active_user is False

        # Toggle back to active
        resp = auth_admin.post(f"/users/{user.id}/toggle-active", follow_redirects=True)
        assert b"activated" in resp.data
        db.session.refresh(user)
        assert user.is_active_user is True

    def test_toggle_not_found(self, auth_admin):
        resp = auth_admin.post("/users/99999/toggle-active", follow_redirects=True)
        assert b"User not found" in resp.data


# =============================================================================
# Audit log
# =============================================================================


class TestAuditLogRoute:
    def test_audit_log_accessible_by_admin(self, auth_admin):
        resp = auth_admin.get("/users/audit-log")
        assert resp.status_code == 200

    def test_audit_log_pagination(self, auth_admin):
        resp = auth_admin.get("/users/audit-log?page=1")
        assert resp.status_code == 200

    def test_audit_log_blocked_for_csr_requester(self, auth_csr_requester):
        resp = auth_csr_requester.get("/users/audit-log", follow_redirects=True)
        assert b"do not have permission" in resp.data


# =============================================================================
# Auth routes
# =============================================================================


class TestAuthRoutes:
    def test_login_page(self, client):
        resp = client.get("/auth/login")
        assert resp.status_code == 200

    def test_login_success(self, client, admin_user):
        resp = client.post("/auth/login", data={
            "username": "testadmin",
            "password": "adminpass",
        }, follow_redirects=False)
        assert resp.status_code == 302

    def test_login_failure(self, client, admin_user):
        resp = client.post("/auth/login", data={
            "username": "testadmin",
            "password": "wrong",
        }, follow_redirects=True)
        assert b"Invalid username or password" in resp.data

    def test_logout(self, auth_admin):
        resp = auth_admin.post("/auth/logout", follow_redirects=True)
        assert resp.status_code == 200
        assert b"logged out" in resp.data

    def test_safe_url_rejects_javascript(self):
        from app.routes.auth import _is_safe_url
        assert _is_safe_url("javascript:alert(1)") is False

    def test_safe_url_rejects_data_uri(self):
        from app.routes.auth import _is_safe_url
        assert _is_safe_url("data:text/html,test") is False


# =============================================================================
# CA revocation cascades
# =============================================================================


class TestCACascadeRevocation:
    def test_revoking_ca_revokes_its_certs(self, app, db, admin_user):
        with app.app_context():
            ca = _create_test_ca("Cascade CA")
            cert = _create_test_cert(ca, cn="cascade.example.com")
            assert cert.is_revoked is False

            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                c.post(f"/ca/{ca.id}/revoke", data={"reason": "key_compromise"})

            db.session.refresh(cert)
            assert cert.is_revoked is True

    def test_revoking_ca_revokes_sub_cas(self, app, db, admin_user):
        with app.app_context():
            root = _create_test_ca("Root Cascade CA")
            intermediate = ca_service.create_intermediate_ca(
                name="Intermediate Cascade CA",
                parent_ca=root,
                subject_attrs={"CN": "Intermediate Cascade CA"},
                key_type="RSA", key_size=2048,
                validity_days=1825,
                passphrase=PASSPHRASE,
            )
            assert intermediate.is_revoked is False

            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                c.post(f"/ca/{root.id}/revoke", data={"reason": "key_compromise"})

            db.session.refresh(intermediate)
            assert intermediate.is_revoked is True


# =============================================================================
# Exception message sanitization
# =============================================================================


class TestExceptionSanitization:
    """Route error flash messages should not leak internal exception details."""

    def test_ca_create_error_generic(self, app, db, admin_user):
        """Creating a CA with invalid parent should show generic error."""
        with app.app_context():
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/ca/create", data={
                    "mode": "generate",
                    "name": "Bad CA",
                    "cn": "Bad CA",
                    "key_type": "RSA",
                    "key_size": "2048",
                    "validity_days": "3650",
                    "ca_type": "intermediate",
                    "parent_id": "99999",
                }, follow_redirects=True)
                # Should get a validation error (Parent CA not found) not an exception trace
                assert b"Traceback" not in resp.data


# =============================================================================
# User role default
# =============================================================================


# =============================================================================
# Certificate detail page content
# =============================================================================


class TestCertificateDetailContent:
    def test_detail_shows_key_usage_defaults(self, app, db, admin_user):
        """When key_usage_json is None, detail page should show default KU values."""
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            # Ensure no explicit KU stored (uses service defaults)
            cert.key_usage_json = None
            cert.extended_key_usage_json = None
            db.session.commit()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/certificates/{cert.id}")
                assert resp.status_code == 200
                assert b"Digital Signature" in resp.data
                assert b"Key Encipherment" in resp.data

    def test_detail_shows_explicit_key_usage(self, app, db, admin_user):
        """When key_usage_json is set, detail page should show stored values."""
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            cert.key_usage_json = json.dumps({
                "digital_signature": True, "key_encipherment": False,
                "content_commitment": True, "data_encipherment": False,
                "key_agreement": False,
            })
            cert.extended_key_usage_json = json.dumps(["codeSigning"])
            db.session.commit()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/certificates/{cert.id}")
                assert resp.status_code == 200
                assert b"Content Commitment" in resp.data
                assert b"Code Signing" in resp.data

    def test_detail_shows_subject_details(self, app, db, admin_user):
        """Detail page should show subject DN fields."""
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            cert.subject_json = json.dumps({
                "CN": "test.example.com", "O": "Test Org", "C": "US",
            })
            db.session.commit()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/certificates/{cert.id}")
                assert resp.status_code == 200
                assert b"Test Org" in resp.data
                assert b"Subject Details" in resp.data

    def test_detail_shows_requester(self, app, db, admin_user):
        """Detail page should show Requested By when set."""
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca, requested_by=admin_user.id)
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/certificates/{cert.id}")
                assert resp.status_code == 200
                assert b"Requested By" in resp.data
                assert b"testadmin" in resp.data

    def test_detail_hides_requester_when_not_set(self, app, db, admin_user):
        """Detail page should not show Requested By when not set."""
        with app.app_context():
            ca = _create_test_ca()
            cert = _create_test_cert(ca)  # no requested_by
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.get(f"/certificates/{cert.id}")
                assert resp.status_code == 200
                assert b"Requested By" not in resp.data


# =============================================================================
# CRL DP URL: custom, auto-detect, and localhost warning
# =============================================================================


class TestCRLDPURL:
    def test_create_cert_with_custom_crl_dp(self, app, db, admin_user):
        """Custom CRL DP URL from form should be used instead of auto-generated."""
        with app.app_context():
            ca = _create_test_ca()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post("/certificates/create", data={
                    "ca_id": str(ca.id),
                    "cn": "custom-crl.example.com",
                    "validity_days": "365",
                    "key_type": "RSA",
                    "key_size": "2048",
                    "crl_dp_url": "https://crl.example.com/my-ca.crl",
                }, follow_redirects=True)
                assert resp.status_code == 200
                cert = Certificate.query.filter_by(common_name="custom-crl.example.com").first()
                assert cert is not None

    def test_sign_csr_with_custom_crl_dp(self, app, db, admin_user):
        """Custom CRL DP URL from form should be used in CSR signing."""
        with app.app_context():
            ca = _create_test_ca()
            csr_model, _, _ = csr_service.create_csr(
                subject_attrs={"CN": "custom-crl-csr.example.com"},
                san_list=["custom-crl-csr.example.com"],
                key_type="RSA", key_size=2048,
                created_by=admin_user.id,
            )
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                resp = c.post(f"/csr/{csr_model.id}/sign", data={
                    "ca_id": str(ca.id),
                    "validity_days": "365",
                    "crl_dp_url": "https://crl.example.com/csr-ca.crl",
                }, follow_redirects=True)
                assert resp.status_code == 200
                db.session.refresh(csr_model)
                assert csr_model.status == "approved"

    def test_auto_detect_hostname_in_create(self, app, db, admin_user):
        """When SERVER_NAME_FOR_OCSP is default, auto-detect from request.host."""
        with app.app_context():
            ca = _create_test_ca()
            with app.test_client() as c:
                c.post("/auth/login", data={
                    "username": "testadmin", "password": "adminpass"
                })
                # GET request to check auto-detected host in rendered template
                resp = c.get("/certificates/create")
                assert resp.status_code == 200
                # The default test client host is 'localhost'
                assert b"localhost" in resp.data

    def test_explicit_server_name_takes_priority(self, app, db, admin_user):
        """When SERVER_NAME_FOR_OCSP is explicitly set, it takes priority."""
        with app.app_context():
            original = app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
            app.config["SERVER_NAME_FOR_OCSP"] = "ca.example.com"
            try:
                ca = _create_test_ca()
                with app.test_client() as c:
                    c.post("/auth/login", data={
                        "username": "testadmin", "password": "adminpass"
                    })
                    resp = c.get("/certificates/create")
                    assert resp.status_code == 200
                    assert b"ca.example.com" in resp.data
            finally:
                app.config["SERVER_NAME_FOR_OCSP"] = original

    def test_localhost_warning_displayed(self, app, db, admin_user):
        """Localhost warning should appear when server contains localhost."""
        with app.app_context():
            original = app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
            app.config["SERVER_NAME_FOR_OCSP"] = "localhost:5000"
            try:
                ca = _create_test_ca()
                with app.test_client() as c:
                    c.post("/auth/login", data={
                        "username": "testadmin", "password": "adminpass"
                    })
                    # The test client host is 'localhost', which triggers the warning
                    resp = c.get("/certificates/create")
                    assert resp.status_code == 200
                    assert b"SERVER_NAME_FOR_OCSP" in resp.data
            finally:
                app.config["SERVER_NAME_FOR_OCSP"] = original

    def test_no_warning_with_production_hostname(self, app, db, admin_user):
        """No localhost warning when SERVER_NAME_FOR_OCSP is production hostname."""
        with app.app_context():
            original = app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
            app.config["SERVER_NAME_FOR_OCSP"] = "ca.example.com"
            try:
                ca = _create_test_ca()
                with app.test_client() as c:
                    c.post("/auth/login", data={
                        "username": "testadmin", "password": "adminpass"
                    })
                    resp = c.get("/certificates/create")
                    assert resp.status_code == 200
                    # No warning should be present
                    assert b"SERVER_NAME_FOR_OCSP" not in resp.data
            finally:
                app.config["SERVER_NAME_FOR_OCSP"] = original


class TestUserRoleDefault:
    def test_user_default_role_is_csr_requester(self, db):
        user = User(username="defaultrole")
        user.set_password("testpass")
        db.session.add(user)
        db.session.commit()
        assert user.role == "csr_requester"
