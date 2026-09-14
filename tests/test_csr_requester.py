"""Tests for the csr_requester role."""

import base64

from app.extensions import db
from app.models.csr import CertificateSigningRequest


def _basic_auth_headers(username, password):
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


class TestCSRRequesterAccess:
    """CSR requesters can create CSRs and view their own."""

    def test_can_access_csr_list(self, auth_csr_requester):
        resp = auth_csr_requester.get("/csr/")
        assert resp.status_code == 200

    def test_can_access_csr_create(self, auth_csr_requester):
        resp = auth_csr_requester.get("/csr/create")
        assert resp.status_code == 200

    def test_can_access_dashboard(self, auth_csr_requester):
        resp = auth_csr_requester.get("/")
        assert resp.status_code == 200

    def test_can_view_own_csr(self, auth_csr_requester, csr_requester, db):
        csr = CertificateSigningRequest(
            common_name="my-csr",
            subject_json='{"CN": "my-csr"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            created_by=csr_requester.id,
        )
        db.session.add(csr)
        db.session.commit()

        resp = auth_csr_requester.get(f"/csr/{csr.id}")
        assert resp.status_code == 200


class TestCSRRequesterRestrictions:
    """CSR requesters cannot access admin-only routes."""

    def test_blocked_from_ca_list(self, auth_csr_requester):
        resp = auth_csr_requester.get("/ca/", follow_redirects=True)
        assert b"do not have permission" in resp.data

    def test_blocked_from_users(self, auth_csr_requester):
        resp = auth_csr_requester.get("/users/", follow_redirects=True)
        assert b"do not have permission" in resp.data

    def test_cannot_sign_csr(self, auth_csr_requester, db):
        csr = CertificateSigningRequest(
            common_name="test",
            subject_json='{"CN": "test"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            status="pending",
        )
        db.session.add(csr)
        db.session.commit()

        resp = auth_csr_requester.get(f"/csr/{csr.id}/sign", follow_redirects=True)
        assert b"do not have permission" in resp.data

    def test_cannot_reject_csr(self, auth_csr_requester, db):
        csr = CertificateSigningRequest(
            common_name="test",
            subject_json='{"CN": "test"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            status="pending",
        )
        db.session.add(csr)
        db.session.commit()

        resp = auth_csr_requester.post(f"/csr/{csr.id}/reject", follow_redirects=True)
        assert b"do not have permission" in resp.data

    def test_cannot_view_others_csr(self, auth_csr_requester, admin_user, db):
        csr = CertificateSigningRequest(
            common_name="admin-csr",
            subject_json='{"CN": "admin-csr"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            created_by=admin_user.id,
        )
        db.session.add(csr)
        db.session.commit()

        resp = auth_csr_requester.get(f"/csr/{csr.id}", follow_redirects=True)
        assert b"do not have permission" in resp.data


class TestCSRRequesterBasicAuth:
    """CSR requester works with Basic Auth."""

    def test_basic_auth_access(self, client, csr_requester):
        resp = client.get("/csr/", headers=_basic_auth_headers("testrequester", "requesterpass"))
        assert resp.status_code == 200

    def test_basic_auth_blocked_from_admin_route(self, client, csr_requester):
        resp = client.get("/ca/", headers=_basic_auth_headers("testrequester", "requesterpass"))
        assert resp.status_code == 403


class TestCSRRequesterUserManagement:
    """Admin can create and manage csr_requester users."""

    def test_admin_can_create_csr_requester(self, auth_admin, db):
        resp = auth_admin.post("/users/create", data={
            "username": "newrequester",
            "password": "pass1234567890",
            "role": "csr_requester",
        }, follow_redirects=True)
        assert b"newrequester" in resp.data
        from app.models.user import User
        user = User.query.filter_by(username="newrequester").first()
        assert user is not None
        assert user.role == "csr_requester"

    def test_admin_can_change_role_to_csr_requester(self, auth_admin, admin_user, db):
        # Create a second admin so we can demote one
        from app.models.user import User
        user2 = User(username="admin2", role="admin")
        user2.set_password("pass2")
        db.session.add(user2)
        db.session.commit()

        resp = auth_admin.post(f"/users/{user2.id}/edit", data={
            "role": "csr_requester",
        }, follow_redirects=True)
        assert b"updated" in resp.data.lower()
        db.session.refresh(user2)
        assert user2.role == "csr_requester"
