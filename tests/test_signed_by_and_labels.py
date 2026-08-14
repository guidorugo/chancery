"""2.10.0 PR-A: CSR signed_by tracking, #<id> title suffixes, Preferences navbar."""

from app.services import ca_service, cert_service, csr_service

PASSPHRASE = "test-passphrase"


def _create_ca(name="SignedBy Test CA"):
    return ca_service.create_root_ca(
        name=name,
        subject_attrs={"CN": name, "O": "Test"},
        key_type="RSA",
        key_size=2048,
        validity_days=3650,
        passphrase=PASSPHRASE,
    )


def _create_csr(created_by, cn="signedby.example.com"):
    csr_model, _, _ = csr_service.create_csr(
        subject_attrs={"CN": cn},
        san_list=[cn],
        key_type="RSA", key_size=2048,
        created_by=created_by,
    )
    return csr_model


def _login(client, username, password):
    client.post("/auth/login", data={"username": username, "password": password})


class TestSignedBy:
    def test_sign_records_signer(self, app, db, admin_user, csr_requester):
        with app.app_context():
            ca = _create_ca()
            csr_model = _create_csr(created_by=csr_requester.id)
            with app.test_client() as c:
                _login(c, "testadmin", "adminpass")
                resp = c.post(f"/csr/{csr_model.id}/sign", data={
                    "ca_id": str(ca.id),
                    "validity_days": "365",
                }, follow_redirects=True)
                assert resp.status_code == 200
            db.session.refresh(csr_model)
            assert csr_model.status == "approved"
            assert csr_model.signed_by == admin_user.id
            assert csr_model.signer.username == "testadmin"

    def test_signed_by_in_json(self, app, db, admin_user, csr_requester):
        with app.app_context():
            ca = _create_ca()
            csr_model = _create_csr(created_by=csr_requester.id)
            with app.test_client() as c:
                _login(c, "testadmin", "adminpass")
                c.post(f"/csr/{csr_model.id}/sign", data={
                    "ca_id": str(ca.id), "validity_days": "365",
                })
                resp = c.get(f"/csr/{csr_model.id}",
                             headers={"Accept": "application/json"})
                assert resp.status_code == 200
                assert resp.get_json()["signed_by"] == admin_user.id

    def test_reject_leaves_signed_by_null(self, app, db, admin_user, csr_requester):
        with app.app_context():
            csr_model = _create_csr(created_by=csr_requester.id)
            with app.test_client() as c:
                _login(c, "testadmin", "adminpass")
                resp = c.post(f"/csr/{csr_model.id}/reject", follow_redirects=True)
                assert resp.status_code == 200
            db.session.refresh(csr_model)
            assert csr_model.status == "rejected"
            assert csr_model.signed_by is None

    def test_csr_detail_shows_signer_and_issuing_ca(self, app, db, admin_user,
                                                    csr_requester):
        with app.app_context():
            ca = _create_ca()
            csr_model = _create_csr(created_by=csr_requester.id)
            with app.test_client() as c:
                _login(c, "testadmin", "adminpass")
                c.post(f"/csr/{csr_model.id}/sign", data={
                    "ca_id": str(ca.id), "validity_days": "365",
                })
                html = c.get(f"/csr/{csr_model.id}").get_data(as_text=True)
                assert "Issuing CA" in html
                assert "Signed By" in html
                assert "testadmin" in html

    def test_unsigned_csr_shows_no_signer_row(self, app, db, admin_user,
                                              csr_requester):
        with app.app_context():
            csr_model = _create_csr(created_by=csr_requester.id)
            with app.test_client() as c:
                _login(c, "testadmin", "adminpass")
                html = c.get(f"/csr/{csr_model.id}").get_data(as_text=True)
                assert "Signed By" not in html


class TestIdSuffix:
    def test_ca_detail_id_suffix(self, app, db, admin_user):
        with app.app_context():
            ca = _create_ca(name="IdSuffix CA")
            with app.test_client() as c:
                _login(c, "testadmin", "adminpass")
                html = c.get(f"/ca/{ca.id}").get_data(as_text=True)
                assert f'<span class="text-body-secondary">#{ca.id}</span>' in html
                assert f"IdSuffix CA #{ca.id} - Cert Manager" in html

    def test_cert_detail_id_suffix(self, app, db, admin_user):
        with app.app_context():
            ca = _create_ca(name="IdSuffix Cert CA")
            cert = cert_service.create_certificate(
                ca=ca,
                subject_attrs={"CN": "idsuffix.example.com"},
                san_list=["idsuffix.example.com"],
                validity_days=365,
                passphrase=PASSPHRASE,
            )
            with app.test_client() as c:
                _login(c, "testadmin", "adminpass")
                html = c.get(f"/certificates/{cert.id}").get_data(as_text=True)
                assert f'<span class="text-body-secondary">#{cert.id}</span>' in html
                assert f"idsuffix.example.com #{cert.id} - Cert Manager" in html


class TestPreferencesLabel:
    def test_navbar_says_preferences(self, app, db, admin_user):
        with app.test_client() as c:
            _login(c, "testadmin", "adminpass")
            html = c.get("/").get_data(as_text=True)
            assert ">Preferences</a>" in html

    def test_users_tab_keeps_its_label(self, app, db, admin_user):
        # The section is renamed in the navbar only; the tab that actually
        # lists users keeps saying "Users".
        with app.test_client() as c:
            _login(c, "testadmin", "adminpass")
            html = c.get("/users/").get_data(as_text=True)
            assert ">Users</a>" in html

    def test_requester_navbar_has_no_preferences(self, app, db, csr_requester):
        with app.test_client() as c:
            _login(c, "testrequester", "requesterpass")
            html = c.get("/").get_data(as_text=True)
            assert ">Preferences</a>" not in html
