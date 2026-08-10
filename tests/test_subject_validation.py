"""Subject-attribute validation.

A bad subject field — most commonly a one-letter Country code — used to reach
``cryptography`` and raise ``ValueError: Attribute's length must be >= 2 and
<= 2, but it was 1``, which every create route swallowed into a generic 500.
The rule (COUNTRY_NAME must be exactly 2, COMMON_NAME 1..64) now lives in
``policy.build_subject``, so it applies to every caller — browser form AND the
Basic-Auth/JSON API — and surfaces as a clear 400.
"""

import base64

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from app.services import ca_service, policy

PASSPHRASE = "test-passphrase"


def _basic(username="testadmin", password="adminpass"):
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


def _seed_ca():
    return ca_service.create_root_ca(
        name="Subj Test CA", subject_attrs={"CN": "Subj Test CA", "O": "T"},
        key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE)


# ---- unit: policy.build_subject -------------------------------------------

def test_build_subject_valid():
    name = policy.build_subject({"CN": "host.example.com", "C": "US", "O": "Acme"})
    assert isinstance(name, x509.Name)
    assert name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "US"


def test_build_subject_one_letter_country_rejected():
    with pytest.raises(ValueError) as exc:
        policy.build_subject({"CN": "x", "C": "U"})
    # Names the field and gives an example — no terse cryptography leak.
    assert "Country" in str(exc.value)
    assert "US" in str(exc.value)


def test_build_subject_three_letter_country_rejected():
    with pytest.raises(ValueError):
        policy.build_subject({"CN": "x", "C": "USA"})


def test_build_subject_strips_padded_country():
    name = policy.build_subject({"CN": "x", "C": " us "})
    assert name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "us"


def test_build_subject_long_common_name_rejected():
    with pytest.raises(ValueError) as exc:
        policy.build_subject({"CN": "a" * 65})
    assert "Common Name" in str(exc.value)


def test_build_subject_skips_empty_fields():
    name = policy.build_subject({"CN": "only-cn", "C": "", "O": "  "})
    assert [a.oid for a in name] == [NameOID.COMMON_NAME]


# ---- API path (Basic Auth -> JSON): the validation IS in the API ----------

def test_api_create_cert_bad_country_is_400_json(app, client, admin_user, db):
    with app.app_context():
        cid = _seed_ca().id
    resp = client.post("/certificates/create", data={
        "ca_id": str(cid), "cn": "leaf.example.com", "country": "U",
        "validity_days": "365", "key_type": "RSA", "key_size": "2048",
    }, headers=_basic())
    assert resp.status_code == 400
    assert "Country" in resp.get_json()["error"]


def test_api_create_cert_good_country_ok(app, client, admin_user, db):
    with app.app_context():
        cid = _seed_ca().id
    resp = client.post("/certificates/create", data={
        "ca_id": str(cid), "cn": "leaf2.example.com", "country": "US",
        "validity_days": "365", "key_type": "RSA", "key_size": "2048",
    }, headers=_basic())
    assert resp.status_code == 201


def test_api_create_csr_bad_country_is_400_json(app, client, admin_user, db):
    resp = client.post("/csr/create", data={
        "mode": "generate", "cn": "csr.example.com", "country": "U",
        "key_type": "RSA", "key_size": "2048",
    }, headers=_basic())
    assert resp.status_code == 400
    assert "Country" in resp.get_json()["error"]


def test_api_create_ca_bad_country_is_400_json(app, client, admin_user, db):
    resp = client.post("/ca/create", data={
        "ca_type": "root", "name": "BadCountryCA", "cn": "BadCountryCA",
        "country": "U", "key_type": "RSA", "key_size": "2048",
        "validity_days": "3650",
    }, headers=_basic())
    assert resp.status_code == 400
    assert "Country" in resp.get_json()["error"]


# ---- browser (session) path: friendly flash, not the generic 500 text -----

def test_web_create_cert_bad_country_shows_friendly_message(auth_admin, app, db):
    with app.app_context():
        cid = _seed_ca().id
    resp = auth_admin.post("/certificates/create", data={
        "ca_id": str(cid), "cn": "leaf.example.com", "country": "U",
        "validity_days": "365", "key_type": "RSA", "key_size": "2048",
    })
    text = resp.get_data(as_text=True)
    assert "must be the two-letter ISO 3166 country code" in text
    assert "unexpected error occurred while creating" not in text
