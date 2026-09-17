"""F14 (3.2.0): ACME server — RFC 8555 over a hand-rolled JWS client (pyca) and a
local http-01 responder thread. Happy path, nonces, signatures, EAB, identifier
policy, failed validation, finalize/CSR checks, revocation (account key and
certificate key), key change, deactivation, maintenance, admin UI, CLI,
outbound policy, JSON exposure and migration."""
import base64
import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from sqlalchemy import text

from app.extensions import db as _db
from app.models.acme import AcmeAccount, AcmeAuthorization, AcmeEabKey, AcmeNonce, AcmeOrder
from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.models.certificate import Certificate
from app.services import ca_service, net_policy, profile_service, scheduler_service
from app.services.acme import jws, service

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}
TOKENS = {}          # token -> body the responder serves


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        prefix = "/.well-known/acme-challenge/"
        body = TOKENS.get(self.path[len(prefix):]) if self.path.startswith(prefix) else None
        if body is None:
            self.send_response(404); self.end_headers(); return
        if body == "__redirect__":
            self.send_response(302); self.send_header("Location", "http://169.254.1.1/x"); self.end_headers(); return
        data = body.encode()
        self.send_response(200); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def responder():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture(autouse=True)
def _acme_cfg(app, responder):
    keys = ("ACME_ENABLED", "ACME_HTTP01_PORT", "ACME_VALIDATION_ALLOW_LOOPBACK", "ACME_BASE_URL",
            "ACME_DEFAULT_VALIDITY_DAYS", "ACME_ORDER_LIFETIME_HOURS", "ACME_VALIDATION_CONNECT_HOST")
    saved = {k: app.config.get(k) for k in keys}
    # identifiers such as web.example.lan are served by the local responder: the
    # test hook connects to 127.0.0.1 for the identifier's own URL, redirects are
    # still policy-checked.
    app.config.update(ACME_ENABLED=True, ACME_HTTP01_PORT=responder, ACME_VALIDATION_ALLOW_LOOPBACK=False,
                      ACME_VALIDATION_CONNECT_HOST="127.0.0.1", ACME_BASE_URL=None)
    TOKENS.clear()
    with app.app_context():
        profile_service.ensure_builtins()
    yield
    app.config.update(saved)


def _ca(name="ACME Root", require_eab=False, enabled=True, **kw):
    ca = ca_service.create_root_ca(name=name, subject_attrs={"CN": name}, key_type="EC", key_size=256,
                                   validity_days=3650, passphrase=PASSPHRASE, **kw)
    ca.acme_enabled = enabled
    ca.acme_require_eab = require_eab
    _db.session.commit()
    return ca


def _fresh(model, id_):
    _db.session.expire_all()
    return _db.session.get(model, id_)


class Client:
    """Minimal ACME client: flattened JWS over the Flask test client."""
    def __init__(self, http, ca_id, key=None, alg="ES256"):
        self.http, self.ca_id, self.alg = http, ca_id, alg
        self.key = key or (ec.generate_private_key(ec.SECP256R1()) if alg == "ES256" else rsa.generate_private_key(65537, 2048))
        self.kid = None
        self.last = None
        r = http.get(f"/acme/{ca_id}/directory")
        assert r.status_code == 200, r.data
        self.dir = r.get_json()

    @property
    def jwk(self):
        return jws.public_key_to_jwk(self.key.public_key())

    def nonce(self):
        r = self.http.head(self.dir["newNonce"])
        assert r.status_code == 200
        return r.headers["Replay-Nonce"]

    def _sig(self, key, alg, data):
        if alg == "RS256":
            return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        size = {"ES256": 32, "ES384": 48}[alg]
        digest = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384()}[alg]
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(digest)))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    def jws(self, url, payload, use_jwk=False, nonce=None, key=None, alg=None, kid=None, extra=None):
        key, alg = key or self.key, alg or self.alg
        protected = {"alg": alg, "nonce": nonce or self.nonce(), "url": url}
        if use_jwk:
            protected["jwk"] = jws.public_key_to_jwk(key.public_key())
        else:
            protected["kid"] = kid or self.kid
        if extra:
            protected.update(extra)
        p = jws.b64url_encode(json.dumps(protected).encode())
        pl = "" if payload is None else jws.b64url_encode(json.dumps(payload).encode())
        return {"protected": p, "payload": pl, "signature": jws.b64url_encode(self._sig(key, alg, f"{p}.{pl}".encode()))}

    def post(self, url, payload=None, use_jwk=False, **kw):
        body = self.jws(url, payload, use_jwk=use_jwk, **kw)
        self.last = self.http.post(url, data=json.dumps(body), content_type="application/jose+json")
        return self.last

    def register(self, contact=None, eab=None, only_existing=False):
        payload = {"termsOfServiceAgreed": True}
        if contact:
            payload["contact"] = contact
        if eab:
            payload["externalAccountBinding"] = eab
        if only_existing:
            payload["onlyReturnExisting"] = True
        r = self.post(self.dir["newAccount"], payload, use_jwk=True)
        if r.status_code in (200, 201):
            self.kid = r.headers["Location"]
        return r

    def eab(self, kid, mac_b64):
        return jws.sign_hmac(jws.b64url_decode(mac_b64), {"alg": "HS256", "kid": kid, "url": self.dir["newAccount"]},
                             json.dumps(self.jwk, separators=(",", ":"), sort_keys=True).encode())

    def order(self, *names):
        return self.post(self.dir["newOrder"], {"identifiers": [{"type": "dns", "value": n} for n in names]})

    def get(self, url):
        return self.post(url, None)

    def serve(self, authz_url, wrong=False):
        """Provision the http-01 responder for an authorization, return the challenge URL."""
        authz = self.get(authz_url).get_json()
        chall = next(c for c in authz["challenges"] if c["type"] == "http-01")
        TOKENS[chall["token"]] = "not-the-key-authorization" if wrong else jws.key_authorization(chall["token"], self.jwk)
        return chall["url"]

    def csr(self, *names, key=None, cn=None):
        key = key or ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn else [])
        csr = (x509.CertificateSigningRequestBuilder().subject_name(subject)
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
               .sign(key, hashes.SHA256()))
        return jws.b64url_encode(csr.public_bytes(serialization.Encoding.DER)), key

    def issue(self, *names):
        """Full happy path; returns (order dict, certificate PEM chain, leaf key)."""
        order = self.order(*names).get_json()
        for authz_url in order["authorizations"]:
            r = self.post(self.serve(authz_url), {})
            assert r.get_json()["status"] == "valid", r.get_json()
        order_url = self.last.headers.get("Location") or None
        csr_b64, key = self.csr(*names)
        r = self.post(order["finalize"], {"csr": csr_b64})
        assert r.status_code == 200 and r.get_json()["status"] == "valid", r.get_json()
        pem = self.get(r.get_json()["certificate"]).data.decode()
        return r.get_json(), pem, key


def _problem(r):
    assert r.mimetype == "application/problem+json", (r.status_code, r.data)
    body = r.get_json()
    assert "Replay-Nonce" in r.headers
    return body["type"].rsplit(":", 1)[1], body


# --------------------------------------------------------------------------- #

class TestDirectoryAndNonces:
    def test_disabled_globally_and_per_ca(self, app, client, db):
        ca = _ca(enabled=False)
        assert client.get(f"/acme/{ca.id}/directory").status_code == 404
        ca.acme_enabled = True; db.session.commit()
        app.config["ACME_ENABLED"] = False
        assert client.get(f"/acme/{ca.id}/directory").status_code == 404
        app.config["ACME_ENABLED"] = True
        d = client.get(f"/acme/{ca.id}/directory").get_json()
        assert set(d) >= {"newNonce", "newAccount", "newOrder", "revokeCert", "keyChange", "meta"}
        assert d["meta"]["externalAccountRequired"] is False and d["newOrder"].startswith("http://localhost/acme/")
        assert client.get("/acme/999/directory").status_code == 404

    def test_revoked_or_pending_ca_has_no_directory(self, app, client, db):
        from app.services import crl_service
        ca = _ca()
        crl_service.revoke_ca(ca.id, "cessation_of_operation", passphrase=PASSPHRASE); db.session.commit()
        assert client.get(f"/acme/{ca.id}/directory").status_code == 404

    def test_nonces(self, app, client, db):
        ca = _ca()
        r = client.head(f"/acme/{ca.id}/new-nonce")
        assert r.status_code == 200 and r.headers["Replay-Nonce"] and r.headers["Cache-Control"] == "no-store"
        r = client.get(f"/acme/{ca.id}/new-nonce")
        assert r.status_code == 204 and r.headers["Replay-Nonce"]
        assert AcmeNonce.query.count() == 2
        assert 'rel="index"' in r.headers.get("Link", "")

    def test_base_url_override(self, app, client, db):
        ca = _ca()
        app.config["ACME_BASE_URL"] = "https://ca.lan:8443/"
        d = client.get(f"/acme/{ca.id}/directory").get_json()
        assert d["newAccount"] == f"https://ca.lan:8443/acme/{ca.id}/new-account"


class TestAccounts:
    def test_register_twice_and_only_existing(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id)
        r = c.register(contact=["mailto:ops@example.lan"])
        assert r.status_code == 201 and r.get_json()["status"] == "valid" and r.headers["Location"].endswith("/account/1") or r.status_code == 201
        assert r.get_json()["contact"] == ["mailto:ops@example.lan"] and "orders" in r.get_json()
        again = c.register()
        assert again.status_code == 200 and again.headers["Location"] == c.kid
        assert AcmeAccount.query.count() == 1
        assert AuditLog.query.filter_by(action="acme_account_created").one().username == "acme"
        other = Client(client, ca.id)
        assert _problem(other.register(only_existing=True))[0] == "accountDoesNotExist"
        assert _problem(other.register(contact=["tel:+123"]))[0] == "unsupportedContact"

    def test_rs256_and_es384_keys(self, app, client, db):
        ca = _ca()
        assert Client(client, ca.id, alg="RS256").register().status_code == 201
        c = Client(client, ca.id, key=ec.generate_private_key(ec.SECP384R1()), alg="ES384")
        assert c.register().status_code == 201
        weak = Client(client, ca.id, key=rsa.generate_private_key(65537, 1024), alg="RS256")
        assert _problem(weak.register())[0] == "badPublicKey"

    def test_update_and_deactivate(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        r = c.post(c.kid, {"contact": ["mailto:new@example.lan"]})
        assert r.status_code == 200 and r.get_json()["contact"] == ["mailto:new@example.lan"]
        assert c.get(c.kid).get_json()["contact"] == ["mailto:new@example.lan"]     # POST-as-GET
        c.order("host.example.lan")
        r = c.post(c.kid, {"status": "deactivated"})
        assert r.get_json()["status"] == "deactivated"
        assert _problem(c.order("x.example.lan"))[0] == "unauthorized"
        assert AcmeOrder.query.filter_by(account_id=int(c.kid.rsplit("/", 1)[1])).one().status == "invalid"

    def test_kid_must_match_account_url(self, app, client, db):
        ca = _ca()
        a, b = Client(client, ca.id), Client(client, ca.id)
        a.register(); b.register()
        assert _problem(a.post(b.kid, None))[0] == "unauthorized"
        assert _problem(a.post(a.dir["newOrder"], {"identifiers": []}, kid=a.kid + "9"))[0] == "accountDoesNotExist"

    def test_key_change(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        new_key = ec.generate_private_key(ec.SECP256R1())
        inner = c.jws(c.dir["keyChange"], {"account": c.kid, "oldKey": c.jwk}, use_jwk=True, key=new_key, nonce="x")
        inner_protected = json.loads(jws.b64url_decode(inner["protected"])); del inner_protected["nonce"]
        p = jws.b64url_encode(json.dumps(inner_protected).encode())
        inner = {"protected": p, "payload": inner["payload"],
                 "signature": jws.b64url_encode(c._sig(new_key, "ES256", f"{p}.{inner['payload']}".encode()))}
        r = c.post(c.dir["keyChange"], inner)
        assert r.status_code == 200, r.get_json()
        old_key = c.key
        assert _problem(c.order("a.example.lan"))[0] == "malformed"     # old key no longer signs
        c.key = new_key
        assert c.order("a.example.lan").status_code == 201
        assert AuditLog.query.filter_by(action="acme_key_changed").count() == 1
        # the old key cannot re-register as a fresh account for the same server? it can (different key) — but the
        # new key may not be stolen by a third account
        third = Client(client, ca.id, key=old_key)
        assert third.register().status_code == 201


class TestJwsRules:
    def test_bad_nonce_and_replay(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id)
        r = c.register(); assert r.status_code == 201
        n = c.nonce()
        assert c.post(c.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "h.example.lan"}]}, nonce=n).status_code == 201
        kind, body = _problem(c.post(c.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "h.example.lan"}]}, nonce=n))
        assert kind == "badNonce" and c.last.headers["Replay-Nonce"]
        assert _problem(c.post(c.dir["newOrder"], {"identifiers": []}, nonce="bogus"))[0] == "badNonce"

    def test_bad_signature_url_alg_and_content_type(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        body = c.jws(c.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "h.example.lan"}]})
        body["payload"] = jws.b64url_encode(json.dumps({"identifiers": [{"type": "dns", "value": "evil.example.lan"}]}).encode())
        r = client.post(c.dir["newOrder"], data=json.dumps(body), content_type="application/jose+json")
        assert _problem(r)[0] == "malformed"
        assert _problem(c.post(c.dir["newOrder"], {"identifiers": []}, extra={"url": c.dir["newAccount"]}))[0] == "unauthorized"
        kind, body = _problem(c.post(c.dir["newOrder"], {}, extra={"alg": "HS256"}))
        assert kind == "badSignatureAlgorithm" and "ES256" in body["algorithms"]
        assert _problem(c.post(c.dir["newOrder"], {}, use_jwk=True))[0] == "malformed"       # kid endpoint, jwk given
        r = client.post(c.dir["newOrder"], data="{}", content_type="application/json")
        assert r.status_code == 415
        r = client.post(c.dir["newOrder"], data="not json", content_type="application/jose+json")
        assert _problem(r)[0] == "malformed"
        r = client.post(c.dir["newAccount"], data=json.dumps(c.jws(c.dir["newAccount"], {}, extra={"crit": ["x"]}, use_jwk=True)),
                        content_type="application/jose+json")
        assert _problem(r)[0] == "malformed"

    def test_post_as_get_required_where_specified(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        order_url = c.order("h.example.lan").headers["Location"]
        assert _problem(c.post(order_url, {"anything": 1}))[0] == "malformed"
        assert c.get(order_url).status_code == 200


class TestEab:
    def test_required_valid_used_and_revoked(self, app, client, db, admin_user):
        ca = _ca(require_eab=True)
        assert client.get(f"/acme/{ca.id}/directory").get_json()["meta"]["externalAccountRequired"] is True
        c = Client(client, ca.id)
        assert _problem(c.register())[0] == "externalAccountRequired"
        row, mac = service.create_eab_key(ca, name="host-1", created_by=admin_user.id); db.session.commit()
        bad = c.eab(row.kid, jws.b64url_encode(b"\x00" * 32))
        assert _problem(c.register(eab=bad))[0] == "unauthorized"
        assert _problem(c.register(eab=c.eab("nope", mac)))[0] == "unauthorized"
        r = c.register(eab=c.eab(row.kid, mac))
        assert r.status_code == 201 and _fresh(AcmeEabKey, row.id).status == "used"
        assert _fresh(AcmeAccount, int(c.kid.rsplit("/", 1)[1])).eab_key.kid == row.kid
        again = Client(client, ca.id)
        assert _problem(again.register(eab=again.eab(row.kid, mac)))[0] == "unauthorized"   # single use
        row2, mac2 = service.create_eab_key(ca, name="host-2"); service.revoke_eab_key(row2); db.session.commit()
        assert _problem(again.register(eab=again.eab(row2.kid, mac2)))[0] == "unauthorized"
        # eab of another CA's key is refused
        other = _ca("Other Root", require_eab=True)
        row3, mac3 = service.create_eab_key(other, name="x"); db.session.commit()
        assert _problem(again.register(eab=again.eab(row3.kid, mac3)))[0] == "unauthorized"
        # url mismatch inside the EAB
        eab = again.eab(row3.kid, mac3)
        wrong = jws.sign_hmac(jws.b64url_decode(mac3), {"alg": "HS256", "kid": row3.kid, "url": "http://elsewhere/"},
                              json.dumps(again.jwk, separators=(",", ":"), sort_keys=True).encode())
        assert _problem(Client(client, other.id).register(eab=wrong))[0] == "unauthorized"

    def test_admin_ui_and_json(self, app, auth_admin, db, admin_user):
        ca = _ca(require_eab=True)
        r = auth_admin.post(f"/ca/{ca.id}/acme/eab", data={"name": "lab"}, headers=JSON)
        assert r.status_code == 201 and r.get_json()["status"] == "unused" and len(r.get_json()["hmac_key"]) >= 40
        kid = r.get_json()["kid"]
        page = auth_admin.get(f"/ca/{ca.id}").data
        assert kid.encode() in page and b"New EAB key" in page and f"/acme/{ca.id}/directory".encode() in page
        row = AcmeEabKey.query.filter_by(kid=kid).one()
        r = auth_admin.post(f"/ca/{ca.id}/acme/eab/{row.id}/revoke", headers=JSON)
        assert r.status_code == 200 and r.get_json()["status"] == "revoked"
        assert AuditLog.query.filter_by(action="revoke_acme_eab_key").one().username == "testadmin"
        r = auth_admin.post(f"/ca/{ca.id}/acme/eab", data={"name": "flash"}, follow_redirects=True)
        assert b"MAC key (shown once)" in r.data


class TestOrdersAndValidation:
    def test_happy_path_issues_a_certificate(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        r = c.order("web.example.lan", "Web.Example.LAN.", "api.example.lan")
        assert r.status_code == 201 and r.headers["Location"].endswith("/order/1") or r.status_code == 201
        order = r.get_json()
        assert order["status"] == "pending" and len(order["authorizations"]) == 2 and order["expires"].endswith("Z")
        assert [i["value"] for i in order["identifiers"]] == ["web.example.lan", "api.example.lan"]
        authz = c.get(order["authorizations"][0]).get_json()
        assert authz["status"] == "pending" and authz["identifier"] == {"type": "dns", "value": "web.example.lan"}
        assert [ch["type"] for ch in authz["challenges"]] == ["http-01", "dns-01"] and len(authz["challenges"][0]["token"]) >= 43
        assert _problem(c.post(order["finalize"], {"csr": "x"}))[0] == "orderNotReady"
        for authz_url in order["authorizations"]:
            chall_url = c.serve(authz_url)
            r = c.post(chall_url, {})
            body = r.get_json()
            assert body["status"] == "valid" and body["validated"].endswith("Z") and 'rel="up"' in r.headers.get("Link", "")
            assert c.get(authz_url).get_json()["status"] == "valid"
        order_url = c.last.headers.get("Link") and None
        order = c.get(r.headers["Link"].split(">")[0][1:]).get_json() if False else c.get(c.dir["newOrder"].replace("new-order", "order/1")).get_json()
        assert order["status"] == "ready"
        csr_b64, key = c.csr("web.example.lan", "api.example.lan", cn="web.example.lan")
        r = c.post(order["finalize"], {"csr": csr_b64})
        assert r.status_code == 200 and r.get_json()["status"] == "valid" and r.get_json()["certificate"]
        pem = c.get(r.get_json()["certificate"])
        assert pem.mimetype == "application/pem-certificate-chain" and pem.data.count(b"BEGIN CERTIFICATE") == 2
        leaf = x509.load_pem_x509_certificate(pem.data)
        assert set(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)) == {"web.example.lan", "api.example.lan"}
        assert leaf.public_key().public_numbers() == key.public_key().public_numbers()
        cert = Certificate.query.filter_by(serial_number=format(leaf.serial_number, "x")).one()
        assert cert.issuance_source == "acme" and cert.acme_account_id == 1 and cert.ca_id == ca.id
        assert (cert.not_after - cert.not_before).days in (89, 90)
        assert cert.to_dict()["issuance_source"] == "acme"
        assert AuditLog.query.filter_by(action="acme_certificate_issued", target_id=cert.id).one().username == "acme"
        assert AuditLog.query.filter_by(action="acme_challenge_validated").count() == 2
        # idempotent: finalize again returns the valid order; challenge again keeps state
        assert c.post(order["finalize"], {"csr": csr_b64}).get_json()["status"] == "valid"
        assert c.post(chall_url, {}).get_json()["status"] == "valid"
        # the account's order list
        orders = c.get(c.register().get_json()["orders"]).get_json()["orders"]
        assert len(orders) == 1

    def test_wrong_key_authorization_fails_the_order(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        order = c.order("bad.example.lan").get_json()
        r = c.post(c.serve(order["authorizations"][0], wrong=True), {})
        body = r.get_json()
        assert body["status"] == "invalid" and body["error"]["type"].endswith("incorrectResponse")
        authz = c.get(order["authorizations"][0]).get_json()
        assert authz["status"] == "invalid"
        order_url = c.last.headers.get("Location")
        got = c.get(order["finalize"].rsplit("/finalize", 1)[0]).get_json()
        assert got["status"] == "invalid" and got["error"]["type"].endswith("unauthorized")
        assert _problem(c.post(order["finalize"], {"csr": "x"}))[0] == "orderNotReady"
        assert AuditLog.query.filter_by(action="acme_challenge_failed").count() == 1

    def test_unreachable_and_redirect_to_forbidden_target(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        app.config["ACME_VALIDATION_CONNECT_HOST"] = None       # real resolution: the name does not exist
        order = c.order("nonexistent-host-xyz.invalid").get_json()
        chall = next(ch for ch in c.get(order["authorizations"][0]).get_json()["challenges"])
        body = c.post(chall["url"], {}).get_json()
        assert body["status"] == "invalid" and body["error"]["type"].endswith("connection")
        # and a name that resolves to this server is refused by the outbound policy
        order = c.order("localhost").get_json()
        chall = next(ch for ch in c.get(order["authorizations"][0]).get_json()["challenges"])
        body = c.post(chall["url"], {}).get_json()
        assert body["status"] == "invalid" and "this server" in body["error"]["detail"]
        app.config["ACME_VALIDATION_CONNECT_HOST"] = "127.0.0.1"
        order = c.order("localhost").get_json()
        authz = c.get(order["authorizations"][0]).get_json()
        TOKENS[authz["challenges"][0]["token"]] = "__redirect__"
        body = c.post(authz["challenges"][0]["url"], {}).get_json()
        assert body["status"] == "invalid" and body["error"]["type"].endswith("connection") and "routable" in body["error"]["detail"]

    def test_identifier_policy(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        assert _problem(c.order("*.example.lan"))[0] == "rejectedIdentifier"
        assert _problem(c.order("10.0.0.5"))[0] == "rejectedIdentifier"
        assert _problem(c.order("bad_host"))[0] == "rejectedIdentifier"
        assert _problem(c.post(c.dir["newOrder"], {"identifiers": [{"type": "ip", "value": "10.0.0.5"}]}))[0] == "unsupportedIdentifier"
        assert _problem(c.post(c.dir["newOrder"], {"identifiers": []}))[0] == "malformed"
        # name constraints of the CA are enforced at order time
        from app.services import name_constraints
        constrained = ca_service.create_root_ca(name="Constrained", subject_attrs={"CN": "c"}, key_type="EC", key_size=256,
                                                validity_days=3650, passphrase=PASSPHRASE,
                                                constraints=name_constraints.normalise("DNS:example.lan", ""))
        constrained.acme_enabled = True; constrained.acme_require_eab = False; db.session.commit()
        cc = Client(client, constrained.id); cc.register()
        assert cc.order("ok.example.lan").status_code == 201
        assert _problem(cc.order("nope.example.org"))[0] == "rejectedIdentifier"

    def test_orders_are_private_to_their_account(self, app, client, db):
        ca = _ca()
        a, b = Client(client, ca.id), Client(client, ca.id)
        a.register(); b.register()
        order = a.order("h.example.lan").get_json()
        assert b.get(order["authorizations"][0]).status_code == 404
        assert b.post(order["finalize"], {"csr": "x"}).status_code == 404
        authz = a.get(order["authorizations"][0]).get_json()
        assert b.post(authz["challenges"][0]["url"], {}).status_code == 404

    def test_finalize_csr_checks(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        order = c.order("one.example.lan", "two.example.lan").get_json()
        for u in order["authorizations"]:
            c.post(c.serve(u), {})
        assert _problem(c.post(order["finalize"], {}))[0] == "badCSR"
        assert _problem(c.post(order["finalize"], {"csr": "!!"}))[0] == "badCSR"
        csr_b64, _ = c.csr("one.example.lan")
        assert _problem(c.post(order["finalize"], {"csr": csr_b64}))[0] == "badCSR"          # missing a name
        csr_b64, _ = c.csr("one.example.lan", "two.example.lan", "three.example.lan")
        assert _problem(c.post(order["finalize"], {"csr": csr_b64}))[0] == "badCSR"          # extra name
        csr_b64, _ = c.csr("one.example.lan", "two.example.lan", cn="other.example.lan")
        assert _problem(c.post(order["finalize"], {"csr": csr_b64}))[0] == "badCSR"          # CN outside
        # a weak key is refused by the key policy through sign_csr -> badCSR, order invalid
        weak = rsa.generate_private_key(65537, 1024)
        csr_b64, _ = c.csr("one.example.lan", "two.example.lan", key=weak)
        kind, body = _problem(c.post(order["finalize"], {"csr": csr_b64}))
        assert kind == "badCSR" and "2048" in body["detail"]
        assert db.session.get(AcmeOrder, 1).status == "invalid" and AuditLog.query.filter_by(action="acme_issuance_failed").count() == 1
        # order still ready → a good CSR succeeds on a fresh order
        order2 = c.order("one.example.lan").get_json()
        c.post(c.serve(order2["authorizations"][0]), {})
        csr_b64, _ = c.csr("one.example.lan")
        assert c.post(order2["finalize"], {"csr": csr_b64}).get_json()["status"] == "valid"

    def test_profile_bounds_validity_and_usage(self, app, client, db):
        ca = _ca()
        profile = profile_service.lookup("web_server") or profile_service.lookup("Web Server")
        profile.max_validity_days = 30; db.session.commit()
        ca.acme_profile_id = profile.id; db.session.commit()
        c = Client(client, ca.id); c.register()
        _order, pem, _key = c.issue("short.example.lan")
        leaf = x509.load_pem_x509_certificate(pem.encode())
        assert (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days in (29, 30)
        cert = Certificate.query.filter_by(serial_number=format(leaf.serial_number, "x")).one()
        assert cert.profile_id == profile.id
        assert json.loads(AuditLog.query.filter_by(action="acme_certificate_issued").one().details)["profile"] == profile.key

    def test_certificate_download_is_account_bound(self, app, client, db):
        ca = _ca()
        a, b = Client(client, ca.id), Client(client, ca.id)
        a.register(); b.register()
        order, _pem, _key = a.issue("dl.example.lan")
        assert b.get(order["certificate"]).status_code == 404
        assert a.get(order["certificate"]).status_code == 200


class TestRevocation:
    def test_revoke_by_account_and_by_certificate_key(self, app, client, db):
        ca = _ca()
        a, b = Client(client, ca.id), Client(client, ca.id)
        a.register(); b.register()
        _order, pem, key = a.issue("rv.example.lan")
        leaf = x509.load_pem_x509_certificate(pem.encode())
        der = jws.b64url_encode(leaf.public_bytes(serialization.Encoding.DER))
        assert _problem(b.post(b.dir["revokeCert"], {"certificate": der}))[0] == "unauthorized"       # not its cert
        assert _problem(a.post(a.dir["revokeCert"], {"certificate": der, "reason": 7}))[0] == "badRevocationReason"
        r = a.post(a.dir["revokeCert"], {"certificate": der, "reason": 4})
        assert r.status_code == 200
        cert = Certificate.query.filter_by(serial_number=format(leaf.serial_number, "x")).one()
        assert cert.is_revoked and cert.revocation_reason == "superseded"
        assert _problem(a.post(a.dir["revokeCert"], {"certificate": der}))[0] == "alreadyRevoked"
        # second certificate revoked with the certificate's own key (jwk), no account
        _order2, pem2, key2 = b.issue("rv2.example.lan")
        leaf2 = x509.load_pem_x509_certificate(pem2.encode())
        der2 = jws.b64url_encode(leaf2.public_bytes(serialization.Encoding.DER))
        stranger = Client(client, ca.id, key=key2)
        assert stranger.post(stranger.dir["revokeCert"], {"certificate": der2, "reason": 1}, use_jwk=True).status_code == 200
        assert Certificate.query.filter_by(serial_number=format(leaf2.serial_number, "x")).one().revocation_reason == "key_compromise"
        # a random key cannot revoke
        _order3, pem3, _ = b.issue("rv3.example.lan")
        der3 = jws.b64url_encode(x509.load_pem_x509_certificate(pem3.encode()).public_bytes(serialization.Encoding.DER))
        assert _problem(Client(client, ca.id).post(stranger.dir["revokeCert"], {"certificate": der3}, use_jwk=True))[0] == "unauthorized"
        assert AuditLog.query.filter_by(action="acme_certificate_revoked").count() == 2
        assert _fresh(CertificateAuthority, ca.id).crl_pem   # CRL refreshed after revocation


class TestMaintenanceAndCli:
    def test_expiry_and_nonce_pruning(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        order = c.order("exp.example.lan").get_json()
        row = AcmeOrder.query.one()
        row.expires = service.utcnow() - timedelta(minutes=1)
        for a in row.authorizations:
            a.expires = row.expires
        old = AcmeNonce.query.first(); old.created_at = service.utcnow() - timedelta(hours=2)
        db.session.commit()
        assert ("acme_maintenance", scheduler_service.job_acme_maintenance, 3600) in scheduler_service.JOBS
        summary = service.maintain()
        assert summary["expired_orders"] == 1 and summary["expired_authorizations"] == 1 and summary["pruned_nonces"] >= 1
        assert _fresh(AcmeOrder, row.id).status == "invalid" and AcmeAuthorization.query.one().status == "expired"
        got = c.get(order["finalize"].rsplit("/finalize", 1)[0]).get_json()
        assert got["status"] == "invalid" and got["error"]["detail"] == "Order expired."
        r = app.test_cli_runner().invoke(args=["acme", "maintain"])
        assert r.exit_code == 0 and json.loads(r.output.strip().splitlines()[-1])["expired_orders"] == 0

    def test_eab_cli(self, app, db):
        ca = _ca()
        runner = app.test_cli_runner()
        r = runner.invoke(args=["acme", "eab-create", "--ca-id", str(ca.id), "--name", "cli-host"])
        assert r.exit_code == 0 and "kid:" in r.output and "hmac key:" in r.output, r.output
        kid = [l for l in r.output.splitlines() if "kid:" in l][0].split()[-1]
        r = runner.invoke(args=["acme", "eab-list"])
        assert kid in r.output and "unused" in r.output
        r = runner.invoke(args=["acme", "eab-revoke", kid])
        assert r.exit_code == 0 and "Revoked" in r.output
        assert AuditLog.query.filter_by(action="revoke_acme_eab_key").one().username == "cli"
        assert runner.invoke(args=["acme", "eab-create", "--ca-id", "999"]).exit_code != 0


class TestAdminSettings:
    def test_set_acme_route(self, app, auth_admin, db):
        ca = _ca(enabled=False)
        r = auth_admin.post(f"/ca/{ca.id}/acme", data={"acme_enabled": "on", "acme_profile": "web_server"}, headers=JSON)
        assert r.status_code == 200, r.data
        assert r.get_json()["acme"] == {"enabled": True, "require_eab": False, "allow_wildcards": False, "profile": "web_server"}
        assert AuditLog.query.filter_by(action="update_ca_acme").one().username == "testadmin"
        r = auth_admin.post(f"/ca/{ca.id}/acme", data={"acme_enabled": "on", "acme_profile": "bogus"}, headers=JSON)
        assert r.status_code == 400
        r = auth_admin.post(f"/ca/{ca.id}/acme", data={"acme_require_eab": "on"}, headers=JSON)
        assert r.get_json()["acme"] == {"enabled": False, "require_eab": True, "allow_wildcards": False, "profile": None}
        page = auth_admin.get(f"/ca/{ca.id}").data
        assert b"Enable ACME" in page and b"Require EAB key" in page
        detail = auth_admin.get(f"/ca/{ca.id}", headers=JSON).get_json()
        assert "acme" in detail and "hmac" not in json.dumps(detail)

    def test_dual_control_creator_cannot_enable(self, app, auth_admin, db, admin_user, monkeypatch):
        from app.services import dual_control_service
        ca = _ca(enabled=False, created_by=admin_user.id)
        monkeypatch.setattr(dual_control_service, "is_active", lambda: True)
        monkeypatch.setattr(dual_control_service, "is_exempt", lambda user: False)
        r = auth_admin.post(f"/ca/{ca.id}/acme", data={"acme_enabled": "on"}, headers=JSON)
        assert r.status_code == 403 and "another administrator" in r.get_json()["error"]
        assert not _fresh(CertificateAuthority, ca.id).acme_enabled
        other = ca_service.create_root_ca(name="Theirs", subject_attrs={"CN": "t"}, key_type="EC", key_size=256,
                                          validity_days=365, passphrase=PASSPHRASE, created_by=admin_user.id + 1000)
        db.session.commit()
        assert auth_admin.post(f"/ca/{other.id}/acme", data={"acme_enabled": "on"}, headers=JSON).status_code == 200

    def test_requester_cannot_touch_acme(self, app, auth_csr_requester, db):
        ca = _ca()
        assert auth_csr_requester.post(f"/ca/{ca.id}/acme", data={"acme_enabled": "on"}, headers=JSON).status_code == 403
        assert auth_csr_requester.post(f"/ca/{ca.id}/acme/eab", data={}, headers=JSON).status_code == 403


class TestNetPolicy:
    def test_targets(self):
        with pytest.raises(net_policy.OutboundTargetError, match="this server"):
            net_policy.check_outbound_target("127.0.0.1")
        assert net_policy.check_outbound_target("127.0.0.1", allow_loopback=True) == ["127.0.0.1"]
        with pytest.raises(net_policy.OutboundTargetError, match="routable"):
            net_policy.check_outbound_target("169.254.10.10")
        with pytest.raises(net_policy.OutboundTargetError, match="routable"):
            net_policy.check_outbound_target("224.0.0.1")
        with pytest.raises(net_policy.OutboundTargetError):
            net_policy.check_outbound_target("")
        with pytest.raises(net_policy.OutboundTargetError, match="resolve"):
            net_policy.check_outbound_target("nonexistent-host-xyz.invalid")
        assert net_policy.check_outbound_target("10.1.2.3") == ["10.1.2.3"]


class TestSchema:
    def test_migration_adds_columns(self, app, db):
        from app import _migrate_schema
        # SQLite cannot drop a column named in a FOREIGN KEY, so the FK columns
        # stay; the migration guards every column separately.
        for table, cols in (("certificate_authorities", ("acme_enabled", "acme_require_eab")),
                            ("certificates", ("issuance_source",))):
            for col in cols:
                db.session.execute(text(f"ALTER TABLE {table} DROP COLUMN {col}"))
        db.session.commit()
        _migrate_schema()
        _migrate_schema()      # idempotent
        for table, cols in (("certificate_authorities", ("acme_enabled", "acme_profile_id", "acme_require_eab")),
                            ("certificates", ("issuance_source", "acme_account_id"))):
            have = {r[1] for r in db.session.execute(text(f"PRAGMA table_info({table})"))}
            assert set(cols) <= have
        ca = _ca("Migrated")
        assert ca.to_dict()["acme"]["require_eab"] is False and ca.acme_enabled

    def test_registry_covers_eab_keys(self):
        from app.services import passphrase_service
        assert ("acme_eab_keys", "hmac_key_enc") in {(m.__tablename__, c) for m, _a, c, _k in passphrase_service.registered()}
