"""3.6.0: dns-01 validation and wildcard identifiers for the ACME server.

The resolver is faked (`dns01.lookup_txt` is monkeypatched): RECORDS maps a
TXT name — or (name, resolver ip) — to the strings the lookup answers, or to
"__fail__" for a failed query. Everything above the lookup is real: identifier
policy, the authorization/challenge objects, the poll-driven retry budget,
finalize with a wildcard CSR, audit rows, the admin switch and the migration.
"""
import json
from datetime import timedelta

import pytest
from cryptography import x509
from sqlalchemy import text

from app.extensions import db as _db
from app.models.acme import AcmeAuthorization, AcmeChallenge, AcmeOrder
from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.models.certificate import Certificate
from app.services import profile_service
from app.services.acme import dns01, jws, service
from tests.test_acme import JSON, Client, _ca, _problem

RECORDS = {}


@pytest.fixture(autouse=True)
def _dns_cfg(app, monkeypatch):
    keys = ("ACME_ENABLED", "ACME_BASE_URL", "ACME_CHALLENGE_TYPES", "ACME_DNS_RESOLVERS",
            "ACME_DNS01_MAX_ATTEMPTS", "ACME_DNS01_RETRY_SECONDS", "ACME_DNS_TIMEOUT_SECONDS")
    saved = {k: app.config.get(k) for k in keys}
    app.config.update(ACME_ENABLED=True, ACME_BASE_URL=None, ACME_CHALLENGE_TYPES="http-01,dns-01",
                      ACME_DNS_RESOLVERS="", ACME_DNS01_MAX_ATTEMPTS=3, ACME_DNS01_RETRY_SECONDS=1,
                      ACME_DNS_TIMEOUT_SECONDS=2)
    RECORDS.clear()
    calls = []

    def fake_lookup(name, nameserver=None, timeout=5.0):
        calls.append((name, nameserver, timeout))
        answer = RECORDS.get((name, nameserver[0]) if nameserver else None, RECORDS.get(name, []))
        if answer == "__fail__":
            raise dns01.DnsLookupError("SERVFAIL")
        return list(answer)

    monkeypatch.setattr(dns01, "lookup_txt", fake_lookup)
    with app.app_context():
        profile_service.ensure_builtins()
    yield calls
    app.config.update(saved)


def _wild_ca(**kw):
    ca = _ca("Wild Root", **kw)
    ca.acme_allow_wildcards = True
    _db.session.commit()
    return ca


def _fresh(model, id_):
    _db.session.expire_all()
    return _db.session.get(model, id_)


def _id(url):
    return int(url.rstrip("/").rsplit("/", 1)[1])


def _publish(client_, authz):
    """Put the key-authorization digest of the authorization's dns-01
    challenge into the fake zone; returns the challenge URL."""
    chall = next(c for c in authz["challenges"] if c["type"] == "dns-01")
    name = dns01.txt_name(("*." if authz.get("wildcard") else "") + authz["identifier"]["value"])
    RECORDS.setdefault(name, []).append(dns01.txt_value(jws.key_authorization(chall["token"], client_.jwk)))
    return chall["url"]


def _details(action, **match):
    rows = AuditLog.query.filter_by(action=action).order_by(AuditLog.id).all()
    out = []
    for r in rows:
        d = r.details if isinstance(r.details, dict) else json.loads(r.details or "{}")
        if all(d.get(k) == v for k, v in match.items()):
            out.append(d)
    return out


# --------------------------------------------------------------------------- #

class TestPureHelpers:
    def test_txt_name_and_value(self):
        assert dns01.txt_name("*.example.lan") == "_acme-challenge.example.lan"
        assert dns01.txt_name("web.example.lan") == "_acme-challenge.web.example.lan"
        value = dns01.txt_value("token.thumbprint")
        assert len(value) == 43 and "=" not in value and "+" not in value and "/" not in value
        import base64
        import hashlib
        assert value == base64.urlsafe_b64encode(hashlib.sha256(b"token.thumbprint").digest()).rstrip(b"=").decode()

    def test_parse_challenge_types(self):
        assert service.parse_challenge_types("dns-01") == ("dns-01",)
        assert service.parse_challenge_types(" DNS-01 , http-01") == ("http-01", "dns-01")
        assert service.parse_challenge_types("http-01,http-01") == ("http-01",)
        for bad in ("", "tls-alpn-01", "http-01,foo"):
            with pytest.raises(ValueError, match="ACME_CHALLENGE_TYPES"):
                service.parse_challenge_types(bad)

    def test_startup_refuses_unknown_challenge_types(self):
        from app import create_app
        from tests.conftest import TestConfig

        class Bad(TestConfig):
            ACME_CHALLENGE_TYPES = "http-01,bogus"

        with pytest.raises(SystemExit):
            create_app(Bad)

    def test_configured_resolvers(self, app):
        with app.app_context():
            app.config["ACME_DNS_RESOLVERS"] = "10.0.0.53, [::1]:5353 ,localhost:53,192.0.2.1:5300"
            got = dns01.configured_resolvers()
            assert got[0] == ("10.0.0.53", 53) and got[1] == ("::1", 5353)
            assert got[2][0] in ("127.0.0.1", "::1") and got[2][1] == 53 and got[3] == ("192.0.2.1", 5300)
            app.config["ACME_DNS_RESOLVERS"] = ""
            assert dns01.configured_resolvers() == []
            app.config["ACME_DNS_RESOLVERS"] = "nonexistent-resolver-xyz.invalid"
            with pytest.raises(dns01.DnsLookupError, match="cannot resolve"):
                dns01.configured_resolvers()
            ok, err, detail = dns01.validate("example.lan", "x")
            assert not ok and err == "dns" and "cannot resolve" in detail

    def test_validate_outcomes(self, app, _dns_cfg):
        with app.app_context():
            name = "_acme-challenge.example.lan"
            assert dns01.validate("*.example.lan", "v") == (False, "dns", f"No TXT record {name} (via the system resolver).")
            RECORDS[name] = ["other"]
            ok, err, detail = dns01.validate("*.example.lan", "v")
            assert (ok, err) == (False, "incorrectResponse") and "1 record(s)" in detail
            RECORDS[name] = ["other", "v"]
            assert dns01.validate("*.example.lan", "v") == (True, None, None)
            RECORDS[name] = "__fail__"
            ok, err, detail = dns01.validate("example.lan", "v")
            assert (ok, err) == (False, "dns") and "SERVFAIL" in detail
            # every configured resolver must agree
            app.config["ACME_DNS_RESOLVERS"] = "192.0.2.1,192.0.2.2:5353"
            RECORDS[(name, "192.0.2.1")] = ["v"]
            RECORDS[(name, "192.0.2.2")] = []
            ok, err, detail = dns01.validate("example.lan", "v")
            assert not ok and err == "dns" and "192.0.2.2:5353" in detail and "192.0.2.1:53" not in detail
            RECORDS[(name, "192.0.2.2")] = ["v"]
            assert dns01.validate("example.lan", "v") == (True, None, None)
            assert [c[1] for c in _dns_cfg[-2:]] == [("192.0.2.1", 53), ("192.0.2.2", 5353)] and _dns_cfg[-1][2] == 2.0


class TestOrders:
    def test_wildcard_order_validates_with_dns01_and_issues(self, app, client, db):
        ca = _wild_ca()
        c = Client(client, ca.id); c.register()
        r = c.order("*.example.lan", "example.lan", "Web.example.lan")
        assert r.status_code == 201, r.data
        order = r.get_json()
        assert [i["value"] for i in order["identifiers"]] == ["*.example.lan", "example.lan", "web.example.lan"]
        wild, plain, web = [c.get(u).get_json() for u in order["authorizations"]]
        # §7.1.4: the authorization names the base domain and flags the wildcard
        assert wild["identifier"] == {"type": "dns", "value": "example.lan"} and wild["wildcard"] is True
        assert [ch["type"] for ch in wild["challenges"]] == ["dns-01"]
        assert plain["identifier"]["value"] == "example.lan" and "wildcard" not in plain
        assert [ch["type"] for ch in plain["challenges"]] == ["http-01", "dns-01"]
        assert [ch["type"] for ch in web["challenges"]] == ["http-01", "dns-01"]
        for authz in (wild, plain, web):
            url = _publish(c, authz)
            body = c.post(url, {}).get_json()
            assert body["status"] == "valid" and body["validated"].endswith("Z"), body
            assert "Retry-After" not in c.last.headers
        assert len(RECORDS["_acme-challenge.example.lan"]) == 2      # both base-name authorizations share one TXT name
        order_url = order["finalize"].rsplit("/finalize", 1)[0]
        assert c.get(order_url).get_json()["status"] == "ready"
        # the CSR must carry exactly the ordered names, wildcard included
        bad_csr, _ = c.csr("example.lan", "web.example.lan", cn="example.lan")
        assert _problem(c.post(order["finalize"], {"csr": bad_csr}))[0] == "badCSR"
        csr_b64, key = c.csr("*.example.lan", "example.lan", "web.example.lan", cn="example.lan")
        r = c.post(order["finalize"], {"csr": csr_b64})
        assert r.status_code == 200 and r.get_json()["status"] == "valid", r.data
        pem = c.get(r.get_json()["certificate"]).data
        leaf = x509.load_pem_x509_certificate(pem)
        sans = set(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
        assert sans == {"*.example.lan", "example.lan", "web.example.lan"}
        cert = Certificate.query.filter_by(serial_number=format(leaf.serial_number, "x")).one()
        assert cert.issuance_source == "acme" and "*.example.lan" in (cert.san_json or "")
        validated = _details("acme_challenge_validated", type="dns-01")
        assert len(validated) == 3 and {d["identifier"] for d in validated} == {"*.example.lan", "example.lan", "web.example.lan"}
        assert validated[0]["attempts"] == 1 and validated[0]["resolvers"] == "system"

    def test_wildcard_policy(self, app, client, db):
        plain = _ca("Plain Root")
        c = Client(client, plain.id); c.register()
        kind, body = _problem(c.order("*.example.lan"))
        assert kind == "rejectedIdentifier" and "does not allow wildcard" in body["detail"]
        wild = _wild_ca()
        w = Client(client, wild.id); w.register()
        for bad in ("*.*.example.lan", "a.*.example.lan", "*example.lan", "*."):
            assert _problem(w.order(bad))[0] == "rejectedIdentifier", bad
        assert w.order("*.example.lan").status_code == 201
        app.config["ACME_CHALLENGE_TYPES"] = "http-01"
        kind, body = _problem(w.order("*.example.lan"))
        assert kind == "rejectedIdentifier" and "needs dns-01" in body["detail"]
        # name constraints apply to the wildcard's base
        from app.services import ca_service, name_constraints
        constrained = ca_service.create_root_ca(name="Constrained", subject_attrs={"CN": "c"}, key_type="EC", key_size=256,
                                                validity_days=3650, passphrase="test-passphrase",
                                                constraints=name_constraints.normalise("DNS:example.lan", ""))
        constrained.acme_enabled = True; constrained.acme_require_eab = False; constrained.acme_allow_wildcards = True
        db.session.commit()
        app.config["ACME_CHALLENGE_TYPES"] = "http-01,dns-01"
        cc = Client(client, constrained.id); cc.register()
        assert cc.order("*.sub.example.lan").status_code == 201
        assert _problem(cc.order("*.example.org"))[0] == "rejectedIdentifier"
        assert _problem(cc.order("*.lan"))[0] == "rejectedIdentifier"

    def test_challenge_types_setting(self, app, client, db):
        ca = _ca()
        c = Client(client, ca.id); c.register()
        app.config["ACME_CHALLENGE_TYPES"] = "dns-01"
        authz = c.get(c.order("only-dns.example.lan").get_json()["authorizations"][0]).get_json()
        assert [ch["type"] for ch in authz["challenges"]] == ["dns-01"]
        app.config["ACME_CHALLENGE_TYPES"] = "http-01"
        authz = c.get(c.order("only-http.example.lan").get_json()["authorizations"][0]).get_json()
        assert [ch["type"] for ch in authz["challenges"]] == ["http-01"]


class TestRetries:
    def _start(self, client, name="*.example.lan"):
        ca = _wild_ca()
        c = Client(client, ca.id); c.register()
        order = c.order(name).get_json()
        authz_url = order["authorizations"][0]
        authz = c.get(authz_url).get_json()
        chall = next(ch for ch in authz["challenges"] if ch["type"] == "dns-01")
        return c, order, authz_url, chall

    def _due(self, chall_url):
        row = _fresh(AcmeChallenge, _id(chall_url))
        row.next_attempt_at = service.utcnow() - timedelta(seconds=1)
        _db.session.commit()

    def test_propagation_delay_then_success(self, app, client, db, _dns_cfg):
        c, order, authz_url, chall = self._start(client)
        r = c.post(chall["url"], {})
        body = r.get_json()
        assert body["status"] == "processing" and r.headers["Retry-After"] == "1"
        assert body["error"]["type"].endswith("dns") and body["error"]["detail"].startswith("Attempt 1/3")
        row = _fresh(AcmeChallenge, _id(chall["url"]))
        assert row.attempts == 1 and row.next_attempt_at is not None
        # not due yet: polls read without a lookup
        n = len(_dns_cfg)
        assert c.get(authz_url).get_json()["status"] == "pending" and c.last.headers["Retry-After"] == "1"
        assert c.get(chall["url"]).get_json()["status"] == "processing"
        assert len(_dns_cfg) == n
        # the record shows up; an order poll never looks, an authorization poll does
        RECORDS["_acme-challenge.example.lan"] = [dns01.txt_value(jws.key_authorization(chall["token"], c.jwk))]
        self._due(chall["url"])
        order_url = order["finalize"].rsplit("/finalize", 1)[0]
        assert c.get(order_url).get_json()["status"] == "pending" and len(_dns_cfg) == n
        authz = c.get(authz_url).get_json()
        assert authz["status"] == "valid" and "Retry-After" not in c.last.headers and len(_dns_cfg) == n + 1
        row = _fresh(AcmeChallenge, _id(chall["url"]))
        assert row.status == "valid" and row.attempts == 2 and row.next_attempt_at is None and row.error_json is None
        assert c.get(order_url).get_json()["status"] == "ready"
        assert _details("acme_challenge_validated")[0]["attempts"] == 2
        assert not _details("acme_challenge_failed")

    def test_challenge_poll_retries_and_budget_exhausts(self, app, client, db):
        c, order, authz_url, chall = self._start(client)
        RECORDS["_acme-challenge.example.lan"] = ["wrong-value"]
        assert c.post(chall["url"], {}).get_json()["status"] == "processing"          # attempt 1
        self._due(chall["url"])
        body = c.get(chall["url"]).get_json()                                       # attempt 2 via the challenge URL
        assert body["status"] == "processing" and body["error"]["detail"].startswith("Attempt 2/3")
        assert body["error"]["type"].endswith("incorrectResponse")
        self._due(chall["url"])
        body = c.get(chall["url"]).get_json()                                       # attempt 3 = budget → invalid
        assert body["status"] == "invalid" and body["error"]["detail"].startswith("Gave up after 3 attempt(s)")
        assert "Retry-After" not in c.last.headers
        assert c.get(authz_url).get_json()["status"] == "invalid"
        got = c.get(order["finalize"].rsplit("/finalize", 1)[0]).get_json()
        assert got["status"] == "invalid"
        failed = _details("acme_challenge_failed")
        assert len(failed) == 1 and failed[0]["attempts"] == 3 and failed[0]["identifier"] == "*.example.lan"
        # re-posting a settled challenge keeps its state
        assert c.post(chall["url"], {}).get_json()["status"] == "invalid"

    def test_lookup_failure_is_retried_with_configured_resolvers(self, app, client, db, _dns_cfg):
        app.config["ACME_DNS_RESOLVERS"] = "192.0.2.53:5353"
        c, order, authz_url, chall = self._start(client)
        RECORDS[("_acme-challenge.example.lan", "192.0.2.53")] = "__fail__"
        body = c.post(chall["url"], {}).get_json()
        assert body["status"] == "processing" and "192.0.2.53:5353" in body["error"]["detail"] and "SERVFAIL" in body["error"]["detail"]
        assert _dns_cfg[-1][1] == ("192.0.2.53", 5353)
        RECORDS[("_acme-challenge.example.lan", "192.0.2.53")] = [dns01.txt_value(jws.key_authorization(chall["token"], c.jwk))]
        self._due(chall["url"])
        assert c.get(authz_url).get_json()["status"] == "valid"
        assert _details("acme_challenge_validated")[0]["resolvers"] == "192.0.2.53:5353"

    def test_expired_authorization_stops_retrying(self, app, client, db, _dns_cfg):
        c, order, authz_url, chall = self._start(client)
        assert c.post(chall["url"], {}).get_json()["status"] == "processing"
        n = len(_dns_cfg)
        authz = _fresh(AcmeAuthorization, _id(authz_url))
        authz.expires = service.utcnow() - timedelta(seconds=1)
        db.session.commit()
        self._due(chall["url"])
        assert c.get(authz_url).get_json()["status"] == "expired" and len(_dns_cfg) == n
        assert c.get(order["finalize"].rsplit("/finalize", 1)[0]).get_json()["status"] == "invalid"

    def test_maintenance_expires_a_processing_authorization(self, app, client, db):
        c, order, authz_url, chall = self._start(client)
        assert c.post(chall["url"], {}).get_json()["status"] == "processing"
        with app.app_context():
            result = service.maintain(now=service.utcnow() + timedelta(days=8))
        assert result["expired_orders"] == 1 and result["expired_authorizations"] == 1
        assert _fresh(AcmeOrder, _id(order["finalize"].rsplit("/finalize", 1)[0])).status == "invalid"


class TestAdminAndSchema:
    def test_allow_wildcards_switch(self, app, auth_admin, db):
        ca = _ca(enabled=False)
        r = auth_admin.post(f"/ca/{ca.id}/acme", data={"acme_enabled": "on", "acme_allow_wildcards": "on"}, headers=JSON)
        assert r.status_code == 200, r.data
        assert r.get_json()["acme"] == {"enabled": True, "require_eab": False, "allow_wildcards": True, "profile": None}
        assert _details("update_ca_acme")[-1]["allow_wildcards"] is True
        assert _fresh(CertificateAuthority, ca.id).acme_allow_wildcards is True
        r = auth_admin.post(f"/ca/{ca.id}/acme", data={"acme_enabled": "on"}, headers=JSON)
        assert r.get_json()["acme"]["allow_wildcards"] is False
        page = auth_admin.get(f"/ca/{ca.id}").data
        assert b"Allow wildcard names (dns-01)" in page and b"http-01 and dns-01" in page

    def test_migration_adds_columns(self, app, db):
        from app import _migrate_schema
        for table, col in (("acme_authorizations", "wildcard"), ("acme_challenges", "attempts"),
                           ("acme_challenges", "next_attempt_at"), ("certificate_authorities", "acme_allow_wildcards")):
            db.session.execute(text(f"ALTER TABLE {table} DROP COLUMN {col}"))
        db.session.commit()
        _migrate_schema()
        _migrate_schema()      # idempotent
        for table, cols in (("acme_authorizations", ("wildcard",)), ("acme_challenges", ("attempts", "next_attempt_at")),
                            ("certificate_authorities", ("acme_allow_wildcards",))):
            have = {r[1] for r in db.session.execute(text(f"PRAGMA table_info({table})"))}
            assert set(cols) <= have, (table, have)
        ca = _wild_ca()
        assert ca.to_dict()["acme"]["allow_wildcards"] is True
