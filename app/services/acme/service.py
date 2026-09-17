"""ACME state machine (RFC 8555) over the models in app.models.acme.

Everything here raises AcmeProblem for protocol errors and leaves committing to
the route (except where noted). Issuance goes through cert_service.sign_csr
with the CA's ACME profile, so profiles, name constraints, key policy and
certificate policies apply exactly as for a signed CSR.
"""
import json
import re
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from flask import current_app, has_request_context, url_for

from ...extensions import db
from ...models.acme import AcmeAccount, AcmeAuthorization, AcmeChallenge, AcmeEabKey, AcmeNonce, AcmeOrder
from ...models.certificate import Certificate
from .. import audit_service, cert_service, crl_service, csr_service, name_constraints, public_url
from ..crypto_utils import decrypt_secret, encrypt_secret
from . import dns01, jws, validation
from .problem import AcmeProblem, error_object

ACTOR = "acme"
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)*[a-z0-9-]{1,63}(?<!-)$")
REASON_CODES = {0: "unspecified", 1: "key_compromise", 2: "ca_compromise", 3: "affiliation_changed",
                4: "superseded", 5: "cessation_of_operation", 6: "certificate_hold",
                9: "privilege_withdrawn", 10: "aa_compromise"}
CHALLENGE_TYPES = ("http-01", "dns-01")


def parse_challenge_types(raw):
    """`ACME_CHALLENGE_TYPES` → tuple in canonical order; ValueError on junk."""
    wanted = [t.strip().lower() for t in (raw or "").split(",") if t.strip()]
    unknown = [t for t in wanted if t not in CHALLENGE_TYPES]
    if unknown or not wanted:
        raise ValueError(f"ACME_CHALLENGE_TYPES must list one or both of {', '.join(CHALLENGE_TYPES)}, got {raw!r}.")
    return tuple(t for t in CHALLENGE_TYPES if t in wanted)


def challenge_types():
    return parse_challenge_types(current_app.config.get("ACME_CHALLENGE_TYPES") or "http-01,dns-01")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def rfc3339(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


# --- URLs ------------------------------------------------------------------

def acme_url(endpoint, ca_id, **values):
    """Absolute URL of an ACME endpoint: ACME_BASE_URL + path when configured,
    else the request's own scheme/host (ProxyFix applies)."""
    base = current_app.config.get("ACME_BASE_URL")
    if base:
        return base.rstrip("/") + url_for(endpoint, ca_id=ca_id, **values)
    return url_for(endpoint, ca_id=ca_id, _external=True, **values)


def directory(ca):
    return {
        "newNonce": acme_url("acme.new_nonce", ca.id),
        "newAccount": acme_url("acme.new_account", ca.id),
        "newOrder": acme_url("acme.new_order", ca.id),
        "revokeCert": acme_url("acme.revoke_cert", ca.id),
        "keyChange": acme_url("acme.key_change", ca.id),
        "meta": {
            "externalAccountRequired": bool(ca.acme_require_eab),
            "website": public_url.public_scheme() + "://" + public_url.public_host() + url_for("ca.detail", ca_id=ca.id),
        },
    }


# --- nonces ----------------------------------------------------------------

def issue_nonce():
    value = jws.b64url_encode(secrets.token_bytes(16))
    db.session.add(AcmeNonce(value=value))
    db.session.commit()
    return value


def consume_nonce(value):
    """True when the nonce existed (and is now spent) and is not stale."""
    if not isinstance(value, str) or len(value) > 64:
        return False
    row = db.session.get(AcmeNonce, value)
    if row is None:
        return False
    fresh = row.created_at >= utcnow() - timedelta(minutes=int(current_app.config.get("ACME_NONCE_LIFETIME_MINUTES", 60)))
    db.session.delete(row)
    db.session.commit()
    return fresh


# --- accounts --------------------------------------------------------------

def account_url(ca_id, account_id):
    return acme_url("acme.account", ca_id, account_id=account_id)


def account_for_kid(ca, kid):
    """Resolve a `kid` header to a live account of this CA's directory."""
    prefix = acme_url("acme.account", ca.id, account_id=0)[:-1]
    if not kid.startswith(prefix) or not kid[len(prefix):].isdigit():
        raise AcmeProblem("accountDoesNotExist", "Unknown account URL.")
    account = db.session.get(AcmeAccount, int(kid[len(prefix):]))
    if account is None or account.ca_id != ca.id or kid != account_url(ca.id, account.id):
        raise AcmeProblem("accountDoesNotExist", "Unknown account URL.")
    if account.status != "valid":
        raise AcmeProblem("unauthorized", f"Account is {account.status}.")
    return account


def account_dict(ca, account):
    return {"status": account.status, "contact": account.contact,
            "orders": acme_url("acme.account_orders", ca.id, account_id=account.id)}


def _validate_contacts(contact):
    if contact is None:
        return []
    if not isinstance(contact, list) or not all(isinstance(c, str) for c in contact):
        raise AcmeProblem("malformed", "'contact' must be a list of URLs.")
    for c in contact:
        if not c.startswith("mailto:") or "@" not in c or len(c) > 254:
            raise AcmeProblem("unsupportedContact", f"Unsupported contact {c!r}: only mailto: URLs are accepted.")
    return contact


def new_account(ca, verified, url):
    """newAccount (§7.3). Returns (account, created)."""
    payload = verified.payload or {}
    tp = jws.thumbprint(verified.jwk)
    existing = AcmeAccount.query.filter_by(ca_id=ca.id, thumbprint=tp).first()
    if payload.get("onlyReturnExisting"):
        if existing is None:
            raise AcmeProblem("accountDoesNotExist", "No account is registered for this key.")
        if existing.status != "valid":
            raise AcmeProblem("unauthorized", f"Account is {existing.status}.")
        existing.last_seen_at = utcnow()
        return existing, False
    if existing is not None:
        if existing.status != "valid":
            raise AcmeProblem("unauthorized", f"Account is {existing.status}.")
        existing.last_seen_at = utcnow()
        return existing, False
    contact = _validate_contacts(payload.get("contact"))
    eab_row = None
    eab = payload.get("externalAccountBinding")
    if eab is not None:
        kid = _eab_kid(eab)
        eab_row = AcmeEabKey.query.filter_by(kid=kid).first()
        if eab_row is None or eab_row.ca_id != ca.id or eab_row.revoked:
            raise AcmeProblem("unauthorized", "Unknown or revoked external account binding key.")
        if eab_row.used_at is not None:
            raise AcmeProblem("unauthorized", "This external account binding key has already been used.")
        mac_key = jws.b64url_decode(decrypt_secret(eab_row.hmac_key_enc, current_app.config["MASTER_PASSPHRASE"]))
        jws.verify_eab(eab, mac_key, url, verified.jwk)
    elif ca.acme_require_eab:
        raise AcmeProblem("externalAccountRequired",
                          "This CA requires an external account binding: ask an administrator for an EAB key id and MAC key.")
    account = AcmeAccount(ca_id=ca.id, jwk_json=json.dumps(verified.jwk, separators=(",", ":"), sort_keys=True),
                          thumbprint=tp, contact_json=json.dumps(contact) if contact else None,
                          eab_key_id=eab_row.id if eab_row else None, last_seen_at=utcnow())
    db.session.add(account)
    if eab_row is not None:
        eab_row.used_at = utcnow()
    db.session.flush()
    audit_service.log_action("acme_account_created", target_type="acme_account", target_id=account.id, actor=ACTOR,
                             details={"ca_id": ca.id, "contact": contact, "eab_kid": eab_row.kid if eab_row else None,
                                      "thumbprint": tp})
    return account, True


def _eab_kid(eab):
    try:
        protected = json.loads(jws.b64url_decode(eab["protected"]))
        kid = protected.get("kid")
    except (KeyError, TypeError, ValueError, AcmeProblem):
        raise AcmeProblem("malformed", "externalAccountBinding is malformed.")
    if not isinstance(kid, str) or not kid:
        raise AcmeProblem("malformed", "externalAccountBinding has no 'kid'.")
    return kid


def update_account(ca, account, payload):
    """POST to the account URL: contact update or deactivation (§7.3.2, §7.3.6)."""
    if payload.get("status") == "deactivated":
        account.status = "deactivated"
        for order in account.orders.filter(AcmeOrder.status.in_(("pending", "ready", "processing"))).all():
            order.status = "invalid"
            order.error_json = json.dumps(error_object("unauthorized", "Account deactivated."))
        audit_service.log_action("acme_account_deactivated", target_type="acme_account", target_id=account.id,
                                 actor=ACTOR, details={"ca_id": ca.id})
        return account
    if "contact" in payload:
        contact = _validate_contacts(payload.get("contact"))
        account.contact_json = json.dumps(contact) if contact else None
    account.last_seen_at = utcnow()
    return account


def change_key(ca, account, inner_body, key_change_url):
    """keyChange (§7.3.5): the outer JWS is signed by the current key (kid); the
    payload is an inner JWS signed by the new key with {account, oldKey}."""
    inner = jws.verify(inner_body, key_change_url, lambda kid: None, allow_jwk=True, allow_kid=False, require_nonce=False)
    if not inner.payload or inner.payload.get("account") != account_url(ca.id, account.id):
        raise AcmeProblem("malformed", "Inner JWS 'account' does not name this account.")
    if inner.payload.get("oldKey") != account.jwk:
        raise AcmeProblem("malformed", "Inner JWS 'oldKey' does not match the account's current key.")
    new_tp = jws.thumbprint(inner.jwk)
    clash = AcmeAccount.query.filter_by(ca_id=ca.id, thumbprint=new_tp).first()
    if clash is not None and clash.id != account.id:
        raise AcmeProblem("malformed", "The new key already belongs to another account.", status=409)
    account.jwk_json = json.dumps(inner.jwk, separators=(",", ":"), sort_keys=True)
    account.thumbprint = new_tp
    audit_service.log_action("acme_key_changed", target_type="acme_account", target_id=account.id, actor=ACTOR,
                             details={"ca_id": ca.id, "thumbprint": new_tp})
    return account


# --- orders ----------------------------------------------------------------

def _parse_identifiers(raw, ca):
    if not isinstance(raw, list) or not raw:
        raise AcmeProblem("malformed", "'identifiers' must be a non-empty list.")
    seen, identifiers = set(), []
    for item in raw:
        if not isinstance(item, dict):
            raise AcmeProblem("malformed", "Each identifier must be an object.")
        typ, value = item.get("type"), item.get("value")
        if typ != "dns":
            raise AcmeProblem("unsupportedIdentifier", f"Identifier type {typ!r} is not supported (only dns).")
        if not isinstance(value, str):
            raise AcmeProblem("malformed", "Identifier value must be a string.")
        value = value.strip().lower().rstrip(".")
        base = value[2:] if value.startswith("*.") else value
        if base != value:                       # wildcard (3.6.0): one leading label, dns-01 only
            if not ca.acme_allow_wildcards:
                raise AcmeProblem("rejectedIdentifier", f"Wildcard identifier {value!r}: this CA does not allow wildcard names.")
            if "dns-01" not in challenge_types():
                raise AcmeProblem("rejectedIdentifier", f"Wildcard identifier {value!r} needs dns-01, which this server does not offer (ACME_CHALLENGE_TYPES).")
        if "*" in base or not _HOSTNAME.match(base) or re.match(r"^\d+\.\d+\.\d+\.\d+$", base):
            raise AcmeProblem("rejectedIdentifier", f"{value!r} is not a valid DNS identifier.")
        if value not in seen:
            seen.add(value)
            identifiers.append({"type": "dns", "value": value})
    try:
        name_constraints.enforce(ca, {}, [f"DNS:{i['value']}" for i in identifiers])
    except ValueError as exc:
        raise AcmeProblem("rejectedIdentifier", str(exc))
    if len(identifiers) > int(current_app.config.get("ACME_MAX_IDENTIFIERS", 100)):
        raise AcmeProblem("rejectedIdentifier", "Too many identifiers in one order.")
    return identifiers


def new_order(ca, account, payload):
    identifiers = _parse_identifiers((payload or {}).get("identifiers"), ca)
    now = utcnow()
    expires = now + timedelta(hours=int(current_app.config.get("ACME_ORDER_LIFETIME_HOURS", 168)))
    order = AcmeOrder(account_id=account.id, ca_id=ca.id, identifiers_json=json.dumps(identifiers), expires=expires)
    db.session.add(order)
    db.session.flush()
    offered = challenge_types()
    for ident in identifiers:
        wildcard = ident["value"].startswith("*.")
        # §7.1.4: an authorization names the base domain, never the wildcard.
        authz = AcmeAuthorization(order_id=order.id, account_id=account.id, ca_id=ca.id, identifier_type="dns",
                                  identifier_value=ident["value"][2:] if wildcard else ident["value"],
                                  wildcard=wildcard, expires=expires)
        db.session.add(authz)
        db.session.flush()
        for typ in (("dns-01",) if wildcard else offered):
            db.session.add(AcmeChallenge(authorization_id=authz.id, type=typ,
                                         token=jws.b64url_encode(secrets.token_bytes(32))))
    db.session.flush()
    account.last_seen_at = now
    audit_service.log_action("acme_order_created", target_type="acme_order", target_id=order.id, actor=ACTOR,
                             details={"ca_id": ca.id, "account_id": account.id,
                                      "identifiers": [i["value"] for i in identifiers]})
    return order


def refresh_order(order, now=None):
    """Derive the order status from its authorizations and expiry (§7.1.6)."""
    now = now or utcnow()
    if order.status in ("valid", "invalid"):
        return order
    if order.expires <= now:
        order.status = "invalid"
        order.error_json = order.error_json or json.dumps(error_object("malformed", "Order expired."))
        return order
    statuses = [_refresh_authz(a, now).status for a in order.authorizations]
    if any(s in ("invalid", "expired", "deactivated") for s in statuses):
        order.status = "invalid"
        order.error_json = order.error_json or json.dumps(error_object("unauthorized", "An authorization failed."))
    elif statuses and all(s == "valid" for s in statuses) and order.status == "pending":
        order.status = "ready"
    return order


def _refresh_authz(authz, now, attempt=False):
    """Expire a stale authorization; with `attempt`, run the next due dns-01
    lookup of a `processing` challenge (polls of the authorization or the
    challenge drive the retries; order polls only read)."""
    if authz.status == "pending" and authz.expires <= now:
        authz.status = "expired"
    elif authz.status == "pending" and attempt:
        for challenge in authz.challenges:
            if (challenge.type == "dns-01" and challenge.status == "processing"
                    and challenge.next_attempt_at is not None and challenge.next_attempt_at <= now):
                _attempt_dns01(authz.ca_id, authz.account, challenge, now)
                refresh_order(authz.order, now)
                break
    return authz


def order_dict(ca, order):
    d = {"status": order.status, "expires": rfc3339(order.expires), "identifiers": order.identifiers,
         "authorizations": [acme_url("acme.authorization", ca.id, authz_id=a.id) for a in order.authorizations],
         "finalize": acme_url("acme.finalize", ca.id, order_id=order.id)}
    if order.certificate_id and order.status == "valid":
        d["certificate"] = acme_url("acme.certificate", ca.id, cert_id=order.certificate_id)
    if order.error:
        d["error"] = order.error
    return d


def authz_dict(ca, authz):
    d = {"identifier": {"type": authz.identifier_type, "value": authz.identifier_value},
         "status": authz.status, "expires": rfc3339(authz.expires),
         "challenges": [challenge_dict(ca, c) for c in authz.challenges]}
    if authz.wildcard:
        d["wildcard"] = True
    return d


def challenge_dict(ca, challenge):
    d = {"type": challenge.type, "url": acme_url("acme.challenge", ca.id, challenge_id=challenge.id),
         "status": challenge.status, "token": challenge.token}
    if challenge.validated_at:
        d["validated"] = rfc3339(challenge.validated_at)
    if challenge.error:
        d["error"] = challenge.error
    return d


def load_order(ca, account, order_id):
    order = db.session.get(AcmeOrder, order_id)
    if order is None or order.ca_id != ca.id or order.account_id != account.id:
        raise AcmeProblem("malformed", "Unknown order.", status=404)
    return refresh_order(order)


def load_authz(ca, account, authz_id):
    authz = db.session.get(AcmeAuthorization, authz_id)
    if authz is None or authz.ca_id != ca.id or authz.account_id != account.id:
        raise AcmeProblem("malformed", "Unknown authorization.", status=404)
    _refresh_authz(authz, utcnow(), attempt=True)
    return authz


def load_challenge(ca, account, challenge_id):
    challenge = db.session.get(AcmeChallenge, challenge_id)
    if challenge is None:
        raise AcmeProblem("malformed", "Unknown challenge.", status=404)
    authz = challenge.authorization
    if authz.ca_id != ca.id or authz.account_id != account.id:
        raise AcmeProblem("malformed", "Unknown challenge.", status=404)
    _refresh_authz(authz, utcnow(), attempt=True)
    return challenge


def deactivate_authz(authz):
    if authz.status == "pending":
        authz.status = "deactivated"
        refresh_order(authz.order)
    return authz


# --- challenges --------------------------------------------------------------

def respond_challenge(ca, account, challenge):
    """The client says the challenge is provisioned (§7.5.1): validate now."""
    authz = challenge.authorization
    now = utcnow()
    _refresh_authz(authz, now)
    if challenge.status != "pending" or authz.status != "pending":
        return challenge            # idempotent: return the current state
    if authz.order.expires <= now:
        refresh_order(authz.order, now)
        raise AcmeProblem("malformed", "The order has expired.")
    challenge.status = "processing"
    if challenge.type == "dns-01":
        _attempt_dns01(ca.id, account, challenge, now)
    else:
        expected = jws.key_authorization(challenge.token, account.jwk)
        ok, err_type, detail = validation.fetch_http01(authz.identifier_value, challenge.token, expected)
        _settle(ca.id, account, challenge, now, ok, err_type, detail)
    refresh_order(authz.order, now)
    return challenge


def _settle(ca_id, account, challenge, now, ok, err_type, detail, extra=None):
    """Final state of a challenge and its authorization, with the audit row."""
    authz = challenge.authorization
    details = {"ca_id": ca_id, "account_id": account.id, "identifier": authz.display_identifier, "type": challenge.type}
    details.update(extra or {})
    if ok:
        challenge.status = "valid"
        challenge.validated_at = now
        challenge.error_json = None
        authz.status = "valid"
        audit_service.log_action("acme_challenge_validated", target_type="acme_order", target_id=authz.order_id,
                                 actor=ACTOR, details=details)
    else:
        challenge.status = "invalid"
        challenge.error_json = json.dumps(error_object(err_type, detail))
        authz.status = "invalid"
        details.update({"error": err_type, "detail": detail})
        audit_service.log_action("acme_challenge_failed", target_type="acme_order", target_id=authz.order_id,
                                 actor=ACTOR, details=details)


def _attempt_dns01(ca_id, account, challenge, now):
    """One dns-01 lookup (3.6.0). Success settles the authorization; a miss
    keeps the challenge `processing` and schedules the next attempt — the
    client's polls run it — until ACME_DNS01_MAX_ATTEMPTS or the
    authorization's expiry, when the challenge fails with the last error."""
    authz = challenge.authorization
    expected = dns01.txt_value(jws.key_authorization(challenge.token, account.jwk))
    ok, err_type, detail = dns01.validate(authz.identifier_value, expected)
    challenge.attempts = (challenge.attempts or 0) + 1
    limit = max(1, int(current_app.config.get("ACME_DNS01_MAX_ATTEMPTS", 10)))
    retry = max(1, int(current_app.config.get("ACME_DNS01_RETRY_SECONDS", 10)))
    extra = {"attempts": challenge.attempts, "resolvers": current_app.config.get("ACME_DNS_RESOLVERS") or "system"}
    if ok:
        challenge.next_attempt_at = None
        _settle(ca_id, account, challenge, now, True, None, None, extra)
    elif challenge.attempts < limit and authz.expires > now + timedelta(seconds=retry):
        challenge.next_attempt_at = now + timedelta(seconds=retry)
        challenge.error_json = json.dumps(error_object(err_type, f"Attempt {challenge.attempts}/{limit}: {detail}"))
    else:
        challenge.next_attempt_at = None
        _settle(ca_id, account, challenge, now, False, err_type,
                f"Gave up after {challenge.attempts} attempt(s): {detail}", extra)


# --- finalize / certificate ---------------------------------------------------

def _acme_profile(ca):
    from .. import profile_service
    profile = ca.acme_profile if ca.acme_profile_id else None
    if profile is None:
        profile = profile_service.lookup("custom")
    if profile is None or not profile.enabled:
        raise AcmeProblem("serverInternal", "The CA's ACME profile is missing or disabled.", status=500)
    return profile


def finalize(ca, account, order, payload):
    order = refresh_order(order)
    if order.status == "valid":
        return order
    if order.status != "ready":
        raise AcmeProblem("orderNotReady", f"Order is {order.status}; every authorization must be valid first.")
    csr_b64 = (payload or {}).get("csr")
    if not isinstance(csr_b64, str):
        raise AcmeProblem("badCSR", "'csr' is missing.")
    try:
        csr = x509.load_der_x509_csr(jws.b64url_decode(csr_b64))
    except (ValueError, AcmeProblem):
        raise AcmeProblem("badCSR", "The CSR is not valid DER.")
    if not csr.is_signature_valid:
        raise AcmeProblem("badCSR", "The CSR signature is invalid.")
    wanted = {i["value"] for i in order.identifiers}
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = {n.lower().rstrip(".") for n in san.get_values_for_type(x509.DNSName)}
        others = [g for g in san if not isinstance(g, x509.DNSName)]
    except x509.ExtensionNotFound:
        dns, others = set(), []
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attrs[0].value.lower().rstrip(".") if cn_attrs else None
    if others:
        raise AcmeProblem("badCSR", "The CSR carries subject alternative names that are not DNS names.")
    if cn and cn not in wanted:
        raise AcmeProblem("badCSR", f"CSR common name {cn!r} is not one of the order's identifiers.")
    if not dns and cn:
        dns = {cn}
    if dns != wanted:
        raise AcmeProblem("badCSR", "The CSR's DNS names do not match the order's identifiers exactly.")
    profile = _acme_profile(ca)
    days = int(current_app.config.get("ACME_DEFAULT_VALIDITY_DAYS", 90))
    if profile.max_validity_days and days > profile.max_validity_days:
        days = profile.max_validity_days
    order.status = "processing"
    order.csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    db.session.commit()
    try:
        csr_model = csr_service.import_csr(order.csr_pem, created_by=None, profile_id=profile.id)
        csr_model.common_name = cn or sorted(wanted)[0]
        csr_model.ca_id = ca.id
        db.session.commit()
        ocsp_url, crl_dp_url = public_url.issuance_urls(ca.id)
        certificate = cert_service.sign_csr(csr_model, ca, days, current_app.config["MASTER_PASSPHRASE"],
                                            ocsp_url=ocsp_url, crl_dp_url=crl_dp_url, signed_by=None, profile=profile)
    except ValueError as exc:
        db.session.rollback()
        order = db.session.get(AcmeOrder, order.id)
        order.status = "invalid"
        order.error_json = json.dumps(error_object("badCSR", str(exc)))
        audit_service.log_action("acme_issuance_failed", target_type="acme_order", target_id=order.id, actor=ACTOR,
                                 details={"ca_id": ca.id, "account_id": account.id, "error": str(exc)})
        db.session.commit()
        raise AcmeProblem("badCSR", str(exc))
    certificate.issuance_source = "acme"
    certificate.acme_account_id = account.id
    order.certificate_id = certificate.id
    order.status = "valid"
    order.finalized_at = utcnow()
    audit_service.log_action("acme_certificate_issued", target_type="certificate", target_id=certificate.id, actor=ACTOR,
                             details={"ca_id": ca.id, "account_id": account.id, "order_id": order.id,
                                      "common_name": certificate.common_name, "identifiers": sorted(wanted),
                                      "profile": profile.key, "validity_days": days})
    db.session.commit()
    return order


def certificate_for(ca, account, cert_id):
    cert = db.session.get(Certificate, cert_id)
    if cert is None or cert.ca_id != ca.id or cert.acme_account_id != account.id:
        raise AcmeProblem("malformed", "Unknown certificate.", status=404)
    return cert


def certificate_chain_pem(cert):
    return cert_service.export_fullchain_pem(cert)


# --- revocation ----------------------------------------------------------------

def revoke(ca, verified, payload):
    """revokeCert (§7.6): signed by the account that got the certificate, or by
    the certificate's own key (jwk)."""
    payload = payload or {}
    try:
        der = jws.b64url_decode(payload.get("certificate", ""))
        presented = x509.load_der_x509_certificate(der)
    except (ValueError, AcmeProblem, TypeError):
        raise AcmeProblem("malformed", "'certificate' is not valid DER.")
    cert = Certificate.query.filter_by(serial_number=format(presented.serial_number, "x")).first()
    if cert is None or cert.ca_id != ca.id or x509.load_pem_x509_certificate(cert.certificate_pem.encode()) != presented:
        raise AcmeProblem("unauthorized", "This certificate was not issued by this CA.")
    if verified.account is not None:
        if cert.acme_account_id != verified.account.id:
            raise AcmeProblem("unauthorized", "The certificate does not belong to this account.")
    else:
        cert_key = presented.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        req_key = verified.public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if cert_key != req_key:
            raise AcmeProblem("unauthorized", "The request is not signed with the certificate's key.")
    reason_code = payload.get("reason", 0)
    if not isinstance(reason_code, int) or reason_code not in REASON_CODES:
        raise AcmeProblem("badRevocationReason", f"Unsupported revocation reason {reason_code!r}.",
                          extra={"reasons": sorted(REASON_CODES)})
    if cert.is_revoked:
        raise AcmeProblem("alreadyRevoked", "The certificate is already revoked.")
    crl_service.revoke_certificate(cert.id, REASON_CODES[reason_code], current_app.config["MASTER_PASSPHRASE"],
                                   commit=False, refresh=False)
    audit_service.log_action("acme_certificate_revoked", target_type="certificate", target_id=cert.id, actor=ACTOR,
                             details={"ca_id": ca.id, "reason": REASON_CODES[reason_code],
                                      "by": "account" if verified.account else "certificate-key",
                                      "account_id": verified.account.id if verified.account else None})
    db.session.commit()
    try:
        crl_service.refresh_crl(ca, current_app.config["MASTER_PASSPHRASE"])
        db.session.commit()
    except Exception:   # a CRL refresh failure must not undo the revocation (G10-1)
        db.session.rollback()
    return cert


# --- EAB keys (admin) -------------------------------------------------------------

def create_eab_key(ca, name=None, created_by=None):
    """Issue an EAB key: returns (row, mac_key_b64url). The MAC key is shown once."""
    mac_key = secrets.token_bytes(32)
    mac_b64 = jws.b64url_encode(mac_key)
    row = AcmeEabKey(ca_id=ca.id, kid=jws.b64url_encode(secrets.token_bytes(12)),
                     hmac_key_enc=encrypt_secret(mac_b64, current_app.config["MASTER_PASSPHRASE"]),
                     name=(name or "").strip()[:100] or None, created_by=created_by)
    db.session.add(row)
    db.session.flush()
    audit_service.log_action("create_acme_eab_key", target_type="acme_eab_key", target_id=row.id,
                             details={"ca_id": ca.id, "kid": row.kid, "name": row.name},
                             actor=None if has_request_context() else "cli")
    return row, mac_b64


def revoke_eab_key(row, actor=None):
    row.revoked = True
    if actor is None and not has_request_context():
        actor = "cli"
    audit_service.log_action("revoke_acme_eab_key", target_type="acme_eab_key", target_id=row.id,
                             details={"ca_id": row.ca_id, "kid": row.kid}, actor=actor)
    return row


# --- maintenance ------------------------------------------------------------------

def maintain(now=None):
    """Scheduler job (hourly): expire stale orders/authorizations, prune nonces."""
    now = now or utcnow()
    expired_orders = 0
    for order in AcmeOrder.query.filter(AcmeOrder.status.in_(("pending", "ready", "processing")),
                                        AcmeOrder.expires <= now).all():
        order.status = "invalid"
        order.error_json = order.error_json or json.dumps(error_object("malformed", "Order expired."))
        expired_orders += 1
    expired_authz = AcmeAuthorization.query.filter(AcmeAuthorization.status == "pending",
                                                   AcmeAuthorization.expires <= now).update(
        {"status": "expired"}, synchronize_session=False)
    cutoff = now - timedelta(minutes=int(current_app.config.get("ACME_NONCE_LIFETIME_MINUTES", 60)))
    pruned = AcmeNonce.query.filter(AcmeNonce.created_at < cutoff).delete(synchronize_session=False)
    db.session.commit()
    return {"expired_orders": expired_orders, "expired_authorizations": int(expired_authz or 0), "pruned_nonces": int(pruned or 0)}
