import hashlib
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from ..extensions import db
from ..models.certificate import Certificate
from ..models.ca import CertificateAuthority
from .keybackend import backend_for_ca, OcspResponseSpec
from . import crypto_utils
from .policy import bounded_not_after

OCSP_RESPONSE_VALIDITY_HOURS = 24
RESPONDER_CN_SUFFIX = " OCSP Responder"

logger = logging.getLogger(__name__)


class MalformedOcspRequest(ValueError):
    """The request body is not a DER OCSPRequest (G8-2). The public route
    answers with an OCSP-level `malformedRequest` at HTTP 200 (RFC 6960
    §4.2.1) instead of a 500."""


def malformed_response() -> bytes:
    """DER-encoded unsigned OCSPResponse with status malformedRequest."""
    return ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.MALFORMED_REQUEST
    ).public_bytes(serialization.Encoding.DER)


class _OcspResponseCache:
    """Short-TTL cache of signed OCSP responses (PKI-2).

    Keyed by (ca_id, serial, is_revoked, hash-alg). The status is part of the
    key and re-read from the DB on every request, so a revoked certificate is
    never answered GOOD from cache — the stale GOOD entry is simply never
    matched again. Bounds the per-request asymmetric signing an unauthenticated
    flood would otherwise cause.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._entries = {}

    def get(self, key, ttl):
        if ttl <= 0:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            der, expires_at = entry
            if now >= expires_at:
                del self._entries[key]
                return None
            return der

    def put(self, key, der, ttl):
        if ttl <= 0:
            return
        with self._lock:
            self._entries[key] = (der, time.monotonic() + ttl)

    def clear(self):
        with self._lock:
            self._entries.clear()


_response_cache = _OcspResponseCache()

_ALLOWED_OCSP_HASHES = (
    hashes.SHA1, hashes.SHA224, hashes.SHA256, hashes.SHA384, hashes.SHA512,
)


def _request_hash_algorithm(ocsp_req):
    """Mirror the request's CertID hash algorithm in the response.

    Clients match responses to requests by CertID, which includes the hash
    algorithm. openssl defaults to SHA-1, and always answering with SHA-256
    made such clients report "no status found". Falls back to SHA-256 for
    unsupported algorithms.
    """
    try:
        algorithm = ocsp_req.hash_algorithm
        if isinstance(algorithm, _ALLOWED_OCSP_HASHES):
            return algorithm
    except Exception:
        pass
    return hashes.SHA256()

_REVOCATION_REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}


# --- delegated OCSP responder (F7, 2.24.0) -------------------------------------
#
# With OCSP_DELEGATED_RESPONDER=true each CA signs a short-lived responder
# certificate (KU digitalSignature, EKU OCSPSigning, id-pkix-ocsp-nocheck) and
# responses are signed by *that* key, not the CA's: the CA key (token or Fernet
# blob) is touched once per OCSP_RESPONDER_VALIDITY_DAYS instead of per
# response, and the hot-path key cache holds the responder key only. The
# scheduler renews responders OCSP_RESPONDER_RENEW_BEFORE_DAYS before expiry;
# the request path renews lazily when it finds none / an expired one, and
# falls back to the direct byKey path on any failure.

_responder_key_cache = {}   # ca_id -> (ciphertext fingerprint, key, expires_at)
_responder_key_lock = threading.Lock()


def _cfg(key, default):
    try:
        from flask import current_app
        return current_app.config.get(key, default)
    except RuntimeError:
        return default


def delegated_enabled():
    return bool(_cfg("OCSP_DELEGATED_RESPONDER", False))


def responder_certificate(ca):
    if not ca.ocsp_responder_cert_pem:
        return None
    try:
        return x509.load_pem_x509_certificate(ca.ocsp_responder_cert_pem.encode())
    except ValueError:
        return None


def responder_status(ca, now=None):
    """Dict describing the CA's responder certificate, or None when it has none."""
    cert = responder_certificate(ca)
    if cert is None:
        return None
    now = now or datetime.now(timezone.utc)
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    try:
        cert.verify_directly_issued_by(ca_cert)
        issued_by_ca = True
    except Exception:
        issued_by_ca = False
    return {
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "days_left": (cert.not_valid_after_utc - now).days,
        "valid": issued_by_ca and cert.not_valid_before_utc <= now < cert.not_valid_after_utc,
        "key_type": crypto_utils.key_info(cert.public_key())[0],
    }


def responder_needs_rotation(ca, now=None, renew_before_days=None):
    """True when the CA has no usable responder, or it expires within
    OCSP_RESPONDER_RENEW_BEFORE_DAYS."""
    status = responder_status(ca, now)
    if status is None or not status["valid"]:
        return True
    if renew_before_days is None:
        renew_before_days = int(_cfg("OCSP_RESPONDER_RENEW_BEFORE_DAYS", 7))
    return status["days_left"] < renew_before_days


def ensure_responder(ca, passphrase, *, force=False, now=None):
    """Issue a fresh responder certificate for `ca` when it needs one (or
    `force`). Returns True when a new one was issued. Flushes, does not
    commit — the caller commits together with its audit row."""
    if not ca.has_signing_key:
        raise ValueError("This CA has no private key and cannot issue an OCSP responder certificate.")
    if ca.approval_status == "pending":
        raise ValueError("This CA is awaiting dual-control approval and cannot issue anything yet.")
    if ca.is_revoked:
        raise ValueError("This CA is revoked; its OCSP responder cannot be renewed.")
    now = now or datetime.now(timezone.utc)
    if not force and not responder_needs_rotation(ca, now):
        return False
    validity_days = int(_cfg("OCSP_RESPONDER_VALIDITY_DAYS", 30))
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    key = crypto_utils.generate_key(ca.key_type, ca.key_size)
    not_after = bounded_not_after(now, validity_days, ca.not_after)
    cn = (ca.name or "CA")[:64 - len(RESPONDER_CN_SUFFIX)] + RESPONDER_CN_SUFFIX
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
        .add_extension(x509.OCSPNoCheck(), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value), critical=False)
    )
    cert_der = backend_for_ca(ca).sign_certificate(builder, ca, secret=passphrase)
    ca.ocsp_responder_cert_pem = x509.load_der_x509_certificate(cert_der).public_bytes(
        serialization.Encoding.PEM).decode()
    ca.ocsp_responder_key_enc = crypto_utils.encrypt_private_key(key, passphrase)
    with _responder_key_lock:
        _responder_key_cache.pop(ca.id, None)
    _response_cache.clear()
    db.session.flush()
    return True


def _responder_key(ca, passphrase):
    """Decrypted responder key, cached for OCSP_KEY_CACHE_TTL_SECONDS (the CA
    key is no longer on this path)."""
    ttl = int(_cfg("OCSP_KEY_CACHE_TTL_SECONDS", 300))
    fingerprint = hashlib.sha256(ca.ocsp_responder_key_enc).digest()
    if ttl > 0:
        with _responder_key_lock:
            entry = _responder_key_cache.get(ca.id)
            if entry and entry[0] == fingerprint and entry[2] > time.monotonic():
                return entry[1]
    key = crypto_utils.decrypt_private_key(ca.ocsp_responder_key_enc, passphrase)
    if ttl > 0:
        with _responder_key_lock:
            _responder_key_cache[ca.id] = (fingerprint, key, time.monotonic() + ttl)
    return key


def _delegated_responder(ca, passphrase):
    """(responder_cert, responder_key) when delegation is on and a responder
    is available (renewing lazily if needed), else None → direct path."""
    if not delegated_enabled():
        return None
    try:
        if responder_needs_rotation(ca):
            if not ensure_responder(ca, passphrase):
                return None
            from . import audit_service
            audit_service.log_action("ocsp_responder_rotated", target_type="ca", target_id=ca.id,
                                     details={"trigger": "lazy", **responder_status(ca)}, actor="system")
            db.session.commit()
        return responder_certificate(ca), _responder_key(ca, passphrase)
    except Exception:
        db.session.rollback()
        logger.exception("Delegated OCSP responder unavailable for CA %s; answering with the CA key", ca.id)
        return None


def _unauthorized():
    response = ocsp.OCSPResponseBuilder().build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED
    )
    return response.public_bytes(serialization.Encoding.DER)


def build_ocsp_response(ocsp_request_der: bytes, ca, passphrase: str) -> bytes:
    # A certificate-only CA can never sign a response, and a dual-control
    # pending CA may not yet — return an unsigned UNAUTHORIZED without
    # parsing or decrypting anything (never raise on the public endpoint).
    if not ca.has_signing_key or ca.approval_status == "pending":
        return _unauthorized()

    # C1: parse the request and look up the subject BEFORE decrypting the CA
    # key. The key decryption (600k PBKDF2) only runs once we know we have a
    # real subject to sign a response about.
    try:
        ocsp_req = ocsp.load_der_ocsp_request(ocsp_request_der)
    except ValueError as exc:
        raise MalformedOcspRequest(str(exc)) from exc
    serial_hex = format(ocsp_req.serial_number, "x")
    algorithm = _request_hash_algorithm(ocsp_req)

    # Look up the serial as a leaf certificate this CA issued, then (B3) as a
    # sub-CA this CA issued — a revoked intermediate must get a REVOKED answer.
    subject = Certificate.query.filter_by(serial_number=serial_hex, ca_id=ca.id).first()
    if subject is None:
        subject = CertificateAuthority.query.filter_by(
            serial_number=serial_hex, parent_id=ca.id
        ).first()

    # Unknown serial — return an unsigned UNAUTHORIZED without touching the key.
    if subject is None:
        return _unauthorized()

    # PKI-2: serve a recent signed response from cache when available. The
    # status is part of the key (read fresh above), so a revoked cert is never
    # answered GOOD from cache.
    # F7: the signer is part of the key too (delegated responder serial or the
    # CA key), so toggling delegation or rotating a responder never replays a
    # response signed by the previous signer.
    delegated = _delegated_responder(ca, passphrase)
    signer = format(delegated[0].serial_number, "x") if delegated else "ca-key"
    cache_key = (ca.id, serial_hex, bool(subject.is_revoked), algorithm.name, signer)
    try:
        from flask import current_app
        cache_ttl = current_app.config.get("OCSP_RESPONSE_CACHE_TTL_SECONDS", 60)
    except RuntimeError:
        cache_ttl = 60
    cached = _response_cache.get(cache_key, cache_ttl)
    if cached is not None:
        return cached

    ca_cert_der = x509.load_pem_x509_certificate(
        ca.certificate_pem.encode()
    ).public_bytes(serialization.Encoding.DER)
    subject_cert_der = x509.load_pem_x509_certificate(
        subject.certificate_pem.encode()
    ).public_bytes(serialization.Encoding.DER)

    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=OCSP_RESPONSE_VALIDITY_HOURS)

    if subject.is_revoked:
        cert_status = ocsp.OCSPCertStatus.REVOKED
        revocation_time = subject.revoked_at or now
        revocation_reason = _REVOCATION_REASONS.get(
            subject.revocation_reason, x509.ReasonFlags.unspecified
        )
    else:
        cert_status = ocsp.OCSPCertStatus.GOOD
        revocation_time = None
        revocation_reason = None

    spec = OcspResponseSpec(
        subject_cert_der=subject_cert_der,
        issuer_cert_der=ca_cert_der,
        cert_status=cert_status,
        this_update=now,
        next_update=next_update,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
        algorithm=algorithm,
    )
    if delegated:
        responder_cert, responder_key = delegated
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=x509.load_der_x509_certificate(subject_cert_der),
            issuer=x509.load_der_x509_certificate(ca_cert_der),
            algorithm=algorithm, cert_status=cert_status, this_update=now, next_update=next_update,
            revocation_time=revocation_time, revocation_reason=revocation_reason,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert).certificates([responder_cert])
        der = builder.sign(responder_key, crypto_utils.hash_for_key(responder_key)).public_bytes(
            serialization.Encoding.DER)
    else:
        der = backend_for_ca(ca).sign_ocsp(spec, ca, secret=passphrase)
    _response_cache.put(cache_key, der, cache_ttl)
    return der
