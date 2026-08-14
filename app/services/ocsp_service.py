import threading
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from ..models.certificate import Certificate
from ..models.ca import CertificateAuthority
from .keybackend import backend_for_ca, OcspResponseSpec

OCSP_RESPONSE_VALIDITY_HOURS = 24


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
    ocsp_req = ocsp.load_der_ocsp_request(ocsp_request_der)
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
    cache_key = (ca.id, serial_hex, bool(subject.is_revoked), algorithm.name)
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
    der = backend_for_ca(ca).sign_ocsp(spec, ca, secret=passphrase)
    _response_cache.put(cache_key, der, cache_ttl)
    return der
