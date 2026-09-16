"""Software key backend — today's behaviour (pyca/cryptography + Fernet).

Keys are Fernet-encrypted under MASTER_PASSPHRASE and decrypted into memory to
sign. This is the default backend; output is byte-identical to the pre-backend
code because the pyca builders are used unchanged.
"""
import hashlib
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp

from flask import current_app

from .base import KeyBackend, OcspResponseSpec
from ..crypto_utils import encrypt_private_key, decrypt_private_key, generate_key, hash_for_key


class SoftwareBackend(KeyBackend):
    name = "software"

    def __init__(self):
        # C1: cache decrypted CA keys for the OCSP hot path so an unauthenticated
        # OCSP flood doesn't run 600k-PBKDF2 per request. Keyed by ca.id, guarded
        # by a fingerprint of the ciphertext so a rotated/re-imported key evicts.
        # Only OCSP uses this; cert/CRL signing decrypts fresh each call.
        self._ocsp_key_cache = {}
        self._ocsp_key_lock = threading.Lock()

    def _secret(self, secret):
        return secret if secret is not None else current_app.config["MASTER_PASSPHRASE"]

    def generate_ca_key(self, key_type, key_size, *, label=None, secret=None):
        key = generate_key(key_type, key_size)  # RSA, EC, Ed25519, Ed448 (F5)
        return key.public_key(), encrypt_private_key(key, self._secret(secret))

    def import_ca_key(self, private_key, *, label=None, secret=None):
        return encrypt_private_key(private_key, self._secret(secret))

    def load_public_key(self, ca):
        return x509.load_pem_x509_certificate(ca.certificate_pem.encode()).public_key()

    def _key(self, ca, secret):
        return decrypt_private_key(ca.private_key_enc, self._secret(secret))

    def _ocsp_key(self, ca, secret):
        """Cached decrypt for OCSP (C1). TTL 0 disables the cache."""
        try:
            ttl = current_app.config.get("OCSP_KEY_CACHE_TTL_SECONDS", 300)
        except RuntimeError:
            ttl = 0
        if ttl <= 0:
            return self._key(ca, secret)
        fingerprint = hashlib.sha256(ca.private_key_enc).digest()
        now = time.monotonic()
        with self._ocsp_key_lock:
            entry = self._ocsp_key_cache.get(ca.id)
            if entry and entry[0] == fingerprint and entry[2] > now:
                return entry[1]
        key = self._key(ca, secret)
        with self._ocsp_key_lock:
            self._ocsp_key_cache[ca.id] = (fingerprint, key, time.monotonic() + ttl)
        return key

    def sign_certificate(self, builder, ca, *, secret=None) -> bytes:
        key = self._key(ca, secret)
        cert = builder.sign(key, hash_for_key(key))
        return cert.public_bytes(serialization.Encoding.DER)

    def sign_crl(self, builder, ca, *, secret=None) -> bytes:
        key = self._key(ca, secret)
        crl = builder.sign(key, hash_for_key(key))
        return crl.public_bytes(serialization.Encoding.DER)

    def sign_ocsp(self, spec: OcspResponseSpec, ca, *, secret=None) -> bytes:
        issuer = x509.load_der_x509_certificate(spec.issuer_cert_der)
        subject = x509.load_der_x509_certificate(spec.subject_cert_der)
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=subject,
            issuer=issuer,
            algorithm=spec.algorithm,
            cert_status=spec.cert_status,
            this_update=spec.this_update,
            next_update=spec.next_update,
            revocation_time=spec.revocation_time,
            revocation_reason=spec.revocation_reason,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, issuer)
        key = self._ocsp_key(ca, secret)
        resp = builder.sign(key, hash_for_key(key))
        return resp.public_bytes(serialization.Encoding.DER)

    def can_export(self) -> bool:
        return True
