"""SoftHSM / PKCS#11 key backend (A1).

The CA private key lives inside a PKCS#11 token and never enters Python memory.
pyca/cryptography cannot sign with a PKCS#11 key (its builders type-check the
key object), so we reproduce pyca's exact DER a different way:

  1. pyca builds and signs the object with a *throwaway* key of the same
     algorithm. The TBS (to-be-signed) bytes are independent of *which* key
     signs — they depend only on the signature AlgorithmIdentifier
     (sha256WithRSAEncryption / ecdsa-with-SHA256), which the same-algorithm
     throwaway reproduces exactly.
  2. the token signs those TBS bytes with the CA's real key.
  3. asn1crypto reassembles the object with the token's signature swapped in.

Because RSA PKCS#1 v1.5 is deterministic, the DER produced here is
byte-identical to what the software backend produced from the same key — the
differential test in tests/test_softhsm.py asserts exactly that.

Certificates and CRLs use the throwaway TBS-swap above. OCSP is different: pyca
refuses to sign an OCSP response when the signing key differs from the responder
certificate, so the response is assembled directly with asn1crypto. To reproduce
pyca's exact CertID, the CertID is lifted from a throwaway pyca OCSP *request*
rather than recomputed. Covers RSA + EC for certificates, CRLs, OCSP, and CA key
generation/import.
"""
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509 import ocsp

from asn1crypto import x509 as asn1_x509, crl as asn1_crl, ocsp as asn1_ocsp
from asn1crypto import algos, core

from .base import KeyBackend, OcspResponseSpec
from . import pkcs11_session


# NIST curve name (asn1crypto NamedCurve) and pyca curve class by key size.
_EC_CURVE_NAME = {256: "secp256r1", 384: "secp384r1", 521: "secp521r1"}
_EC_CURVE_BY_SIZE = {256: ec.SECP256R1, 384: ec.SECP384R1, 521: ec.SECP521R1}


class Pkcs11Backend(KeyBackend):
    name = "softhsm"

    # -- helpers -------------------------------------------------------------
    def _ca_key_info(self, ca):
        """('RSA', None) or ('EC', curve) from the CA's key_type/key_size
        columns — not the certificate, which does not yet exist while a root
        CA is being self-signed."""
        if ca.key_type == "RSA":
            return "RSA", None
        if ca.key_type == "EC":
            # HSM-1: fail with a clear error (not a raw KeyError) for an EC curve
            # the backend doesn't support — otherwise `keys migrate-to-hsm` would
            # scrub the software key and then brick the CA on first sign.
            curve_cls = _EC_CURVE_BY_SIZE.get(ca.key_size)
            if curve_cls is None:
                raise ValueError(
                    f"EC key on an unsupported curve (size {ca.key_size}); the HSM "
                    "backend supports P-256, P-384, and P-521 only.")
            return "EC", curve_cls()
        raise ValueError("Unsupported CA key type for the HSM backend.")

    def _throwaway_key(self, ca):
        key_type, curve = self._ca_key_info(ca)
        if key_type == "RSA":
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return ec.generate_private_key(curve)

    def _hsm_sign(self, tbs_bytes, ca):
        """Sign TBS bytes inside the token; return the X.509 signatureValue.

        We sign with the single-part RSA mechanism but the *raw* EC mechanism
        over a SHA-256 digest: SoftHSM (and many hardware tokens) implement only
        CKM_ECDSA, not CKM_ECDSA_SHA256. The certificate's algorithm is
        ecdsa-with-SHA256 either way (the software backend also hashes with
        SHA-256), so signing the SHA-256 digest keeps output equivalent.
        """
        import hashlib
        from pkcs11 import ObjectClass, Mechanism
        from pkcs11.util.ec import encode_ecdsa_signature

        key_type, _curve = self._ca_key_info(ca)
        with pkcs11_session.session_scope() as session:
            priv = session.get_key(
                object_class=ObjectClass.PRIVATE_KEY, label=ca.key_label
            )
            if key_type == "RSA":
                # SHA256_RSA_PKCS hashes and signs; the result is the PKCS#1 v1.5
                # signatureValue directly.
                return priv.sign(tbs_bytes, mechanism=Mechanism.SHA256_RSA_PKCS)
            # Raw ECDSA over the SHA-256 digest returns r||s; wrap it in the DER
            # Ecdsa-Sig-Value X.509 wants.
            digest = hashlib.sha256(tbs_bytes).digest()
            raw = priv.sign(digest, mechanism=Mechanism.ECDSA)
            return encode_ecdsa_signature(raw)

    def _reassemble(self, asn1_obj, tbs_field, sig_field, ca):
        """Return DER of asn1_obj with its signature replaced by the token's,
        computed over the (unchanged) TBS bytes. The TBS is signer-independent,
        so this reproduces pyca's exact encoding."""
        tbs = asn1_obj[tbs_field]
        signature = self._hsm_sign(tbs.dump(), ca)
        return asn1_obj.__class__({
            tbs_field: tbs,
            "signature_algorithm": asn1_obj["signature_algorithm"],
            sig_field: signature,
        }).dump()

    def _sig_alg_name(self, ca):
        key_type, _ = self._ca_key_info(ca)
        return "sha256_rsa" if key_type == "RSA" else "sha256_ecdsa"

    @staticmethod
    def _gtime(dt):
        """DER GeneralizedTime in UTC with whole-second precision (RFC 5280
        profile: no fractional seconds, trailing 'Z'). pyca truncates the same
        way, so this keeps output byte-compatible."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return core.GeneralizedTime(dt.astimezone(timezone.utc).replace(microsecond=0))

    def _ocsp_cert_status(self, spec):
        status = spec.cert_status
        if status == ocsp.OCSPCertStatus.GOOD:
            return asn1_ocsp.CertStatus(name="good", value=core.Null())
        if status == ocsp.OCSPCertStatus.REVOKED:
            revoked = {"revocation_time": self._gtime(spec.revocation_time)}
            if spec.revocation_reason is not None:
                revoked["revocation_reason"] = spec.revocation_reason.name
            return asn1_ocsp.CertStatus(
                name="revoked", value=asn1_ocsp.RevokedInfo(revoked)
            )
        return asn1_ocsp.CertStatus(name="unknown", value=core.Null())

    # -- key lifecycle -------------------------------------------------------
    def generate_ca_key(self, key_type, key_size, *, label, secret=None):
        from pkcs11 import KeyType, Attribute
        from pkcs11.util.ec import encode_named_curve_parameters

        with pkcs11_session.session_scope() as session:
            if key_type == "RSA":
                pub, _priv = session.generate_keypair(
                    KeyType.RSA, key_size, store=True, label=label,
                    id=label.encode()[:32],
                    private_template={
                        Attribute.TOKEN: True, Attribute.PRIVATE: True,
                        Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
                        Attribute.SIGN: True,
                    },
                    public_template={Attribute.TOKEN: True, Attribute.VERIFY: True},
                )
                n = int.from_bytes(pub[Attribute.MODULUS], "big")
                e = int.from_bytes(pub[Attribute.PUBLIC_EXPONENT], "big")
                public_key = rsa.RSAPublicNumbers(e, n).public_key()
            elif key_type == "EC":
                params = encode_named_curve_parameters(_EC_CURVE_NAME[key_size])
                pub, _priv = session.generate_keypair(
                    KeyType.EC, key_size, store=True, label=label,
                    id=label.encode()[:32],
                    private_template={
                        Attribute.TOKEN: True, Attribute.PRIVATE: True,
                        Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
                        Attribute.SIGN: True,
                    },
                    public_template={
                        Attribute.TOKEN: True, Attribute.VERIFY: True,
                        Attribute.EC_PARAMS: params,
                    },
                )
                from pkcs11.util.ec import encode_ec_public_key
                spki = encode_ec_public_key(pub)
                public_key = serialization.load_der_public_key(spki)
            else:
                raise ValueError(f"Unsupported key type: {key_type}")

            # Tag both objects with the real SKI (CKA_ID) for interop/lookup.
            try:
                ski = x509.SubjectKeyIdentifier.from_public_key(public_key).digest
                pub[Attribute.ID] = ski
            except Exception:
                pass
        return public_key, label

    def import_ca_key(self, private_key, *, label, secret=None):
        from pkcs11 import Attribute
        from pkcs11.util.rsa import decode_rsa_private_key
        from pkcs11.util.ec import decode_ec_private_key

        der = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        if isinstance(private_key, rsa.RSAPrivateKey):
            template = decode_rsa_private_key(der)
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            template = decode_ec_private_key(der)
        else:
            raise ValueError("Unsupported key type for HSM import.")

        template[Attribute.TOKEN] = True
        template[Attribute.LABEL] = label
        template[Attribute.ID] = label.encode()[:32]
        template[Attribute.PRIVATE] = True
        template[Attribute.SENSITIVE] = True
        template[Attribute.EXTRACTABLE] = False  # one-way: cannot be pulled back out
        template[Attribute.SIGN] = True
        with pkcs11_session.session_scope() as session:
            session.create_object(template)
        return label

    def load_public_key(self, ca):
        return x509.load_pem_x509_certificate(ca.certificate_pem.encode()).public_key()

    def verify_signing_key(self, ca):
        """CORE-3: prove the token holds a usable signing key for this CA by
        signing a random nonce and verifying it against the CA certificate's
        public key. Raises on failure — `keys migrate-to-hsm` calls this BEFORE
        scrubbing the software copy, so a silent/partial import can't brick the CA.
        """
        import os
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, ec as _ec

        key_type, _ = self._ca_key_info(ca)
        public_key = self.load_public_key(ca)
        nonce = os.urandom(32)
        signature = self._hsm_sign(nonce, ca)  # signs SHA-256(nonce) in the token
        if key_type == "RSA":
            public_key.verify(signature, nonce, padding.PKCS1v15(), hashes.SHA256())
        else:
            public_key.verify(signature, nonce, _ec.ECDSA(hashes.SHA256()))

    # -- signing -------------------------------------------------------------
    def sign_certificate(self, builder, ca, *, secret=None) -> bytes:
        der = builder.sign(self._throwaway_key(ca), hashes.SHA256()).public_bytes(
            serialization.Encoding.DER)
        return self._reassemble(
            asn1_x509.Certificate.load(der), "tbs_certificate", "signature_value", ca)

    def sign_crl(self, builder, ca, *, secret=None) -> bytes:
        der = builder.sign(self._throwaway_key(ca), hashes.SHA256()).public_bytes(
            serialization.Encoding.DER)
        return self._reassemble(
            asn1_crl.CertificateList.load(der), "tbs_cert_list", "signature", ca)

    def sign_ocsp(self, spec: OcspResponseSpec, ca, *, secret=None) -> bytes:
        # pyca refuses to sign an OCSP response when the signing key differs from
        # the responder cert, so assemble it with asn1crypto. To reproduce pyca's
        # exact CertID (issuer name/key hashes, request-mirrored hash algorithm),
        # lift it from a throwaway pyca OCSP *request* rather than recomputing.
        issuer = x509.load_der_x509_certificate(spec.issuer_cert_der)
        subject = x509.load_der_x509_certificate(spec.subject_cert_der)
        req = ocsp.OCSPRequestBuilder().add_certificate(
            subject, issuer, spec.algorithm).build()
        cert_id = asn1_ocsp.OCSPRequest.load(
            req.public_bytes(serialization.Encoding.DER)
        )["tbs_request"]["request_list"][0]["req_cert"]

        responder_key_hash = x509.SubjectKeyIdentifier.from_public_key(
            issuer.public_key()).digest

        response_data = asn1_ocsp.ResponseData({
            "responder_id": asn1_ocsp.ResponderId(
                name="by_key", value=responder_key_hash),
            "produced_at": self._gtime(datetime.now(timezone.utc)),
            "responses": [asn1_ocsp.SingleResponse({
                "cert_id": cert_id,
                "cert_status": self._ocsp_cert_status(spec),
                "this_update": self._gtime(spec.this_update),
                "next_update": self._gtime(spec.next_update),
            })],
        })
        signature = self._hsm_sign(response_data.dump(), ca)
        basic = asn1_ocsp.BasicOCSPResponse({
            "tbs_response_data": response_data,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {"algorithm": self._sig_alg_name(ca)}),
            "signature": signature,
        })
        return asn1_ocsp.OCSPResponse({
            "response_status": "successful",
            "response_bytes": asn1_ocsp.ResponseBytes({
                "response_type": "basic_ocsp_response",
                "response": basic,
            }),
        }).dump()

    # -- capabilities --------------------------------------------------------
    def can_export(self) -> bool:
        return False
