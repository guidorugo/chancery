"""JWS handling for ACME (RFC 8555 §6.2, RFC 7515/7517/7518/7638) on pyca only.

Supported account key algorithms: RS256 (RSA ≥ 2048), ES256/ES384/ES512
(P-256/P-384/P-521). External-account-binding JWS use HS256/HS384/HS512.
"""
import base64
import hashlib
import hmac as _hmac
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .problem import AcmeProblem

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")

EC_ALGS = {"ES256": (ec.SECP256R1, hashes.SHA256, 32),
           "ES384": (ec.SECP384R1, hashes.SHA384, 48),
           "ES512": (ec.SECP521R1, hashes.SHA512, 66)}
HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
ALGS = ("RS256",) + tuple(EC_ALGS)
_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
_CURVE_NAMES = {v: k for k, v in _CURVES.items()}


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    if not isinstance(text, str) or not _B64URL.match(text):
        raise AcmeProblem("malformed", "Invalid base64url encoding.")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _int_from_b64(text, name):
    raw = b64url_decode(text)
    if not raw:
        raise AcmeProblem("badPublicKey", f"JWK member {name!r} is empty.")
    return int.from_bytes(raw, "big")


def jwk_to_public_key(jwk):
    if not isinstance(jwk, dict):
        raise AcmeProblem("badPublicKey", "JWK must be an object.")
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            key = rsa.RSAPublicNumbers(_int_from_b64(jwk["e"], "e"), _int_from_b64(jwk["n"], "n")).public_key()
            if key.key_size < 2048:
                raise AcmeProblem("badPublicKey", "RSA account keys must be at least 2048 bits.")
            return key
        if kty == "EC":
            curve = _CURVES.get(jwk.get("crv"))
            if curve is None:
                raise AcmeProblem("badPublicKey", f"Unsupported curve {jwk.get('crv')!r}.")
            return ec.EllipticCurvePublicNumbers(_int_from_b64(jwk["x"], "x"), _int_from_b64(jwk["y"], "y"),
                                                 curve()).public_key()
    except AcmeProblem:
        raise
    except (KeyError, ValueError, TypeError) as exc:
        raise AcmeProblem("badPublicKey", f"Invalid JWK: {exc}")
    raise AcmeProblem("badPublicKey", f"Unsupported key type {kty!r}.")


def public_key_to_jwk(key):
    if isinstance(key, rsa.RSAPublicKey):
        n = key.public_numbers()
        return {"kty": "RSA", "n": b64url_encode(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")),
                "e": b64url_encode(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big"))}
    if isinstance(key, ec.EllipticCurvePublicKey):
        n = key.public_numbers()
        size = (key.curve.key_size + 7) // 8
        return {"kty": "EC", "crv": _CURVE_NAMES[type(key.curve)],
                "x": b64url_encode(n.x.to_bytes(size, "big")), "y": b64url_encode(n.y.to_bytes(size, "big"))}
    raise AcmeProblem("badPublicKey", "Unsupported key type.")


def thumbprint(jwk):
    """RFC 7638 JWK thumbprint (SHA-256, base64url)."""
    kty = jwk.get("kty")
    if kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    else:
        raise AcmeProblem("badPublicKey", f"Unsupported key type {kty!r}.")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return b64url_encode(hashlib.sha256(canonical).digest())


def key_authorization(token, jwk):
    return f"{token}.{thumbprint(jwk)}"


def _verify_signature(public_key, alg, signing_input, signature):
    try:
        if alg == "RS256":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise AcmeProblem("malformed", "RS256 requires an RSA key.")
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return
        curve, digest, size = EC_ALGS[alg]
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, curve):
            raise AcmeProblem("malformed", f"{alg} requires a {_CURVE_NAMES[curve]} key.")
        if len(signature) != 2 * size:
            raise AcmeProblem("malformed", "Invalid ECDSA signature length.")
        r = int.from_bytes(signature[:size], "big")
        s = int.from_bytes(signature[size:], "big")
        public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(digest()))
    except InvalidSignature:
        raise AcmeProblem("malformed", "JWS signature verification failed.")


class Verified:
    """Result of verify(): the protected header, the decoded payload (None for
    POST-as-GET), the key used and, when a kid was used, the resolved account."""
    def __init__(self, protected, payload, jwk, kid, public_key, account=None):
        self.protected, self.payload, self.jwk, self.kid, self.public_key, self.account = (
            protected, payload, jwk, kid, public_key, account)


def parse(raw):
    try:
        body = json.loads(raw)
    except (ValueError, TypeError):
        raise AcmeProblem("malformed", "Request body is not JSON.")
    if not isinstance(body, dict) or not all(isinstance(body.get(k), str) for k in ("protected", "payload", "signature")):
        raise AcmeProblem("malformed", "Request body is not a flattened JWS with protected, payload and signature.")
    return body


def verify(body, expected_url, account_for_kid, allow_jwk, allow_kid=True, require_nonce=True):
    """Verify a flattened JWS against ACME rules. `account_for_kid(kid)` must
    return the account (or raise accountDoesNotExist). Nonce checking is the
    caller's job (it needs the database)."""
    try:
        protected = json.loads(b64url_decode(body["protected"]))
    except ValueError:
        raise AcmeProblem("malformed", "Protected header is not JSON.")
    if not isinstance(protected, dict):
        raise AcmeProblem("malformed", "Protected header must be an object.")
    if "crit" in protected:
        raise AcmeProblem("malformed", "Critical header parameters are not supported.")
    alg = protected.get("alg")
    if alg not in ALGS:
        raise AcmeProblem("badSignatureAlgorithm", f"Unsupported algorithm {alg!r}.", extra={"algorithms": list(ALGS)})
    if protected.get("url") != expected_url:
        raise AcmeProblem("unauthorized", "The JWS 'url' header does not match the request URL.")
    if require_nonce and (not isinstance(protected.get("nonce"), str) or not protected["nonce"]):
        raise AcmeProblem("badNonce", "The JWS carries no nonce.")
    if not require_nonce and "nonce" in protected:
        raise AcmeProblem("malformed", "The inner JWS must not carry a nonce.")
    jwk, kid = protected.get("jwk"), protected.get("kid")
    if (jwk is None) == (kid is None):
        raise AcmeProblem("malformed", "Exactly one of 'jwk' and 'kid' must be present.")
    account = None
    if jwk is not None:
        if not allow_jwk:
            raise AcmeProblem("malformed", "This request must be signed with an account key ('kid').")
        public_key = jwk_to_public_key(jwk)
    else:
        if not allow_kid:
            raise AcmeProblem("malformed", "This request must carry the key in 'jwk'.")
        if not isinstance(kid, str):
            raise AcmeProblem("malformed", "'kid' must be a string.")
        account = account_for_kid(kid)
        jwk = account.jwk
        public_key = jwk_to_public_key(jwk)
    signing_input = f"{body['protected']}.{body['payload']}".encode("ascii")
    _verify_signature(public_key, alg, signing_input, b64url_decode(body["signature"]))
    raw_payload = b64url_decode(body["payload"])
    if raw_payload == b"":
        payload = None                      # POST-as-GET (§6.3)
    else:
        try:
            payload = json.loads(raw_payload)
        except ValueError:
            raise AcmeProblem("malformed", "Payload is not JSON.")
        if not isinstance(payload, dict):
            raise AcmeProblem("malformed", "Payload must be an object.")
    return Verified(protected, payload, jwk, kid, public_key, account)


def verify_eab(eab, mac_key, expected_url, outer_jwk):
    """Verify an externalAccountBinding JWS (§7.3.4): HMAC over the account
    key, signed with the MAC key issued for `kid`. Returns the kid."""
    if not isinstance(eab, dict) or not all(isinstance(eab.get(k), str) for k in ("protected", "payload", "signature")):
        raise AcmeProblem("malformed", "externalAccountBinding is not a flattened JWS.")
    try:
        protected = json.loads(b64url_decode(eab["protected"]))
    except ValueError:
        raise AcmeProblem("malformed", "externalAccountBinding protected header is not JSON.")
    alg = protected.get("alg")
    if alg not in HMAC_ALGS:
        raise AcmeProblem("badSignatureAlgorithm", "externalAccountBinding must use HS256, HS384 or HS512.",
                          extra={"algorithms": list(HMAC_ALGS)})
    if "nonce" in protected:
        raise AcmeProblem("malformed", "externalAccountBinding must not carry a nonce.")
    if protected.get("url") != expected_url:
        raise AcmeProblem("unauthorized", "externalAccountBinding 'url' does not match the newAccount URL.")
    try:
        inner = json.loads(b64url_decode(eab["payload"]))
    except ValueError:
        raise AcmeProblem("malformed", "externalAccountBinding payload is not JSON.")
    if inner != outer_jwk:
        raise AcmeProblem("unauthorized", "externalAccountBinding does not bind the account key of this request.")
    expected = _hmac.new(mac_key, f"{eab['protected']}.{eab['payload']}".encode("ascii"), HMAC_ALGS[alg]).digest()
    if not _hmac.compare_digest(expected, b64url_decode(eab["signature"])):
        raise AcmeProblem("unauthorized", "externalAccountBinding MAC is invalid.")
    return protected.get("kid")


def sign_hmac(mac_key, protected, payload, alg="HS256"):
    """Test/CLI helper: build an HMAC JWS (used for EAB examples)."""
    p = b64url_encode(json.dumps(protected, separators=(",", ":")).encode())
    pl = b64url_encode(payload if isinstance(payload, bytes) else json.dumps(payload, separators=(",", ":")).encode())
    sig = _hmac.new(mac_key, f"{p}.{pl}".encode("ascii"), HMAC_ALGS[alg]).digest()
    return {"protected": p, "payload": pl, "signature": b64url_encode(sig)}


def public_key_pem(key):
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
