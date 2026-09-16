import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


SALT_SIZE = 16
PBKDF2_ITERATIONS = 600_000

# --- key algorithms (F5, 2.20.0) ------------------------------------------------
#
# The key types Chancery generates and accepts, everywhere (CA, certificate,
# CSR, import, profiles). RSA and the three NIST curves as before; Ed25519 and
# Ed448 are deliberate additions (assessment G4-3): they sign with EdDSA and no
# separate hash (`hash_for_key` returns None, which is what pyca expects).
# Anything else — DSA, other curves, unknown algorithms — is refused at every
# entry point instead of being carried along as key_type "Unknown".
KEY_TYPES = ("RSA", "EC", "ED25519", "ED448")
EC_SIZES = (256, 384, 521)
# The `key_size` stored for an Edwards key (the column is NOT NULL): the key's
# bit length, fixed per algorithm.
ED_KEY_SIZES = {"ED25519": 256, "ED448": 456}
_EC_CURVES = {256: ec.SECP256R1, 384: ec.SECP384R1, 521: ec.SECP521R1}
_ED_PRIVATE = {"ED25519": ed25519.Ed25519PrivateKey, "ED448": ed448.Ed448PrivateKey}
_ED_PUBLIC = {ed25519.Ed25519PublicKey: "ED25519", ed448.Ed448PublicKey: "ED448"}


def generate_key(key_type, key_size=None):
    """Generate a private key of `key_type` after the key policy check (B5).
    `key_size` is bits for RSA, the curve size for EC, and ignored for the
    Edwards curves (their size is fixed)."""
    from .policy import enforce_key_strength
    enforce_key_strength(key_type, key_size)
    if key_type == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if key_type == "EC":
        return ec.generate_private_key(_EC_CURVES[key_size]())
    if key_type in _ED_PRIVATE:
        return _ED_PRIVATE[key_type].generate()
    raise ValueError(f"Unsupported key type: {key_type}")


def key_info(public_key):
    """(key_type, key_size) for a public (or private) key object, as stored on
    CAs and certificates. Raises ValueError for an algorithm Chancery does not
    support (G4-3) instead of returning "Unknown"."""
    if hasattr(public_key, "public_key") and not hasattr(public_key, "public_bytes"):
        public_key = public_key.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.curve.key_size
    for cls, name in _ED_PUBLIC.items():
        if isinstance(public_key, cls):
            return name, ED_KEY_SIZES[name]
    raise ValueError("Unsupported key algorithm; Chancery supports RSA, EC P-256/P-384/P-521, Ed25519 and Ed448.")


def is_ed_key(key):
    """True for an Ed25519/Ed448 private or public key."""
    return isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey,
                            ed448.Ed448PrivateKey, ed448.Ed448PublicKey))


def hash_for_key(key):
    """The digest to pass to a pyca `sign()` for this key: None for the
    Edwards curves (EdDSA hashes internally), SHA-256 otherwise."""
    return None if is_ed_key(key) else hashes.SHA256()


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_private_key(private_key, passphrase: str) -> bytes:
    if isinstance(private_key, bytes):
        key_pem = private_key
    else:
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    salt = os.urandom(SALT_SIZE)
    fernet_key = _derive_key(passphrase, salt)
    f = Fernet(fernet_key)
    encrypted = f.encrypt(key_pem)
    return salt + encrypted


def decrypt_private_key(encrypted_data: bytes, passphrase: str):
    salt = encrypted_data[:SALT_SIZE]
    token = encrypted_data[SALT_SIZE:]
    fernet_key = _derive_key(passphrase, salt)
    f = Fernet(fernet_key)
    key_pem = f.decrypt(token)
    return serialization.load_pem_private_key(key_pem, password=None)


def decrypt_payload(encrypted_data: bytes, passphrase: str) -> bytes:
    """Raw Fernet payload (key PEM or secret bytes) under `passphrase`. Raises
    cryptography.fernet.InvalidToken on a wrong passphrase or corrupt data."""
    salt = encrypted_data[:SALT_SIZE]
    token = encrypted_data[SALT_SIZE:]
    return Fernet(_derive_key(passphrase, salt)).decrypt(token)


def can_decrypt(encrypted_data: bytes, passphrase: str) -> bool:
    try:
        decrypt_payload(encrypted_data, passphrase)
        return True
    except (InvalidToken, ValueError, TypeError):
        return False


def rewrap(encrypted_data: bytes, old_passphrase: str, new_passphrase: str) -> bytes:
    """Re-encrypt a blob under a new passphrase with a fresh salt (F18). The
    payload is untouched, so it works for keys and secrets alike."""
    payload = decrypt_payload(encrypted_data, old_passphrase)
    salt = os.urandom(SALT_SIZE)
    return salt + Fernet(_derive_key(new_passphrase, salt)).encrypt(payload)


def encrypt_secret(plaintext: str, passphrase: str) -> bytes:
    """Encrypt an arbitrary secret string (same salt+Fernet format as keys)."""
    salt = os.urandom(SALT_SIZE)
    f = Fernet(_derive_key(passphrase, salt))
    return salt + f.encrypt(plaintext.encode("utf-8"))


def decrypt_secret(encrypted_data: bytes, passphrase: str) -> str:
    salt = encrypted_data[:SALT_SIZE]
    token = encrypted_data[SALT_SIZE:]
    f = Fernet(_derive_key(passphrase, salt))
    return f.decrypt(token).decode("utf-8")
