import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


SALT_SIZE = 16
PBKDF2_ITERATIONS = 600_000


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
