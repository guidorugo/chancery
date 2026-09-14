import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from ..extensions import db
from ..models.csr import CertificateSigningRequest
from .crypto_utils import encrypt_private_key
from .policy import build_subject, enforce_key_strength
from . import san


def _generate_key(key_type: str, key_size: int):
    # G7-1: the same floor as CA/certificate generation — a 1024-bit CSR key was
    # accepted here (and only refused later, at signing).
    enforce_key_strength(key_type, key_size)
    if key_type == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "EC":
        curves = {256: ec.SECP256R1(), 384: ec.SECP384R1(), 521: ec.SECP521R1()}
        return ec.generate_private_key(curves[key_size])
    raise ValueError(f"Unsupported key type: {key_type}")


def _build_san_extensions(san_list):
    # F4: shared syntax (DNS/IP/EMAIL/URI/UPN), unknown prefixes refused (G4-4).
    return san.build_general_names(san_list)


def create_csr(subject_attrs, san_list=None, key_type="RSA", key_size=2048, passphrase=None,
               created_by=None, profile_id=None):
    key = _generate_key(key_type, key_size)
    subject = build_subject(subject_attrs)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    if san_list:
        san_names = _build_san_extensions(san_list)
        if san_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_names),
                critical=False,
            )

    csr = builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    enc_key = None
    if passphrase:
        enc_key = encrypt_private_key(key, passphrase)

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    csr_model = CertificateSigningRequest(
        common_name=subject_attrs.get("CN", ""),
        subject_json=json.dumps(subject_attrs),
        csr_pem=csr_pem,
        san_json=json.dumps(san_list) if san_list else None,
        created_by=created_by,
        profile_id=profile_id,
    )
    db.session.add(csr_model)
    db.session.commit()

    return csr_model, key_pem, enc_key


def parse_csr(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode() if isinstance(csr_pem, str) else csr_pem)

    subject_attrs = {}
    for attr in csr.subject:
        subject_attrs[attr.oid._name] = attr.value

    san_list = []
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        # F4: DNS/IP/EMAIL/URI/UPN are carried; directoryName/registeredID and
        # other otherNames are dropped (they are never issued either).
        san_list = san.extension_to_strings(san_ext.value)
    except x509.ExtensionNotFound:
        pass

    return subject_attrs, san_list


def import_csr(csr_pem, created_by=None, profile_id=None):
    subject_attrs, san_list = parse_csr(csr_pem)
    cn = subject_attrs.get("commonName", subject_attrs.get("CN", "Unknown"))

    csr_model = CertificateSigningRequest(
        common_name=cn,
        subject_json=json.dumps(subject_attrs),
        csr_pem=csr_pem if isinstance(csr_pem, str) else csr_pem.decode(),
        san_json=json.dumps(san_list) if san_list else None,
        created_by=created_by,
        profile_id=profile_id,
    )
    db.session.add(csr_model)
    db.session.commit()
    return csr_model
