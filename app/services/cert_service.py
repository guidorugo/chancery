import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID

from ..extensions import db
from ..models.certificate import Certificate
from .crypto_utils import encrypt_private_key, decrypt_private_key
from .policy import enforce_key_strength, enforce_public_key_strength, bounded_not_after
from .keybackend import backend_for_ca


def _generate_key(key_type: str, key_size: int):
    enforce_key_strength(key_type, key_size)
    if key_type == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "EC":
        curves = {256: ec.SECP256R1(), 384: ec.SECP384R1(), 521: ec.SECP521R1()}
        return ec.generate_private_key(curves[key_size])
    raise ValueError(f"Unsupported key type: {key_type}")


def _build_subject(attrs: dict) -> x509.Name:
    name_attrs = []
    mapping = {
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
    }
    for key, oid in mapping.items():
        if attrs.get(key):
            name_attrs.append(x509.NameAttribute(oid, attrs[key]))
    return x509.Name(name_attrs)


def _build_san(san_list: list) -> x509.SubjectAlternativeName:
    names = []
    for san in san_list:
        san = san.strip()
        if not san:
            continue
        if san.startswith("IP:"):
            import ipaddress
            names.append(x509.IPAddress(ipaddress.ip_address(san[3:])))
        elif san.startswith("EMAIL:"):
            names.append(x509.RFC822Name(san[6:]))
        else:
            # Remove DNS: prefix if present
            if san.startswith("DNS:"):
                san = san[4:]
            names.append(x509.DNSName(san))
    return x509.SubjectAlternativeName(names) if names else None


def _get_hash_algorithm(key):
    return hashes.SHA256()


EKU_MAP = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "ocspSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
}


def sign_csr(csr_model, ca, validity_days, passphrase, san_list=None,
             key_usage=None, extended_key_usage=None, ocsp_url=None,
             crl_dp_url=None):
    if not ca.has_signing_key:
        raise ValueError("This CA was imported without its private key and cannot issue certificates.")
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    csr = x509.load_pem_x509_csr(csr_model.csr_pem.encode())

    # Proof-of-possession (B1): the CSR must be validly self-signed, proving
    # the requester holds the private key for the embedded public key.
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid (proof-of-possession failed); refusing to sign.")
    enforce_public_key_strength(csr.public_key())  # B5

    now = datetime.now(timezone.utc)
    # PKI-4: refuse issuance from an expired (but not-yet-revoked) CA with a
    # clear error, rather than an opaque 500 or a silently ultra-short cert.
    _ca_na = ca.not_after if ca.not_after.tzinfo else ca.not_after.replace(tzinfo=timezone.utc)
    if _ca_na <= now:
        raise ValueError("The issuing CA has expired and can no longer issue certificates.")
    not_after = bounded_not_after(now, validity_days, ca.not_after)  # B4
    serial = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            ),
            critical=False,
        )
    )

    # Key Usage
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=key_usage.get("digital_signature", True),
                key_encipherment=key_usage.get("key_encipherment", True),
                content_commitment=key_usage.get("content_commitment", False),
                data_encipherment=key_usage.get("data_encipherment", False),
                key_agreement=key_usage.get("key_agreement", False),
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    # Extended Key Usage
    if extended_key_usage:
        eku_oids = [EKU_MAP[u] for u in extended_key_usage if u in EKU_MAP]
        if eku_oids:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(eku_oids),
                critical=False,
            )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )

    # SAN
    effective_san = san_list
    if not effective_san and csr_model.san_json:
        effective_san = json.loads(csr_model.san_json)
    if effective_san:
        san_ext = _build_san(effective_san)
        if san_ext:
            builder = builder.add_extension(san_ext, critical=False)

    # OCSP AIA extension
    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url),
                ),
            ]),
            critical=False,
        )

    # CRL Distribution Points
    if crl_dp_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_dp_url)],
                    relative_name=None, crl_issuer=None, reasons=None,
                ),
            ]),
            critical=False,
        )

    cert_der = backend_for_ca(ca).sign_certificate(builder, ca, secret=passphrase)
    cert = x509.load_der_x509_certificate(cert_der)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    # Determine key info from CSR public key
    pub_key = csr.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type = "EC"
        key_size = pub_key.key_size
    else:
        key_type = "Unknown"
        key_size = 0

    subject_attrs = {}
    for attr in csr.subject:
        subject_attrs[attr.oid._name] = attr.value

    certificate = Certificate(
        serial_number=format(serial, "x"),
        common_name=csr_model.common_name,
        subject_json=json.dumps(subject_attrs),
        certificate_pem=cert_pem,
        ca_id=ca.id,
        key_type=key_type,
        key_size=key_size,
        not_before=now,
        # PKI-3: store the certificate's ACTUAL notAfter (clamped to the CA's
        # expiry and second-truncated), not the raw requested window — the DB
        # must not overstate expiry.
        not_after=cert.not_valid_after_utc.replace(tzinfo=None),
        san_json=json.dumps(effective_san) if effective_san else csr_model.san_json,
        key_usage_json=json.dumps(key_usage) if key_usage else None,
        extended_key_usage_json=json.dumps(extended_key_usage) if extended_key_usage else None,
        requested_by=csr_model.created_by,
    )
    db.session.add(certificate)
    db.session.flush()

    csr_model.status = "approved"
    csr_model.certificate_id = certificate.id
    csr_model.ca_id = ca.id

    db.session.commit()
    return certificate


def create_certificate(ca, subject_attrs, san_list, validity_days, passphrase,
                       key_type="RSA", key_size=2048, key_usage=None,
                       extended_key_usage=None, ocsp_url=None,
                       crl_dp_url=None):
    if not ca.has_signing_key:
        raise ValueError("This CA was imported without its private key and cannot issue certificates.")
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())

    key = _generate_key(key_type, key_size)
    subject = _build_subject(subject_attrs)

    now = datetime.now(timezone.utc)
    # PKI-4: refuse issuance from an expired (but not-yet-revoked) CA with a
    # clear error, rather than an opaque 500 or a silently ultra-short cert.
    _ca_na = ca.not_after if ca.not_after.tzinfo else ca.not_after.replace(tzinfo=timezone.utc)
    if _ca_na <= now:
        raise ValueError("The issuing CA has expired and can no longer issue certificates.")
    not_after = bounded_not_after(now, validity_days, ca.not_after)  # B4
    serial = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            ),
            critical=False,
        )
    )

    # Key Usage
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=key_usage.get("digital_signature", True),
                key_encipherment=key_usage.get("key_encipherment", True),
                content_commitment=key_usage.get("content_commitment", False),
                data_encipherment=key_usage.get("data_encipherment", False),
                key_agreement=key_usage.get("key_agreement", False),
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    # Extended Key Usage
    if extended_key_usage:
        eku_oids = [EKU_MAP[u] for u in extended_key_usage if u in EKU_MAP]
        if eku_oids:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(eku_oids),
                critical=False,
            )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )

    # SAN
    if san_list:
        san_ext = _build_san(san_list)
        if san_ext:
            builder = builder.add_extension(san_ext, critical=False)

    # OCSP AIA extension
    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url),
                ),
            ]),
            critical=False,
        )

    # CRL Distribution Points
    if crl_dp_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_dp_url)],
                    relative_name=None, crl_issuer=None, reasons=None,
                ),
            ]),
            critical=False,
        )

    cert_der = backend_for_ca(ca).sign_certificate(builder, ca, secret=passphrase)
    cert = x509.load_der_x509_certificate(cert_der)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    enc_key = encrypt_private_key(key, passphrase)

    certificate = Certificate(
        serial_number=format(serial, "x"),
        common_name=subject_attrs.get("CN", ""),
        subject_json=json.dumps(subject_attrs),
        certificate_pem=cert_pem,
        private_key_enc=enc_key,
        ca_id=ca.id,
        key_type=key_type,
        key_size=key_size,
        not_before=now,
        # PKI-3: store the certificate's ACTUAL notAfter (clamped to the CA's
        # expiry and second-truncated), not the raw requested window — the DB
        # must not overstate expiry.
        not_after=cert.not_valid_after_utc.replace(tzinfo=None),
        san_json=json.dumps(san_list) if san_list else None,
        key_usage_json=json.dumps(key_usage) if key_usage else None,
        extended_key_usage_json=json.dumps(extended_key_usage) if extended_key_usage else None,
    )
    db.session.add(certificate)
    db.session.commit()
    return certificate


def export_certificate_pem(certificate):
    return certificate.certificate_pem


def export_certificate_der(certificate):
    cert = x509.load_pem_x509_certificate(certificate.certificate_pem.encode())
    return cert.public_bytes(serialization.Encoding.DER)


def export_chain_pem(certificate):
    """The issuing CA chain only (issuer -> ... -> root), PEM, no leaf.

    Suitable for a web server's `ssl_trusted_certificate` / `chain.pem`. All
    public material, so callable over GET.
    """
    from .ca_service import get_ca_chain
    return get_ca_chain(certificate.ca)


def export_fullchain_pem(certificate):
    """Leaf certificate + issuing CA chain (leaf -> intermediates -> root), PEM.

    The classic `fullchain.pem` that nginx/apache/haproxy expect. Public
    material only (no private key), so callable over GET.
    """
    from .ca_service import get_ca_chain
    leaf = certificate.certificate_pem.rstrip("\n")
    return leaf + "\n" + get_ca_chain(certificate.ca)


def export_pkcs12(certificate, passphrase, export_password):
    cert = x509.load_pem_x509_certificate(certificate.certificate_pem.encode())

    if not certificate.private_key_enc:
        raise ValueError("No private key available for this certificate")
    if not export_password:
        raise ValueError("An export password is required for PKCS#12.")

    key = decrypt_private_key(certificate.private_key_enc, passphrase)

    # Build CA chain
    from ..models.ca import CertificateAuthority
    ca = db.session.get(CertificateAuthority, certificate.ca_id)
    ca_certs = []
    current = ca
    while current:
        ca_certs.append(x509.load_pem_x509_certificate(current.certificate_pem.encode()))
        if current.parent:
            current = current.parent
        else:
            break

    p12 = pkcs12.serialize_key_and_certificates(
        name=certificate.common_name.encode(),
        key=key,
        cert=cert,
        cas=ca_certs if ca_certs else None,
        encryption_algorithm=BestAvailableEncryption(export_password.encode()),
    )
    return p12
