import json
import uuid
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtensionOID

from ..extensions import db
from ..models.ca import CertificateAuthority
from .crypto_utils import encrypt_private_key, decrypt_private_key
from .policy import enforce_key_strength, enforce_public_key_strength, bounded_not_after
from .keybackend import get_backend, backend_for_ca, default_backend_name


def _key_label():
    """Unique PKCS#11 object label for a new CA key (HSM backends)."""
    return "ca-" + uuid.uuid4().hex

MAX_PEM_SIZE = 64 * 1024  # 64KB


def _publish_initial_crl(ca, passphrase):
    """Publish an initial CRL for a newly created/imported keyed CA so the
    read-only public CRL endpoint (C1) always has something to serve.
    Best-effort — the CA already exists; a failure just defers the CRL to the
    admin 'Generate CRL' action or the first revocation.
    """
    if not ca or not ca.has_signing_key:
        return
    from . import crl_service
    import logging
    try:
        crl_service.generate_crl(ca, passphrase)
    except Exception:
        db.session.rollback()
        logging.getLogger(__name__).warning("Initial CRL generation failed for CA %s", ca.id)


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


def _get_hash_algorithm(key):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return hashes.SHA256()
    return hashes.SHA256()


def create_root_ca(name, subject_attrs, key_type, key_size, validity_days, passphrase,
                   path_length=None, backend=None):
    enforce_key_strength(key_type, key_size)  # B5
    backend_name = backend or default_backend_name()
    kb = get_backend(backend_name)
    label = _key_label()
    public_key, key_ref = kb.generate_ca_key(
        key_type, key_size, label=label, secret=passphrase)

    subject = _build_subject(subject_attrs)
    now = datetime.now(timezone.utc)
    not_after = bounded_not_after(now, validity_days, is_ca=True)  # B4
    serial = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False,
        )
    )

    # A root signs its own certificate. Build the (uncommitted) CA object first
    # so the backend can sign with it (software reads private_key_enc, HSM reads
    # key_type/key_label); the certificate does not exist yet, hence the
    # column-based key lookup in the backend.
    ca = CertificateAuthority(
        name=name,
        common_name=subject_attrs.get("CN", name),
        serial_number=format(serial, "x"),
        private_key_enc=(key_ref if backend_name == "software" else b""),
        key_backend=backend_name,
        key_label=(label if backend_name != "software" else None),
        parent_id=None,
        is_root=True,
        key_type=key_type,
        key_size=key_size,
        not_before=now,
        not_after=not_after,
        path_length=path_length,
    )
    cert_der = kb.sign_certificate(builder, ca, secret=passphrase)
    ca.certificate_pem = x509.load_der_x509_certificate(cert_der).public_bytes(
        serialization.Encoding.PEM).decode()
    db.session.add(ca)
    db.session.commit()
    _publish_initial_crl(ca, passphrase)
    return ca


def create_intermediate_ca(name, parent_ca, subject_attrs, key_type, key_size,
                           validity_days, passphrase, path_length=None, backend=None):
    if not parent_ca.has_signing_key:
        raise ValueError("Parent CA was imported without its private key and cannot sign a new intermediate CA.")
    enforce_key_strength(key_type, key_size)  # B5

    # The child key lives in the child's chosen backend; the parent's backend
    # signs the child certificate (software and HSM parents/children mix freely).
    backend_name = backend or default_backend_name()
    child_kb = get_backend(backend_name)
    label = _key_label()
    public_key, key_ref = child_kb.generate_ca_key(
        key_type, key_size, label=label, secret=passphrase)

    subject = _build_subject(subject_attrs)
    parent_cert = x509.load_pem_x509_certificate(parent_ca.certificate_pem.encode())

    # PKI-6: honour the parent's pathLenConstraint so the issued intermediate
    # actually chain-validates. pathLen<=0 forbids any sub-CA; otherwise the
    # child's budget is at most parent-1 (clamp a larger / unlimited request).
    if parent_ca.path_length is not None:
        if parent_ca.path_length <= 0:
            raise ValueError(
                "The parent CA's path length is 0 — it cannot issue a sub-CA.")
        allowed = parent_ca.path_length - 1
        if path_length is None or path_length > allowed:
            path_length = allowed

    now = datetime.now(timezone.utc)
    # B4: bound to the CA maximum and never outlive the parent CA.
    not_after = bounded_not_after(now, validity_days, parent_ca.not_after, is_ca=True)
    serial = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent_cert.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                parent_cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            ),
            critical=False,
        )
    )

    ca = CertificateAuthority(
        name=name,
        common_name=subject_attrs.get("CN", name),
        serial_number=format(serial, "x"),
        private_key_enc=(key_ref if backend_name == "software" else b""),
        key_backend=backend_name,
        key_label=(label if backend_name != "software" else None),
        parent_id=parent_ca.id,
        is_root=False,
        key_type=key_type,
        key_size=key_size,
        not_before=now,
        not_after=not_after,
        path_length=path_length,
    )
    cert_der = backend_for_ca(parent_ca).sign_certificate(
        builder, parent_ca, secret=passphrase)
    ca.certificate_pem = x509.load_der_x509_certificate(cert_der).public_bytes(
        serialization.Encoding.PEM).decode()
    db.session.add(ca)
    db.session.commit()
    _publish_initial_crl(ca, passphrase)
    return ca


def get_ca_chain(ca):
    chain = []
    current = ca
    while current:
        chain.append(current.certificate_pem)
        if current.parent:
            current = current.parent
        else:
            break
    return "\n".join(chain)


def _find_parent_by_issuer(cert):
    """Find an existing CA whose subject matches cert's issuer. Returns id or None."""
    for candidate in CertificateAuthority.query.all():
        try:
            candidate_cert = x509.load_pem_x509_certificate(candidate.certificate_pem.encode())
            if candidate_cert.subject == cert.issuer:
                return candidate.id
        except Exception:
            continue
    return None


def detect_parent_ca(cert_pem):
    """Detect if a certificate is self-signed and find its parent CA.

    Accepts a single PEM certificate or a bundle (the first certificate is
    examined). Returns (is_self_signed, parent_id); (None, None) on parse error.
    """
    try:
        data = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
        cert = x509.load_pem_x509_certificates(data)[0]
    except Exception:
        return (None, None)

    if cert.issuer == cert.subject:
        return (True, None)
    return (False, _find_parent_by_issuer(cert))


def _load_import_private_key(key_bytes, key_passphrase=None):
    """Parse an (optionally encrypted) PEM private key with friendly errors."""
    password = key_passphrase.encode() if key_passphrase else None
    try:
        private_key = serialization.load_pem_private_key(key_bytes, password=password)
    except TypeError:
        if password is None:
            raise ValueError("The private key is encrypted. Provide its passphrase in the key passphrase field.")
        raise ValueError("The private key is not encrypted. Leave the key passphrase empty.")
    except Exception:
        if password is not None:
            raise ValueError("Could not decrypt the private key. Check the key passphrase.")
        raise ValueError("Failed to parse private key PEM. Ensure it is a valid PEM-encoded private key.")

    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError("Unsupported key type. Only RSA and EC keys are supported.")
    return private_key


def _key_info_from_public(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.curve.key_size
    raise ValueError("Unsupported certificate key type. Only RSA and EC are supported.")


def _unique_ca_name(base):
    name = base
    suffix = 2
    while CertificateAuthority.query.filter_by(name=name).first():
        name = f"{base} ({suffix})"
        suffix += 1
    return name


def _import_ca_object(name, cert, private_key, passphrase, parent_id=None):
    """Validate and stage a single CA row from parsed objects.

    private_key may be None for certificate-only imports (empty-bytes
    sentinel is stored). Flushes but does not commit.
    """
    # BasicConstraints - must be a CA
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            raise ValueError("Certificate has BasicConstraints with ca=False. Only CA certificates can be imported.")
        path_length = bc.value.path_length
    except x509.ExtensionNotFound:
        raise ValueError("Certificate is missing the BasicConstraints extension. Only CA certificates can be imported.")

    # PKI-7: enforce the key-strength floor on import too (generation and CSR
    # signing already do), so a weak CA (e.g. RSA-1024 or an off-list curve)
    # cannot enter the trust hierarchy via the import path.
    enforce_public_key_strength(cert.public_key())

    # Key-cert match (validate the material before database constraints)
    if private_key is not None:
        cert_pub_bytes = cert.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if cert_pub_bytes != key_pub_bytes:
            raise ValueError("The private key does not match the certificate's public key.")
        key_type, key_size = _key_info_from_public(private_key.public_key())
        enc_key = encrypt_private_key(private_key, passphrase)
    else:
        key_type, key_size = _key_info_from_public(cert.public_key())
        enc_key = b""  # sentinel: imported without a private key

    # Name uniqueness
    if CertificateAuthority.query.filter_by(name=name).first():
        raise ValueError(f"A CA with the name '{name}' already exists.")

    # Serial uniqueness
    serial_hex = format(cert.serial_number, "x")
    if CertificateAuthority.query.filter_by(serial_number=serial_hex).first():
        raise ValueError(f"A CA with serial number '{serial_hex}' already exists.")

    cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    common_name = cn_attrs[0].value if cn_attrs else name

    is_self_signed = cert.issuer == cert.subject

    # Resolve parent
    resolved_parent_id = None
    if parent_id is not None and str(parent_id).strip():
        parent_ca = db.session.get(CertificateAuthority, int(parent_id))
        if not parent_ca:
            raise ValueError("Specified parent CA not found.")
        resolved_parent_id = parent_ca.id
    elif not is_self_signed:
        resolved_parent_id = _find_parent_by_issuer(cert)

    ca = CertificateAuthority(
        name=name,
        common_name=common_name,
        serial_number=serial_hex,
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        private_key_enc=enc_key,
        parent_id=resolved_parent_id,
        is_root=is_self_signed and resolved_parent_id is None,
        key_type=key_type,
        key_size=key_size,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        path_length=path_length,
    )
    db.session.add(ca)
    db.session.flush()
    return ca


def _order_chain(certs):
    """Order CA certificates leaf-first up the chain; verify each signature.

    Accepts an unordered bundle. The top of the returned list is the highest
    parent present in the bundle (not necessarily self-signed - the chain may
    continue in an existing database CA).
    """
    unique = {}
    for cert in certs:
        unique[(cert.serial_number, cert.subject.public_bytes())] = cert
    certs = list(unique.values())
    if len(certs) == 1:
        return certs

    issuer_keys = {c.issuer.public_bytes() for c in certs if c.issuer != c.subject}
    leaves = [c for c in certs if c.subject.public_bytes() not in issuer_keys]
    if len(leaves) != 1:
        raise ValueError("The certificate bundle does not form a single chain.")

    by_subject = {c.subject.public_bytes(): c for c in certs}
    ordered = [leaves[0]]
    current = leaves[0]
    while current.issuer != current.subject:
        parent = by_subject.get(current.issuer.public_bytes())
        if parent is None:
            break  # top of the provided bundle; may still link to an existing CA
        if parent in ordered:
            raise ValueError("The certificate bundle contains a loop.")
        try:
            current.verify_directly_issued_by(parent)
        except Exception as exc:
            raise ValueError(f"Certificate chain does not verify: {exc}")
        ordered.append(parent)
        current = parent

    if len(ordered) != len(certs):
        raise ValueError("The certificate bundle contains certificates that are not part of one chain.")
    return ordered


def _import_chain(name, ordered, private_key, passphrase, parent_id=None):
    """Import an ordered (leaf-first) chain.

    Parents are imported certificate-only with auto-generated names
    (deduplicated against existing CAs by serial number); the leaf gets the
    requested name and the private key, when provided.
    """
    top = ordered[-1]
    top_parent_id = None
    if parent_id is not None and str(parent_id).strip():
        if top.issuer == top.subject:
            raise ValueError("The bundle ends in a self-signed root; a parent CA cannot be assigned to it.")
        top_parent_id = parent_id

    imported_parents = []
    current_parent_id = top_parent_id

    for cert in reversed(ordered[1:]):
        serial_hex = format(cert.serial_number, "x")
        existing = CertificateAuthority.query.filter_by(serial_number=serial_hex).first()
        if existing:
            current_parent_id = existing.id
            continue
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        base_name = cn_attrs[0].value if cn_attrs else f"{name} parent"
        parent_ca = _import_ca_object(
            _unique_ca_name(base_name), cert, None, passphrase, parent_id=current_parent_id
        )
        imported_parents.append(parent_ca.name)
        current_parent_id = parent_ca.id

    leaf = _import_ca_object(name, ordered[0], private_key, passphrase, parent_id=current_parent_id)
    db.session.commit()
    leaf._imported_parents = imported_parents
    return leaf


def import_ca(name, cert_pem, key_pem, passphrase, parent_id=None, key_passphrase=None):
    """Import an existing CA from PEM material.

    cert_pem may contain a single CA certificate or a full chain bundle; with
    a bundle, parents are imported certificate-only (deduplicated by serial
    number) and linked. key_pem is optional - omit it to import
    certificate-only (e.g. an offline root) - and may be encrypted, with
    key_passphrase used to decrypt it.
    """
    cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
    if len(cert_bytes) > MAX_PEM_SIZE:
        raise ValueError("Certificate PEM exceeds 64KB size limit.")

    private_key = None
    if key_pem:
        key_bytes = key_pem.encode() if isinstance(key_pem, str) else key_pem
        if len(key_bytes) > MAX_PEM_SIZE:
            raise ValueError("Private key PEM exceeds 64KB size limit.")
        private_key = _load_import_private_key(key_bytes, key_passphrase)

    try:
        certs = x509.load_pem_x509_certificates(cert_bytes)
    except Exception:
        raise ValueError("Failed to parse certificate PEM. Ensure it is a valid PEM-encoded certificate.")

    ordered = _order_chain(certs)
    if len(ordered) == 1:
        ca = _import_ca_object(name, ordered[0], private_key, passphrase, parent_id=parent_id)
        db.session.commit()
        ca._imported_parents = []
    else:
        ca = _import_chain(name, ordered, private_key, passphrase, parent_id=parent_id)
    _publish_initial_crl(ca, passphrase)
    return ca


def _refuse_if_not_exportable(ca, cert_only_msg):
    """Raise if the CA key cannot be exported: HSM keys are non-extractable,
    certificate-only imports have no key. Software-keyed CAs pass through."""
    if ca.is_exportable:
        return
    if ca.key_backend == "softhsm":
        raise ValueError("This CA's key is held in the HSM token and cannot be exported.")
    raise ValueError(cert_only_msg)


def export_ca_key_pem(ca, passphrase):
    """Decrypt and return the CA's private key as unencrypted PKCS#8 PEM."""
    _refuse_if_not_exportable(
        ca, "This CA was imported without its private key; there is no key to export.")
    key = decrypt_private_key(ca.private_key_enc, passphrase)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def export_ca_pkcs12(ca, passphrase, export_password):
    """Export the CA as a password-protected PKCS#12 bundle.

    The bundle contains the CA certificate, its private key, and the parent
    chain as additional certificates — importable back via import_pkcs12().
    """
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12

    _refuse_if_not_exportable(
        ca, "This CA was imported without its private key; PKCS#12 export is not possible.")
    if not export_password:
        raise ValueError("An export password is required for PKCS#12.")

    cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    key = decrypt_private_key(ca.private_key_enc, passphrase)

    chain_certs = []
    current = ca.parent
    while current:
        chain_certs.append(x509.load_pem_x509_certificate(current.certificate_pem.encode()))
        current = current.parent

    return pkcs12.serialize_key_and_certificates(
        name=ca.name.encode(),
        key=key,
        cert=cert,
        cas=chain_certs or None,
        encryption_algorithm=BestAvailableEncryption(export_password.encode()),
    )


def import_pkcs12(name, p12_bytes, p12_password, passphrase, parent_id=None):
    """Import a CA from a PKCS#12 (.p12/.pfx) bundle.

    The bundle's main certificate becomes the named CA (with its key when
    present); additional certificates are treated as its chain and imported
    certificate-only.
    """
    from cryptography.hazmat.primitives.serialization import pkcs12

    if len(p12_bytes) > MAX_PEM_SIZE:
        raise ValueError("PKCS#12 file exceeds 64KB size limit.")

    password = p12_password.encode() if p12_password else None
    try:
        key, cert, additional = pkcs12.load_key_and_certificates(p12_bytes, password)
    except Exception:
        raise ValueError("Could not open the PKCS#12 file: wrong password or not a valid PKCS#12 bundle.")

    if key is not None and not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError("Unsupported key type. Only RSA and EC keys are supported.")

    if cert is None:
        # Key-less bundles store their certificates in the additional list
        certs = list(additional or [])
        if not certs:
            raise ValueError("The PKCS#12 bundle does not contain a certificate.")
    else:
        certs = [cert] + list(additional or [])

    ordered = _order_chain(certs)
    if cert is not None and ordered[0] != cert:
        raise ValueError("The PKCS#12 main certificate is not the leaf of the bundled chain.")
    if len(ordered) == 1:
        ca = _import_ca_object(name, ordered[0], key, passphrase, parent_id=parent_id)
        db.session.commit()
        ca._imported_parents = []
    else:
        ca = _import_chain(name, ordered, key, passphrase, parent_id=parent_id)
    _publish_initial_crl(ca, passphrase)
    return ca
