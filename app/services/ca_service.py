import json
import uuid
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from ..extensions import db
from ..models.ca import CertificateAuthority
from .crypto_utils import encrypt_private_key, decrypt_private_key, key_info
from .policy import (enforce_key_strength, enforce_public_key_strength,
                     bounded_not_after, build_subject)
from .keybackend import get_backend, backend_for_ca, default_backend_name
from . import certificate_policies, name_constraints
from ..models.ca_certificate import CaCertificate


def _key_label():
    """Unique PKCS#11 object label for a new CA key (HSM backends)."""
    return "ca-" + uuid.uuid4().hex

MAX_PEM_SIZE = 64 * 1024  # 64KB


def publish_initial_crl(ca, passphrase):
    """Publish an initial CRL for a newly created/imported keyed CA so the
    read-only public CRL endpoint (C1) always has something to serve.
    Best-effort — the CA already exists; a failure just defers the CRL to the
    admin 'Generate CRL' action or the first revocation.

    Skipped for dual-control pending CAs (they cannot sign yet); the approve
    route publishes their first CRL instead.
    """
    if not ca or not ca.has_signing_key or ca.approval_status == "pending":
        return
    from . import crl_service
    import logging
    try:
        crl_service.generate_crl(ca, passphrase)
    except Exception:
        db.session.rollback()
        logging.getLogger(__name__).warning("Initial CRL generation failed for CA %s", ca.id)


def create_root_ca(name, subject_attrs, key_type, key_size, validity_days, passphrase,
                   path_length=None, backend=None, created_by=None,
                   approval_status="approved", constraints=None, policies=None):
    """`constraints` (F2): `{"permitted": [...], "excluded": [...]}` from
    `name_constraints.normalise()`; encoded as a critical NameConstraints
    extension and stored on the row. `policies` (F3): a list from
    `certificate_policies.normalise()`, stamped as certificatePolicies and
    inherited by every certificate this CA issues."""
    enforce_key_strength(key_type, key_size)  # B5
    nc_ext = name_constraints.build_extension(constraints)
    cp_ext = certificate_policies.build_extension(policies)
    backend_name = backend or default_backend_name()
    kb = get_backend(backend_name)
    label = _key_label()
    public_key, key_ref = kb.generate_ca_key(
        key_type, key_size, label=label, secret=passphrase)
    key_type, key_size = key_info(public_key)  # canonical (Edwards keys have a fixed size)

    subject = build_subject(subject_attrs)
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
    if nc_ext is not None:
        builder = builder.add_extension(nc_ext, critical=True)
    if cp_ext is not None:
        builder = builder.add_extension(cp_ext, critical=False)

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
        created_by=created_by,
        approval_status=approval_status,
        approved_by=(created_by if approval_status == "approved" else None),
        approved_at=(now if approval_status == "approved" else None),
    )
    ca.set_name_constraints(constraints)
    ca.set_certificate_policies(policies)
    cert_der = kb.sign_certificate(builder, ca, secret=passphrase)
    ca.certificate_pem = x509.load_der_x509_certificate(cert_der).public_bytes(
        serialization.Encoding.PEM).decode()
    db.session.add(ca)
    db.session.commit()
    publish_initial_crl(ca, passphrase)
    return ca


def create_intermediate_ca(name, parent_ca, subject_attrs, key_type, key_size,
                           validity_days, passphrase, path_length=None, backend=None,
                           created_by=None, approval_status="approved", constraints=None,
                           policies=None):
    if not parent_ca.has_signing_key:
        raise ValueError("Parent CA was imported without its private key and cannot sign a new intermediate CA.")
    if parent_ca.approval_status == "pending":
        raise ValueError("The parent CA is awaiting dual-control approval and cannot sign a new intermediate CA yet.")
    # G4-2 / G4-6: a revoked or expired parent must not be able to grow the
    # hierarchy — the route's dropdown hides such parents, but the server
    # accepted any parent_id.
    if parent_ca.is_revoked:
        raise ValueError("The parent CA is revoked and cannot sign a new intermediate CA.")
    _parent_not_after = (parent_ca.not_after if parent_ca.not_after.tzinfo
                         else parent_ca.not_after.replace(tzinfo=timezone.utc))
    if _parent_not_after <= datetime.now(timezone.utc):
        raise ValueError("The parent CA has expired and cannot sign a new intermediate CA.")
    enforce_key_strength(key_type, key_size)  # B5
    # F2: the new CA's own name (a hostname-like CN) must sit inside the
    # parent chain's constraints, like any other certified name.
    name_constraints.enforce(parent_ca, subject_attrs, [])
    nc_ext = name_constraints.build_extension(constraints)
    cp_ext = certificate_policies.build_extension(policies)

    # The child key lives in the child's chosen backend; the parent's backend
    # signs the child certificate (software and HSM parents/children mix freely).
    backend_name = backend or default_backend_name()
    child_kb = get_backend(backend_name)
    label = _key_label()
    public_key, key_ref = child_kb.generate_ca_key(
        key_type, key_size, label=label, secret=passphrase)
    key_type, key_size = key_info(public_key)

    subject = build_subject(subject_attrs)
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
    if nc_ext is not None:
        builder = builder.add_extension(nc_ext, critical=True)
    if cp_ext is not None:
        builder = builder.add_extension(cp_ext, critical=False)

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
        created_by=created_by,
        approval_status=approval_status,
        approved_by=(created_by if approval_status == "approved" else None),
        approved_at=(now if approval_status == "approved" else None),
    )
    ca.set_name_constraints(constraints)
    ca.set_certificate_policies(policies)
    cert_der = backend_for_ca(parent_ca).sign_certificate(
        builder, parent_ca, secret=passphrase)
    ca.certificate_pem = x509.load_der_x509_certificate(cert_der).public_bytes(
        serialization.Encoding.PEM).decode()
    db.session.add(ca)
    db.session.commit()
    publish_initial_crl(ca, passphrase)
    return ca


def chain_pems(ca, via=None):
    """The CA chain as a list of PEMs, issuing CA first, up to the top.

    `via` (F11) is a CaCertificate alternate to route through: at the CA it
    belongs to, its PEM is used instead of the primary and the walk continues
    from the alternate's issuer (a cross-certificate) or the parent (a
    previous primary / pending re-issue). An alternate that is not usable
    (pending, or a cross-certificate from a revoked issuer) raises ValueError.
    """
    if via is not None and not via.is_usable:
        raise ValueError("That alternate certificate is not usable (pending approval or issued by a revoked CA).")
    chain, seen, current = [], set(), ca
    while current is not None and current.id not in seen:
        seen.add(current.id)
        if via is not None and via.ca_id == current.id:
            chain.append(via.certificate_pem)
            if via.kind == "cross":
                current = via.issuer            # None for an externally issued cross-cert: chain ends here
                continue
        else:
            chain.append(current.certificate_pem)
        current = current.parent
    return chain


def get_ca_chain(ca, via=None):
    return "\n".join(chain_pems(ca, via))


# --- F11: re-issue, cross-sign, alternates ------------------------------------

def _ca_cert_builder(ca, ca_cert, issuer_cert, validity_days, now, path_length):
    """Certificate for `ca`'s existing key and subject: same extensions as at
    creation (BasicConstraints, CA key usage, SKI, Name Constraints,
    Certificate Policies), issuer/AKI from `issuer_cert`, new serial."""
    not_after = bounded_not_after(now, validity_days, is_ca=True)  # callers clamp to the issuer's expiry
    serial = x509.random_serial_number()
    builder = (
        x509.CertificateBuilder()
        .subject_name(ca_cert.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(ca_cert.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value), critical=False)
    )
    nc_ext = name_constraints.build_extension(ca.name_constraints)
    if nc_ext is not None:
        builder = builder.add_extension(nc_ext, critical=True)
    cp_ext = certificate_policies.build_extension(ca.certificate_policies)
    if cp_ext is not None:
        builder = builder.add_extension(cp_ext, critical=False)
    return builder, serial, not_after


def _alternate_from_der(ca, kind, cert_der, issuer_ca_id, created_by, approval_status):
    cert = x509.load_der_x509_certificate(cert_der)
    now = datetime.now(timezone.utc)
    row = CaCertificate(
        ca_id=ca.id, kind=kind,
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        issuer_ca_id=issuer_ca_id, serial_number=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc,
        approval_status=approval_status, created_by=created_by,
        approved_by=(created_by if approval_status == "approved" else None),
        approved_at=(now if approval_status == "approved" else None),
    )
    db.session.add(row)
    db.session.flush()
    return row


def _promote_reissue(ca, row):
    """Make a re-issued certificate the primary; the old primary becomes a
    `previous` alternate (same key, so every leaf's AKI still matches)."""
    old_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    previous = CaCertificate(
        ca_id=ca.id, kind="previous", certificate_pem=ca.certificate_pem, issuer_ca_id=ca.parent_id,
        serial_number=ca.serial_number, not_before=old_cert.not_valid_before_utc,
        not_after=old_cert.not_valid_after_utc, approval_status="approved",
        created_by=row.created_by, approved_by=row.approved_by, approved_at=row.approved_at,
    )
    db.session.add(previous)
    new_cert = x509.load_pem_x509_certificate(row.certificate_pem.encode())
    ca.certificate_pem = row.certificate_pem
    ca.serial_number = row.serial_number
    ca.not_before = new_cert.not_valid_before_utc.replace(tzinfo=None)
    ca.not_after = new_cert.not_valid_after_utc.replace(tzinfo=None)
    ca.expiry_notified_at = None          # the expiry clock restarts (F10)
    db.session.delete(row)
    db.session.flush()
    return previous


def reissue_ca_certificate(ca, passphrase, validity_days=None, created_by=None, approval_status="approved"):
    """Issue a new certificate for `ca`'s existing key (same subject, SKI and
    extensions; new serial and validity), signed by the parent or self.
    With `approval_status="pending"` the certificate is stored as a `reissue`
    alternate until approved; otherwise it becomes the primary at once and the
    old primary is kept as `previous`. Returns the CaCertificate row (the
    `previous` row when promoted immediately). Flushes, does not commit."""
    if not ca.has_signing_key and ca.is_root:
        raise ValueError("A certificate-only root cannot re-issue its own certificate (no private key).")
    if ca.is_revoked:
        raise ValueError("A revoked CA cannot be re-issued.")
    if ca.approval_status == "pending":
        raise ValueError("This CA is awaiting dual-control approval.")
    issuer = ca if ca.is_root else ca.parent
    if issuer is None:
        raise ValueError("This CA's issuer is not in the database (imported without its chain); it cannot be re-issued here.")
    if issuer is not ca:
        if not issuer.has_signing_key or issuer.approval_status == "pending":
            raise ValueError("The parent CA cannot sign (no private key or awaiting approval).")
        if issuer.is_revoked:
            raise ValueError("The parent CA is revoked and cannot re-issue this CA.")
        if ca_expired_naive(issuer):
            raise ValueError("The parent CA has expired and cannot re-issue this CA.")
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    issuer_cert = x509.load_pem_x509_certificate(issuer.certificate_pem.encode())
    now = datetime.now(timezone.utc)
    if validity_days is None:
        validity_days = max(1, (ca.not_after - ca.not_before).days)
    if issuer is not ca:
        validity_days = min(validity_days, max(1, (issuer.not_after.replace(tzinfo=timezone.utc) - now).days))
    builder, serial, _ = _ca_cert_builder(ca, ca_cert, issuer_cert, validity_days, now, ca.path_length)
    cert_der = backend_for_ca(issuer).sign_certificate(builder, issuer, secret=passphrase)
    row = _alternate_from_der(ca, "reissue", cert_der, issuer.id if issuer is not ca else None,
                              created_by, approval_status)
    if approval_status == "approved":
        return _promote_reissue(ca, row)
    return row


def cross_sign_ca(ca, issuer, passphrase, validity_days=None, created_by=None, approval_status="approved"):
    """Have `issuer` certify `ca`'s existing public key: a cross-certificate
    stored as a `cross` alternate (the primary is untouched). Flushes, does
    not commit."""
    if issuer.id == ca.id:
        raise ValueError("A CA cannot cross-sign itself; use re-issue.")
    if ca.is_revoked:
        raise ValueError("A revoked CA cannot be cross-signed.")
    if not issuer.has_signing_key or issuer.approval_status == "pending" or issuer.is_revoked:
        raise ValueError("The issuing CA cannot sign (no private key, awaiting approval, or revoked).")
    if ca_expired_naive(issuer):
        raise ValueError("The issuing CA has expired.")
    # the issuer must not be below `ca` in the hierarchy (a loop would validate nothing)
    current = issuer
    while current is not None:
        if current.id == ca.id:
            raise ValueError("The issuing CA is a descendant of this CA; a cross-certificate would create a loop.")
        current = current.parent
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    issuer_cert = x509.load_pem_x509_certificate(issuer.certificate_pem.encode())
    subject_attrs = {attr.oid._name: attr.value for attr in ca_cert.subject}
    subject_attrs.setdefault("CN", ca.common_name)
    name_constraints.enforce(issuer, subject_attrs, [])  # F2: the issuer chain's constraints apply
    now = datetime.now(timezone.utc)
    if validity_days is None:
        validity_days = max(1, (ca.not_after - now.replace(tzinfo=None)).days)
    validity_days = min(validity_days, max(1, (issuer.not_after.replace(tzinfo=timezone.utc) - now).days))
    path_length = ca.path_length
    if issuer.path_length is not None:                    # PKI-6: honour the issuer's budget
        if issuer.path_length <= 0:
            raise ValueError("The issuing CA's path length is 0 — it cannot certify a CA.")
        allowed = issuer.path_length - 1
        if path_length is None or path_length > allowed:
            path_length = allowed
    builder, serial, _ = _ca_cert_builder(ca, ca_cert, issuer_cert, validity_days, now, path_length)
    cert_der = backend_for_ca(issuer).sign_certificate(builder, issuer, secret=passphrase)
    return _alternate_from_der(ca, "cross", cert_der, issuer.id, created_by, approval_status)


def import_alternate_certificate(ca, cert_pem, created_by=None):
    """Attach an externally issued certificate for this CA's key (e.g. a
    cross-certificate from another PKI) as a `cross` alternate. The issuer is
    linked when it is a CA in this database. Flushes, does not commit."""
    data = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
    if len(data) > MAX_PEM_SIZE:
        raise ValueError("Certificate PEM exceeds 64KB size limit.")
    try:
        cert = x509.load_pem_x509_certificates(data)[0]
    except Exception:
        raise ValueError("Failed to parse certificate PEM. Ensure it is a valid PEM-encoded certificate.")
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    same_key = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == \
        ca_cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if not same_key:
        raise ValueError("The certificate's public key does not match this CA's key.")
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise ValueError("The certificate has no BasicConstraints extension; it is not a CA certificate.")
    if not bc.ca:
        raise ValueError("The certificate is not a CA certificate (BasicConstraints ca=False).")
    serial_hex = format(cert.serial_number, "x")
    if serial_hex == ca.serial_number or any(a.serial_number == serial_hex for a in ca.alternate_certificates):
        raise ValueError("This certificate is already stored for the CA.")
    issuer_id = None if cert.issuer == cert.subject else _find_parent_by_issuer(cert)
    return _alternate_from_der(ca, "cross", cert.public_bytes(serialization.Encoding.DER), issuer_id, created_by, "approved")


def approve_alternate(row, approved_by):
    """Dual-control approval of a pending alternate; a pending re-issue is
    promoted to primary. Returns the row that now represents the change."""
    if row.approval_status != "pending":
        raise ValueError("This certificate is not awaiting approval.")
    row.approval_status = "approved"
    row.approved_by = approved_by
    row.approved_at = datetime.now(timezone.utc)
    if row.kind == "reissue":
        return _promote_reissue(row.ca, row)
    db.session.flush()
    return row


def delete_alternate(row):
    db.session.delete(row)
    db.session.flush()


def ca_expired_naive(ca, now=None):
    now = now or datetime.now(timezone.utc)
    not_after = ca.not_after if ca.not_after.tzinfo else ca.not_after.replace(tzinfo=timezone.utc)
    return not_after <= now


def _find_parent_by_issuer(cert):
    """Find an existing, non-revoked CA that actually issued `cert`.

    G4-7: subject-name equality alone is not proof of issuance — the candidate
    must also verify the certificate's signature. Returns the CA id or None.
    """
    for candidate in CertificateAuthority.query.filter_by(is_revoked=False).all():
        try:
            candidate_cert = x509.load_pem_x509_certificate(candidate.certificate_pem.encode())
            if candidate_cert.subject != cert.issuer:
                continue
            cert.verify_directly_issued_by(candidate_cert)
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

    enforce_public_key_strength(private_key.public_key())  # F5/G4-3: RSA, EC P-256/384/521, Ed25519, Ed448
    return private_key


def _key_info_from_public(public_key):
    return key_info(public_key)  # F5: RSA, EC P-256/384/521, Ed25519, Ed448; else ValueError


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
        # G4-2: never link a new CA under a revoked parent.
        if parent_ca.is_revoked:
            raise ValueError("The selected parent CA is revoked; a CA cannot be linked under it.")
        # G4-7: an explicitly chosen parent must have actually issued this
        # certificate (issuer name match + signature), the same check bundle
        # imports already apply.
        parent_cert = x509.load_pem_x509_certificate(parent_ca.certificate_pem.encode())
        try:
            cert.verify_directly_issued_by(parent_cert)
        except Exception as exc:
            raise ValueError("The certificate was not issued by the selected parent CA "
                             f"(issuer/signature check failed: {exc}).")
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
    ca.set_name_constraints(name_constraints.from_certificate(cert))  # F2: shown and enforced
    ca.set_certificate_policies(certificate_policies.from_certificate(cert))  # F3: inherited by leaves
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


def _apply_import_approval(ca, created_by, approval_status):
    """Stamp dual-control fields on an imported leaf CA and commit.

    Pending only makes sense for a CA that can sign; certificate-only imports
    auto-approve (they cannot issue anything anyway). Chain-imported parents
    are always certificate-only, so they keep the approved default.
    """
    ca.created_by = created_by
    if approval_status == "pending" and ca.has_signing_key:
        ca.approval_status = "pending"
        ca.approved_by = None
        ca.approved_at = None
    else:
        ca.approval_status = "approved"
        ca.approved_by = created_by
        ca.approved_at = datetime.now(timezone.utc)
    db.session.commit()


def import_ca(name, cert_pem, key_pem, passphrase, parent_id=None, key_passphrase=None,
              created_by=None, approval_status="approved"):
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
    _apply_import_approval(ca, created_by, approval_status)
    publish_initial_crl(ca, passphrase)
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


def import_pkcs12(name, p12_bytes, p12_password, passphrase, parent_id=None,
                  created_by=None, approval_status="approved"):
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

    if key is not None:
        enforce_public_key_strength(key.public_key())  # F5/G4-3: the same allow-list as the PEM path

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
    _apply_import_approval(ca, created_by, approval_status)
    publish_initial_crl(ca, passphrase)
    return ca
