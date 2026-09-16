import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from ..extensions import db
from ..models.certificate import Certificate
from .crypto_utils import encrypt_private_key, decrypt_private_key, generate_key, key_info
from .policy import (enforce_public_key_strength, bounded_not_after, build_subject)
from .keybackend import backend_for_ca
from . import certificate_policies, name_constraints, profile_service, san


def _build_san(san_list):
    """F4: SAN syntax lives in `services.san` (DNS/IP/EMAIL/URI/UPN; unknown
    prefixes are refused instead of becoming DNS names — G4-4)."""
    return san.build_extension(san_list)


EKU_MAP = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "ocspSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
}


class CsrAlreadyProcessed(ValueError):
    """The CSR is no longer pending: already signed or rejected, or a concurrent
    request is signing it right now (G7-4)."""


def _claim_csr(csr_model):
    """G7-4: atomically move the CSR from `pending` to `signing` so two workers
    cannot both issue from one CSR (the route's status check is check-then-act).
    Committed immediately so the claim is visible to the other worker."""
    from sqlalchemy import update
    from ..models.csr import CertificateSigningRequest

    result = db.session.execute(
        update(CertificateSigningRequest)
        .where(CertificateSigningRequest.id == csr_model.id,
               CertificateSigningRequest.status == "pending")
        .values(status="signing")
    )
    if result.rowcount != 1:
        db.session.rollback()
        raise CsrAlreadyProcessed("This CSR has already been processed.")
    db.session.commit()
    db.session.refresh(csr_model)


def _release_csr(csr_model):
    """Undo a claim after a signing failure so the CSR can be retried."""
    from sqlalchemy import update
    from ..models.csr import CertificateSigningRequest

    db.session.rollback()
    db.session.execute(
        update(CertificateSigningRequest)
        .where(CertificateSigningRequest.id == csr_model.id,
               CertificateSigningRequest.status == "signing")
        .values(status="pending")
    )
    db.session.commit()
    try:
        db.session.refresh(csr_model)
    except Exception:
        pass


def sign_csr(csr_model, ca, validity_days, passphrase, san_list=None,
             key_usage=None, extended_key_usage=None, ocsp_url=None,
             crl_dp_url=None, signed_by=None, profile=None):
    if not ca.has_signing_key:
        raise ValueError("This CA was imported without its private key and cannot issue certificates.")
    if ca.approval_status == "pending":
        raise ValueError("This CA is awaiting dual-control approval and cannot issue certificates yet.")
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    csr = x509.load_pem_x509_csr(csr_model.csr_pem.encode())

    # Proof-of-possession (B1): the CSR must be validly self-signed, proving
    # the requester holds the private key for the embedded public key.
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid (proof-of-possession failed); refusing to sign.")
    enforce_public_key_strength(csr.public_key())  # B5

    # F1: bound the request by the profile (key from the CSR, SANs as they
    # will be issued) before claiming the CSR.
    effective_san = san_list
    if not effective_san and csr_model.san_json:
        effective_san = json.loads(csr_model.san_json)
    key_type, key_size = key_info(csr.public_key())
    key_usage, extended_key_usage, include_aia = profile_service.enforce(
        profile, key_type=key_type, key_size=key_size, validity_days=validity_days,
        san_list=effective_san, common_name=csr_model.common_name,
        key_usage=key_usage, extended_key_usage=extended_key_usage)
    name_constraints.enforce(ca, {"CN": csr_model.common_name}, effective_san)  # F2

    _claim_csr(csr_model)
    try:
        return _sign_claimed_csr(csr_model, csr, ca, ca_cert, validity_days, passphrase,
                                 san_list, key_usage, extended_key_usage, ocsp_url,
                                 crl_dp_url, signed_by, include_aia=include_aia,
                                 profile_id=profile.id if profile is not None else None,
                                 policies=certificate_policies.for_issuance(ca, profile))
    except Exception:
        _release_csr(csr_model)
        raise


def _leaf_builder(ca, ca_cert, subject, public_key, validity_days, key_usage,
                  extended_key_usage, san_list, ocsp_url, crl_dp_url, include_aia=True,
                  policies=None):
    """The end-entity CertificateBuilder shared by direct issuance, CSR signing
    and renewal: BasicConstraints CA:FALSE, SKI/AKI, Key Usage (defaults:
    digitalSignature + keyEncipherment), EKU (defaults: serverAuth +
    clientAuth), SAN, optional OCSP AIA and CRL DP. Returns
    (builder, not_before, serial)."""
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
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
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

    # OCSP AIA extension (a profile may opt out of AIA)
    if ocsp_url and include_aia:
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

    # Certificate Policies (F3): the profile's list, else the issuing CA's
    if policies:
        builder = builder.add_extension(certificate_policies.build_extension(policies), critical=False)
    return builder, now, serial


def _sign_claimed_csr(csr_model, csr, ca, ca_cert, validity_days, passphrase,
                      san_list, key_usage, extended_key_usage, ocsp_url,
                      crl_dp_url, signed_by, include_aia=True, profile_id=None, policies=None):
    effective_san = san_list
    if not effective_san and csr_model.san_json:
        effective_san = json.loads(csr_model.san_json)

    builder, now, serial = _leaf_builder(
        ca, ca_cert, csr.subject, csr.public_key(), validity_days, key_usage,
        extended_key_usage, effective_san, ocsp_url, crl_dp_url, include_aia, policies=policies)
    cert_der = backend_for_ca(ca).sign_certificate(builder, ca, secret=passphrase)
    cert = x509.load_der_x509_certificate(cert_der)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    key_type, key_size = key_info(csr.public_key())

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
        not_before=cert.not_valid_before_utc.replace(tzinfo=None),
        # PKI-3: store the certificate's ACTUAL notAfter (clamped to the CA's
        # expiry and second-truncated), not the raw requested window — the DB
        # must not overstate expiry.
        not_after=cert.not_valid_after_utc.replace(tzinfo=None),
        san_json=json.dumps(effective_san) if effective_san else csr_model.san_json,
        key_usage_json=json.dumps(key_usage) if key_usage else None,
        extended_key_usage_json=json.dumps(extended_key_usage) if extended_key_usage else None,
        requested_by=csr_model.created_by,
        issued_by=signed_by,
        profile_id=profile_id,
    )
    db.session.add(certificate)
    db.session.flush()

    csr_model.status = "approved"
    csr_model.certificate_id = certificate.id
    csr_model.ca_id = ca.id
    csr_model.signed_by = signed_by

    db.session.commit()
    return certificate


def create_certificate(ca, subject_attrs, san_list, validity_days, passphrase,
                       key_type="RSA", key_size=2048, key_usage=None,
                       extended_key_usage=None, ocsp_url=None,
                       crl_dp_url=None, issued_by=None, profile=None):
    if not ca.has_signing_key:
        raise ValueError("This CA was imported without its private key and cannot issue certificates.")
    if ca.approval_status == "pending":
        raise ValueError("This CA is awaiting dual-control approval and cannot issue certificates yet.")
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())

    # F1: the profile is policy — for a named profile the Key Usage / EKU are
    # its own, and the request is bounded by it before any key is generated.
    key_usage, extended_key_usage, include_aia = profile_service.enforce(
        profile, key_type=key_type, key_size=key_size, validity_days=validity_days,
        san_list=san_list, common_name=subject_attrs.get("CN"),
        key_usage=key_usage, extended_key_usage=extended_key_usage)

    name_constraints.enforce(ca, subject_attrs, san_list)  # F2: before any key is generated

    key = generate_key(key_type, key_size)
    key_type, key_size = key_info(key)  # canonical (an Edwards key has a fixed size)
    subject = build_subject(subject_attrs)

    builder, now, serial = _leaf_builder(
        ca, ca_cert, subject, key.public_key(), validity_days, key_usage,
        extended_key_usage, san_list, ocsp_url, crl_dp_url, include_aia,
        policies=certificate_policies.for_issuance(ca, profile))
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
        not_before=cert.not_valid_before_utc.replace(tzinfo=None),
        # PKI-3: store the certificate's ACTUAL notAfter (clamped to the CA's
        # expiry and second-truncated), not the raw requested window — the DB
        # must not overstate expiry.
        not_after=cert.not_valid_after_utc.replace(tzinfo=None),
        san_json=json.dumps(san_list) if san_list else None,
        key_usage_json=json.dumps(key_usage) if key_usage else None,
        extended_key_usage_json=json.dumps(extended_key_usage) if extended_key_usage else None,
        issued_by=issued_by,
        profile_id=profile.id if profile is not None else None,
    )
    db.session.add(certificate)
    db.session.commit()
    return certificate


# --- renewal (F9, 2.19.0) ------------------------------------------------------

class AlreadyRenewed(ValueError):
    """The certificate already has a renewal (superseded); pass force=True to
    issue another one anyway."""


def original_validity_days(certificate):
    """The window the certificate was issued with (at least 1 day) — the
    default validity of its renewal."""
    return max(1, (_naive(certificate.not_after) - _naive(certificate.not_before)).days)


def _naive(dt):
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


def renew_certificate(old, passphrase, *, validity_days=None, rekey=False, revoke_old=False,
                      ocsp_url=None, crl_dp_url=None, issued_by=None, force=False):
    """Issue a successor for `old` from the same CA with the same subject,
    SANs, Key Usage / EKU and profile (re-checked against the profile as it
    is *now*), and link it via `renewed_from_id`.

    - `rekey=False` keeps the public key: the escrowed private key (direct
      issuance) is carried over as-is, a CSR-signed certificate's key stays
      with its owner. The reused key is re-checked against the current key
      policy (B5).
    - `rekey=True` generates a fresh key of the same type/size; only possible
      when the private key is escrowed (a CSR-signed certificate needs a new
      CSR instead).
    - A revoked certificate can only be renewed with a new key (its old one
      may be compromised). A certificate that already has a renewal raises
      AlreadyRenewed unless `force`.
    - `revoke_old` revokes the old certificate with reason `superseded` in
      the same transaction.

    Nothing is committed: the caller commits together with its audit row
    (G10-1) and refreshes the CRL afterwards when it revoked the old one.
    """
    from . import crl_service

    ca = old.ca
    if ca.is_revoked:
        raise ValueError("The issuing CA is revoked; the certificate cannot be renewed.")
    if not ca.has_signing_key:
        raise ValueError("The issuing CA has no private key and cannot issue certificates.")
    if ca.approval_status == "pending":
        raise ValueError("The issuing CA is awaiting dual-control approval and cannot issue certificates yet.")
    if old.renewals and not force:
        raise AlreadyRenewed(
            f"Certificate #{old.id} was already renewed as #{old.renewals[-1].id}; pass force to renew it again.")
    if rekey and not old.private_key_enc:
        raise ValueError("This certificate was issued from a CSR, so the CA holds no private key to replace — "
                         "submit a new CSR to re-key it.")
    if old.is_revoked and not rekey:
        raise ValueError("A revoked certificate can only be renewed with a new key (its key may be compromised).")
    profile = old.profile
    if profile is not None and not profile.enabled:
        raise ValueError(f"Certificate profile '{profile.name}' is disabled; enable it or issue a new certificate.")

    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    old_cert = x509.load_pem_x509_certificate(old.certificate_pem.encode())
    san_list = json.loads(old.san_json) if old.san_json else []
    key_usage = json.loads(old.key_usage_json) if old.key_usage_json else None
    extended_key_usage = json.loads(old.extended_key_usage_json) if old.extended_key_usage_json else None

    if validity_days is None:
        validity_days = original_validity_days(old)
        if profile is not None and profile.max_validity_days:
            validity_days = min(validity_days, profile.max_validity_days)
    key_usage, extended_key_usage, include_aia = profile_service.enforce(
        profile, key_type=old.key_type, key_size=old.key_size, validity_days=validity_days,
        san_list=san_list, common_name=old.common_name,
        key_usage=key_usage, extended_key_usage=extended_key_usage)
    name_constraints.enforce(ca, {"CN": old.common_name}, san_list)  # F2 (a re-imported CA may constrain)

    if rekey:
        key = generate_key(old.key_type, old.key_size)
        public_key = key.public_key()
        enc_key = encrypt_private_key(key, passphrase)
    else:
        public_key = old_cert.public_key()
        enforce_public_key_strength(public_key)  # B5: policy may have tightened since
        enc_key = old.private_key_enc            # same ciphertext, same passphrase

    builder, now, serial = _leaf_builder(
        ca, ca_cert, old_cert.subject, public_key, validity_days, key_usage,
        extended_key_usage, san_list, ocsp_url, crl_dp_url, include_aia,
        policies=certificate_policies.for_issuance(ca, profile))
    cert_der = backend_for_ca(ca).sign_certificate(builder, ca, secret=passphrase)
    cert = x509.load_der_x509_certificate(cert_der)

    new = Certificate(
        serial_number=format(serial, "x"),
        common_name=old.common_name,
        subject_json=old.subject_json,
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        private_key_enc=enc_key,
        ca_id=ca.id,
        key_type=old.key_type,
        key_size=old.key_size,
        not_before=cert.not_valid_before_utc.replace(tzinfo=None),
        not_after=cert.not_valid_after_utc.replace(tzinfo=None),
        san_json=old.san_json,
        key_usage_json=json.dumps(key_usage) if key_usage else None,
        extended_key_usage_json=json.dumps(extended_key_usage) if extended_key_usage else None,
        requested_by=old.requested_by,
        issued_by=issued_by,
        profile_id=old.profile_id,
        renewed_from_id=old.id,
    )
    db.session.add(new)
    db.session.flush()
    if revoke_old and not old.is_revoked:
        crl_service.revoke_certificate(old.id, "superseded", passphrase=passphrase,
                                       commit=False, refresh=False)
    return new


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
