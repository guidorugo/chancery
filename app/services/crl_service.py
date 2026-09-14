from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import CRLEntryExtensionOID

from ..extensions import db
from ..models.ca import CertificateAuthority
from ..models.certificate import Certificate
from .keybackend import backend_for_ca


REVOCATION_REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}


def refresh_crl(ca, passphrase):
    """Regenerate and cache the CRL for a CA that holds a signing key.

    No-op (returns None) for certificate-only CAs, which cannot sign a CRL,
    and for dual-control pending CAs (revoking one must not 500).
    """
    if not ca or not ca.has_signing_key or ca.approval_status == "pending":
        return None
    return generate_crl(ca, passphrase)


def revoke_certificate(cert_id, reason="unspecified", passphrase=None, *,
                       commit=True, refresh=True):
    """Mark a certificate revoked.

    G10-1: the routes pass commit=False/refresh=False so the audit row lands in
    the same transaction as the state change, and run the CRL refresh
    themselves afterwards (a refresh failure must not lose the audit row or
    turn an already-persisted revocation into a 500).
    """
    if reason not in REVOCATION_REASONS:
        raise ValueError("Invalid revocation reason.")
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        raise ValueError("Certificate not found")
    if certificate.is_revoked:
        raise ValueError("Certificate is already revoked")

    certificate.is_revoked = True
    certificate.revoked_at = datetime.now(timezone.utc)
    certificate.revocation_reason = reason
    if commit:
        db.session.commit()

    # B2: publish the revocation immediately by regenerating the issuing CA's
    # CRL, instead of serving a stale cached CRL until a manual regeneration.
    if refresh and passphrase is not None:
        refresh_crl(certificate.ca, passphrase)
    return certificate


def _revoked_subtree(ca):
    """`ca` plus every revoked descendant, depth-first."""
    out = [ca]
    for child in ca.children:
        if child.is_revoked:
            out.extend(_revoked_subtree(child))
    return out


def publish_final_crl(ca, passphrase):
    """G4-8: a revoked CA can never regenerate its CRL again (the UI, CLI and
    scheduler all skip revoked CAs), so its last CRL must stay valid until the
    CA certificate itself expires — otherwise validators of an old leaf see
    "CRL expired" instead of "revoked". No-op for keyless/pending/expired CAs.
    """
    if not ca or not ca.has_signing_key or ca.approval_status == "pending":
        return None
    not_after = ca.not_after if ca.not_after.tzinfo else ca.not_after.replace(tzinfo=timezone.utc)
    if not_after <= datetime.now(timezone.utc):
        return None
    return generate_crl(ca, passphrase, next_update=not_after)


def publish_revocation_crls(ca, passphrase):
    """CRL publication after `revoke_ca`: the parent's CRL now lists the revoked
    intermediate (B3), and every CA in the revoked subtree publishes a final CRL
    covering its now-revoked leaves (G4-8)."""
    refresh_crl(ca.parent, passphrase)
    for rca in _revoked_subtree(ca):
        publish_final_crl(rca, passphrase)


def revoke_ca(ca_id, reason="unspecified", passphrase=None, *, commit=True, refresh=True):
    if reason not in REVOCATION_REASONS:
        raise ValueError("Invalid revocation reason.")
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        raise ValueError("CA not found")
    if ca.is_revoked:
        raise ValueError("CA is already revoked")

    now = datetime.now(timezone.utc)
    certs_revoked = 0
    sub_cas_revoked = 0
    revoked_cas = []

    def _revoke_ca_recursive(target_ca):
        nonlocal certs_revoked, sub_cas_revoked

        target_ca.is_revoked = True
        target_ca.revoked_at = now
        target_ca.revocation_reason = reason
        revoked_cas.append(target_ca)

        # Revoke all non-revoked certificates issued by this CA
        active_certs = Certificate.query.filter_by(ca_id=target_ca.id, is_revoked=False).all()
        for cert in active_certs:
            cert.is_revoked = True
            cert.revoked_at = now
            cert.revocation_reason = reason
            certs_revoked += 1

        # Recursively revoke child CAs
        for child_ca in target_ca.children:
            if not child_ca.is_revoked:
                sub_cas_revoked += 1
                _revoke_ca_recursive(child_ca)

    _revoke_ca_recursive(ca)
    if commit:
        db.session.commit()

    if refresh and passphrase is not None:
        publish_revocation_crls(ca, passphrase)
    return ca, certs_revoked, sub_cas_revoked


def generate_crl(ca, passphrase, validity_days=None, next_update=None):
    """Sign and cache a fresh CRL. `next_update` (aware datetime) overrides the
    `validity_days` window — used for a revoked CA's final CRL (G4-8)."""
    if not ca.has_signing_key:
        raise ValueError("This CA was imported without its private key and cannot sign CRLs.")
    if ca.approval_status == "pending":
        raise ValueError("This CA is awaiting dual-control approval and cannot sign CRLs yet.")
    if validity_days is None:
        # PKI-1: configurable CRL validity window (default 7 days).
        try:
            from flask import current_app
            validity_days = current_app.config.get("CRL_VALIDITY_DAYS", 7)
        except RuntimeError:
            validity_days = 7
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())

    now = datetime.now(timezone.utc)
    if next_update is None:
        next_update = now + timedelta(days=validity_days)
    # F3: atomic increment so concurrent workers can't mint duplicate CRL numbers.
    db.session.query(CertificateAuthority).filter(
        CertificateAuthority.id == ca.id
    ).update(
        {CertificateAuthority.crl_number: CertificateAuthority.crl_number + 1},
        synchronize_session=False,
    )
    db.session.refresh(ca)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
        .add_extension(
            x509.CRLNumber(ca.crl_number),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            ),
            critical=False,
        )
    )

    # Revoked leaf certificates issued by this CA, plus (B3) revoked sub-CAs
    # this CA issued — a revoked intermediate must appear on its parent's CRL.
    revoked_entries = [
        (c.serial_number, c.revoked_at, c.revocation_reason)
        for c in Certificate.query.filter_by(ca_id=ca.id, is_revoked=True).all()
    ]
    revoked_entries += [
        (sub.serial_number, sub.revoked_at, sub.revocation_reason)
        for sub in CertificateAuthority.query.filter_by(parent_id=ca.id, is_revoked=True).all()
    ]
    for serial_hex, revoked_at, reason_str in revoked_entries:
        revoked_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(serial_hex, 16))
            .revocation_date(revoked_at or now)
        )

        reason = REVOCATION_REASONS.get(reason_str, x509.ReasonFlags.unspecified)
        revoked_builder = revoked_builder.add_extension(
            x509.CRLReason(reason),
            critical=False,
        )

        builder = builder.add_revoked_certificate(revoked_builder.build())

    crl_der = backend_for_ca(ca).sign_crl(builder, ca, secret=passphrase)
    crl = x509.load_der_x509_crl(crl_der)

    # Cache the CRL on the CA for public download
    ca.crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()
    db.session.commit()
    return crl


def get_crl_pem(ca, passphrase):
    if ca.crl_pem:
        return ca.crl_pem.encode()
    crl = generate_crl(ca, passphrase)
    return crl.public_bytes(serialization.Encoding.PEM)


def get_crl_der(ca, passphrase):
    if ca.crl_pem:
        crl = x509.load_pem_x509_crl(ca.crl_pem.encode())
        return crl.public_bytes(serialization.Encoding.DER)
    crl = generate_crl(ca, passphrase)
    return crl.public_bytes(serialization.Encoding.DER)
