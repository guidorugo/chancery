#!/usr/bin/env python3
"""Seed demo data for chancery.

Creates a realistic spread of Certificate Authorities, certificates, and CSRs
covering every lifecycle state so the UI, dashboard, metrics, and CRLs have
something to show:

  * CAs   — active (root + intermediate + EC root), expired, revoked
  * Certs — active, expiring-soon, expired, revoked (with varied reasons)
  * CSRs  — pending, approved (signed into a cert), rejected

Run it inside the app environment so it sees the real database and the
MASTER_PASSPHRASE:

    # Deployed box (Docker):
    docker compose exec app python scripts/seed_demo.py
    docker compose exec app python scripts/seed_demo.py --reset   # recreate

    # Local dev (venv active, .env exported):
    python scripts/seed_demo.py [--reset]

SAFETY
------
Everything created is tagged: CA names start with "Demo " and every leaf CN
ends in ".demo.example.com". `--reset` deletes *only* those objects, so it
never touches real data (e.g. the grugo.me test certificate). Without
`--reset`, the script refuses to run a second time rather than crash on the
unique CA-name constraint.

NOTE ON "EXPIRED"
-----------------
Issuance always stamps validity from *now* (the services enforce a positive
validity window), so an already-expired object cannot be minted directly. The
expired CAs/certs here are issued normally and then have their stored
notBefore/notAfter back-dated into the past — which is exactly what the app's
expiry badges, dashboard counts, and `/metrics` read. (The bytes inside the
PEM keep their original issue dates; that's fine for a demo.)
"""
import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

# Allow `python scripts/seed_demo.py` from the repo root (add repo root, not
# the scripts/ dir, to sys.path so `import app` resolves).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models.ca import CertificateAuthority  # noqa: E402
from app.models.certificate import Certificate  # noqa: E402
from app.models.csr import CertificateSigningRequest  # noqa: E402
from app.models.user import User  # noqa: E402
try:  # 2.25.0+: alternate CA certificates hang off a CA too
    from app.models.ca_certificate import CaCertificate  # noqa: E402
except ImportError:  # older app: nothing to clean up
    CaCertificate = None
from app.services import (  # noqa: E402
    ca_service, cert_service, crl_service, csr_service,
)
from app.services.keybackend import hsm_available  # noqa: E402

DEMO_DOMAIN = "demo.example.com"
DEMO_CA_PREFIX = "Demo "  # every demo CA name starts with this


def _utcnaive():
    """Naive-UTC 'now', matching how SQLite stores notBefore/notAfter."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- #
# reset                                                                        #
# --------------------------------------------------------------------------- #
def _destroy_hsm_key(label):
    """Best-effort removal of a demo CA's key objects from the SoftHSM token.
    The app has no CA-delete, so nothing else cleans these up — without this a
    repeated seed/--remove cycle would leave orphaned token objects behind."""
    try:
        import pkcs11
        from app.services.keybackend import pkcs11_session
        with pkcs11_session.session_scope() as session:
            for obj in list(session.get_objects({pkcs11.Attribute.LABEL: label})):
                obj.destroy()
    except Exception as exc:
        print(f"  (note: could not remove HSM key {label!r}: {exc})")


def _depth(ca):
    d, cur = 0, ca
    while cur.parent_id is not None and d < 32:
        cur = db.session.get(CertificateAuthority, cur.parent_id)
        if cur is None:
            break
        d += 1
    return d


def reset_demo(force=False):
    """Delete the seeded demo objects — and whatever depends on them.

    A certificate or CSR cannot outlive its issuing CA (`ca_id` is NOT NULL),
    so anything a demo CA issued goes too, even if it was created by hand
    outside the demo naming (it is listed). A *real* (non-demo) CA chained
    under a demo CA is refused unless `force`, because the app has no other
    way to delete a CA; with `force` its whole subtree goes as well.
    """
    cas = CertificateAuthority.query.filter(
        CertificateAuthority.name.like(f"{DEMO_CA_PREFIX}%")).all()
    ca_ids = {ca.id for ca in cas}
    foreign = []
    frontier = list(ca_ids)
    while frontier:                      # non-demo CAs anywhere below a demo CA
        kids = CertificateAuthority.query.filter(
            CertificateAuthority.parent_id.in_(frontier)).all() if frontier else []
        frontier = [k.id for k in kids if k.id not in ca_ids]
        for k in kids:
            if k.id not in ca_ids:
                foreign.append(k)
                ca_ids.add(k.id)
    if foreign and not force:
        names = ", ".join(f"#{c.id} {c.name!r}" for c in foreign)
        raise SystemExit(f"refusing: non-demo CA(s) chained under a demo CA: {names}. "
                         "Re-run with --remove --force to delete them (and everything they issued) too.")
    cas = cas + foreign

    certs = Certificate.query.filter(db.or_(
        Certificate.common_name.like(f"%{DEMO_DOMAIN}"),
        Certificate.ca_id.in_(ca_ids))).all() if ca_ids else Certificate.query.filter(
        Certificate.common_name.like(f"%{DEMO_DOMAIN}")).all()
    cert_ids = {c.id for c in certs}
    csr_filter = [CertificateSigningRequest.common_name.like(f"%{DEMO_DOMAIN}")]
    if ca_ids:
        csr_filter.append(CertificateSigningRequest.ca_id.in_(ca_ids))
    if cert_ids:
        csr_filter.append(CertificateSigningRequest.certificate_id.in_(cert_ids))
    csrs = CertificateSigningRequest.query.filter(db.or_(*csr_filter)).all()
    alternates = []
    if CaCertificate is not None and ca_ids:
        alternates = CaCertificate.query.filter(db.or_(
            CaCertificate.ca_id.in_(ca_ids), CaCertificate.issuer_ca_id.in_(ca_ids))).all()

    extra_certs = [c for c in certs if not c.common_name.endswith(DEMO_DOMAIN)]
    extra_csrs = [c for c in csrs if not c.common_name.endswith(DEMO_DOMAIN)]
    for label, items in (("certificate(s) issued by a demo CA", extra_certs),
                         ("CSR(s) tied to a demo CA", extra_csrs),
                         ("non-demo CA(s) chained under a demo CA (--force)", foreign)):
        if items:
            print(f"  also removing {len(items)} {label}: "
                  + ", ".join(f"#{c.id} {getattr(c, 'name', None) or c.common_name!r}" for c in items))

    # Wipe any SoftHSM-held demo keys before the DB rows that reference them.
    hsm = 0
    for ca in cas:
        if getattr(ca, "key_backend", "software") == "softhsm" and ca.key_label:
            _destroy_hsm_key(ca.key_label)
            hsm += 1

    for c in csrs:            # drop CSR->cert references first
        db.session.delete(c)
    db.session.commit()
    for c in certs:           # then the leaf certificates
        db.session.delete(c)
    db.session.commit()
    for a in alternates:      # alternate CA certificates (cross-signs, previous primaries)
        db.session.delete(a)
    db.session.commit()
    for ca in sorted(cas, key=_depth, reverse=True):  # deepest first: children before parents
        db.session.delete(ca)
    db.session.commit()
    print(f"  reset: removed {len(csrs)} CSRs, {len(certs)} certs, {len(cas)} CAs"
          + (f", {len(alternates)} alternate CA cert(s)" if alternates else "")
          + (f", {hsm} HSM key(s)" if hsm else ""))


# --------------------------------------------------------------------------- #
# small helpers over the services                                             #
# --------------------------------------------------------------------------- #
class Seeder:
    def __init__(self, app):
        self.passphrase = app.config["MASTER_PASSPHRASE"]
        server = app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
        self.scheme = app.config.get("OCSP_URL_SCHEME", "http")
        self.server = server
        self.admin = User.query.filter_by(
            role="admin", is_active_user=True).first()

    def _urls(self, ca):
        base = f"{self.scheme}://{self.server}/public"
        return f"{base}/ocsp/{ca.id}", f"{base}/crl/{ca.id}.crl"

    # -- CAs ----------------------------------------------------------------
    def root_ca(self, name, cn, key_type="RSA", key_size=2048, years=10,
                backend="software"):
        ca = ca_service.create_root_ca(
            name=name, subject_attrs={"CN": cn, "O": "Demo Corp", "C": "US"},
            key_type=key_type, key_size=key_size, validity_days=years * 365,
            passphrase=self.passphrase, backend=backend)
        tag = "  [HSM]" if backend == "softhsm" else ""
        print(f"  + root CA        {name}  ({key_type}-{key_size}){tag}")
        return ca

    def intermediate_ca(self, name, cn, parent, key_type="RSA", key_size=2048,
                        years=5, backend="software"):
        ca = ca_service.create_intermediate_ca(
            name=name, parent_ca=parent,
            subject_attrs={"CN": cn, "O": "Demo Corp", "C": "US"},
            key_type=key_type, key_size=key_size, validity_days=years * 365,
            passphrase=self.passphrase, backend=backend, path_length=0)
        tag = "  [HSM]" if backend == "softhsm" else ""
        print(f"  + intermediate   {name}  (under {parent.name}){tag}")
        return ca

    # -- leaf certs ---------------------------------------------------------
    def cert(self, ca, cn, sans=None, eku=None, validity_days=365, own=True,
             key_type="RSA", key_size=2048):
        ocsp_url, crl_dp = self._urls(ca)
        c = cert_service.create_certificate(
            ca=ca, subject_attrs={"CN": cn, "O": "Demo Corp", "C": "US"},
            san_list=sans or [cn], validity_days=validity_days,
            passphrase=self.passphrase, key_type=key_type, key_size=key_size,
            extended_key_usage=eku, ocsp_url=ocsp_url, crl_dp_url=crl_dp)
        if own and self.admin:
            c.requested_by = self.admin.id
            db.session.commit()
        return c

    # -- state mutators (post-issuance) -------------------------------------
    @staticmethod
    def backdate(obj, issued_days_ago, valid_days):
        """Move an object's validity window fully into the past → expired."""
        nb = _utcnaive() - timedelta(days=issued_days_ago)
        obj.not_before = nb
        obj.not_after = nb + timedelta(days=valid_days)
        db.session.commit()

    @staticmethod
    def expiring_soon(obj, days_left=12, valid_days=365):
        now = _utcnaive()
        obj.not_after = now + timedelta(days=days_left)
        obj.not_before = obj.not_after - timedelta(days=valid_days)
        db.session.commit()

    def revoke_cert(self, cert, reason):
        crl_service.revoke_certificate(cert.id, reason=reason,
                                       passphrase=self.passphrase)

    def revoke_ca(self, ca, reason):
        crl_service.revoke_ca(ca.id, reason=reason, passphrase=self.passphrase)

    # -- CSRs ---------------------------------------------------------------
    def csr(self, cn, sans=None, key_type="RSA", key_size=2048):
        created_by = self.admin.id if self.admin else None
        csr_model, _key, _enc = csr_service.create_csr(
            subject_attrs={"CN": cn, "O": "Demo Corp", "C": "US"},
            san_list=sans or [cn], key_type=key_type, key_size=key_size,
            passphrase=self.passphrase, created_by=created_by)
        return csr_model

    def sign_csr(self, csr_model, ca, validity_days=365):
        ocsp_url, crl_dp = self._urls(ca)
        return cert_service.sign_csr(
            csr_model, ca, validity_days=validity_days,
            passphrase=self.passphrase, ocsp_url=ocsp_url, crl_dp_url=crl_dp)

    @staticmethod
    def reject_csr(csr_model):
        csr_model.status = "rejected"
        db.session.commit()


# --------------------------------------------------------------------------- #
# the dataset                                                                  #
# --------------------------------------------------------------------------- #
def seed(app):
    s = Seeder(app)

    print("CAs:")
    root = s.root_ca("Demo Root CA", "Demo Root CA", key_size=4096, years=10)
    issuing = s.intermediate_ca("Demo Issuing CA", "Demo Issuing CA", root, years=5)
    ec_root = s.root_ca("Demo EC Root CA", "Demo EC Root CA",
                        key_type="EC", key_size=256, years=8)
    legacy = s.root_ca("Demo Legacy Root CA", "Demo Legacy Root CA", years=5)
    compromised = s.root_ca("Demo Compromised CA", "Demo Compromised CA", years=5)

    # A SoftHSM-backed intermediate (its signing key lives in the PKCS#11 token,
    # never in Python memory) — only when the HSM is configured, so a plain venv
    # without SoftHSM still works.
    hsm_ca = None
    if hsm_available():
        hsm_ca = s.intermediate_ca("Demo HSM Issuing CA", "Demo HSM Issuing CA",
                                   root, years=5, backend="softhsm")
    else:
        print("  ~ SoftHSM not available — skipping the HSM-backed CA")

    print("Certificates:")
    # --- active (deliberately mixed key types, not all RSA-2048) ---
    s.cert(issuing, f"www.{DEMO_DOMAIN}",
           sans=[f"www.{DEMO_DOMAIN}", DEMO_DOMAIN], eku=["serverAuth"],
           validity_days=730, key_type="EC", key_size=256)
    s.cert(issuing, f"api.{DEMO_DOMAIN}", eku=["serverAuth"],
           key_type="RSA", key_size=2048)
    s.cert(issuing, f"client.{DEMO_DOMAIN}", eku=["clientAuth"],
           key_type="EC", key_size=384)
    s.cert(issuing, f"support@{DEMO_DOMAIN}", sans=[f"support@{DEMO_DOMAIN}"],
           eku=["emailProtection"], key_type="RSA", key_size=4096)
    s.cert(ec_root, f"ec-service.{DEMO_DOMAIN}", eku=["serverAuth"],
           key_type="EC", key_size=256)
    print("  + 5 active (EC P-256/P-384, RSA 2048/4096)")

    # --- issued by the HSM CA ---
    if hsm_ca:
        s.cert(hsm_ca, f"hsm-web.{DEMO_DOMAIN}", eku=["serverAuth"],
               key_type="EC", key_size=256)
        s.cert(hsm_ca, f"hsm-client.{DEMO_DOMAIN}", eku=["clientAuth"],
               key_type="RSA", key_size=2048)
        print("  + 2 issued by the HSM CA")

    # --- expiring soon ---
    soon = s.cert(issuing, f"expiring-soon.{DEMO_DOMAIN}", eku=["serverAuth"],
                  key_type="EC", key_size=256)
    s.expiring_soon(soon, days_left=12)
    print("  + 1 expiring-soon (~12 days left)")

    # --- expired (back-dated) ---
    exp1 = s.cert(issuing, f"expired.{DEMO_DOMAIN}", eku=["serverAuth"],
                  key_type="RSA", key_size=2048)
    s.backdate(exp1, issued_days_ago=800, valid_days=365)        # expired ~435d ago
    legacy_leaf = s.cert(legacy, f"legacy-app.{DEMO_DOMAIN}", eku=["serverAuth"],
                         key_type="EC", key_size=256)
    s.backdate(legacy_leaf, issued_days_ago=1200, valid_days=730)
    print("  + 2 expired")

    # --- revoked, with varied reasons ---
    r1 = s.cert(issuing, f"revoked-keycomp.{DEMO_DOMAIN}", eku=["serverAuth"],
                key_type="RSA", key_size=4096)
    s.revoke_cert(r1, "key_compromise")
    r2 = s.cert(issuing, f"superseded.{DEMO_DOMAIN}", eku=["serverAuth"],
                key_type="EC", key_size=256)
    s.revoke_cert(r2, "superseded")
    r3 = s.cert(issuing, f"cessation.{DEMO_DOMAIN}", eku=["clientAuth"],
                key_type="RSA", key_size=2048)
    s.revoke_cert(r3, "cessation_of_operation")
    print("  + 3 revoked (key_compromise, superseded, cessation_of_operation)")

    print("CA state changes:")
    # Give the doomed CAs a leaf each so the demo shows whole affected branches.
    s.cert(compromised, f"comp-service.{DEMO_DOMAIN}", eku=["serverAuth"],
           key_type="EC", key_size=256)
    s.revoke_ca(compromised, "ca_compromise")          # cascades to its leaf
    print(f"  ~ {compromised.name} revoked (ca_compromise) — its cert revoked too")
    s.backdate(legacy, issued_days_ago=2000, valid_days=1825)   # expired ~175d ago
    print(f"  ~ {legacy.name} back-dated to expired")

    print("CSRs:")
    s.csr(f"pending-web.{DEMO_DOMAIN}", sans=[f"pending-web.{DEMO_DOMAIN}"])
    s.csr(f"pending-client.{DEMO_DOMAIN}", key_type="EC", key_size=256)
    print("  + 2 pending")
    signed = s.csr(f"signed.{DEMO_DOMAIN}", key_type="EC", key_size=256)
    s.sign_csr(signed, issuing, validity_days=365)     # -> approved + a new cert
    print("  + 1 approved (signed into a certificate)")
    rejected = s.csr(f"rejected.{DEMO_DOMAIN}")
    s.reject_csr(rejected)
    print("  + 1 rejected")


# --------------------------------------------------------------------------- #
# summary                                                                      #
# --------------------------------------------------------------------------- #
def _ca_state(ca):
    if ca.is_revoked:
        return "revoked"
    return "expired" if ca.expiry_status == "expired" else "active"


def _cert_state(c):
    if c.is_revoked:
        return "revoked"
    return c.expiry_status  # valid | expiring_soon | expired


def summary():
    cas = CertificateAuthority.query.filter(
        CertificateAuthority.name.like(f"{DEMO_CA_PREFIX}%")).all()
    certs = Certificate.query.filter(
        Certificate.common_name.like(f"%{DEMO_DOMAIN}")).all()
    csrs = CertificateSigningRequest.query.filter(
        CertificateSigningRequest.common_name.like(f"%{DEMO_DOMAIN}")).all()

    def tally(items, fn):
        out = {}
        for it in items:
            k = fn(it)
            out[k] = out.get(k, 0) + 1
        return out

    def fmt(items, fn):
        return ", ".join(f"{k}={v}" for k, v in sorted(tally(items, fn).items()))

    print("\n=== demo data summary ===")
    print(f"CAs   ({len(cas):2d}): {fmt(cas, _ca_state)}")
    print(f"          backends: {fmt(cas, lambda c: c.key_backend)}")
    print(f"Certs ({len(certs):2d}): {fmt(certs, _cert_state)}")
    print(f"          key types: {fmt(certs, lambda c: c.key_type + str(c.key_size))}")
    print(f"CSRs  ({len(csrs):2d}): {fmt(csrs, lambda c: c.status)}")


def main():
    parser = argparse.ArgumentParser(
        description="Seed or remove chancery demo data.")
    parser.add_argument("--remove", action="store_true",
                        help="remove previously-seeded demo objects and exit (no reseed)")
    parser.add_argument("--force", action="store_true",
                        help="with --remove/--reset: also delete non-demo CAs chained under a demo CA")
    parser.add_argument("--reset", action="store_true",
                        help="remove previously-seeded demo objects, then reseed")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        existing = CertificateAuthority.query.filter(
            CertificateAuthority.name.like(f"{DEMO_CA_PREFIX}%")).count()

        # --remove: delete the demo objects and stop (the cleanup the API can't do).
        if args.remove:
            if existing:
                reset_demo(force=args.force)
                print("Removed all demo data.")
            else:
                print("No demo data found — nothing to remove.")
            return 0

        if existing and not args.reset:
            print(f"Demo data already present ({existing} demo CAs). "
                  "Re-run with --reset to recreate, or --remove to delete it.")
            return 0
        if args.reset and existing:
            print("Resetting existing demo data...")
            reset_demo(force=args.force)

        seed(app)
        summary()
        print("\nDone. Log in and browse /ca, /certificates, and /csr.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
