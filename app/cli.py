"""Flask CLI commands for CA key-backend management (A1).

`flask keys migrate-to-hsm` moves software CA signing keys into the PKCS#11
token. This is intentionally one-way: after migration the key is non-extractable
and the encrypted software copy is scrubbed, so the trust anchor can no longer be
read off the host. Back up any key you might need to export BEFORE migrating.
"""
import click
from flask import current_app
from flask.cli import AppGroup

from .extensions import db
from .models.ca import CertificateAuthority
from .services.crypto_utils import decrypt_private_key
from .services.keybackend import get_backend, hsm_available
from .services.ca_service import _key_label

keys_cli = AppGroup("keys", help="CA key-backend management.")


@keys_cli.command("migrate-to-hsm")
@click.option("--ca-id", type=int, default=None,
              help="Migrate only this CA (default: every software-keyed CA).")
@click.option("--dry-run", is_flag=True,
              help="Show what would migrate without changing anything.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def migrate_to_hsm(ca_id, dry_run, yes):
    """Move software CA signing keys into the PKCS#11 token (IRREVERSIBLE)."""
    if not hsm_available():
        raise click.ClickException(
            "HSM backend not available. Set KEY_BACKEND=softhsm and the PKCS11_* "
            "settings, and initialise the token, before migrating.")

    q = CertificateAuthority.query.filter(
        CertificateAuthority.key_backend == "software",
        CertificateAuthority.private_key_enc != b"",
    )
    if ca_id is not None:
        q = q.filter(CertificateAuthority.id == ca_id)
    cas = q.all()
    if not cas:
        click.echo("No software-keyed CAs to migrate.")
        return

    click.echo("The following CA keys will be moved into the HSM token:")
    for ca in cas:
        click.echo(f"  [{ca.id}] {ca.name} ({ca.key_type} {ca.key_size})")
    click.echo("")
    click.echo("This is IRREVERSIBLE: each key becomes non-extractable and its")
    click.echo("encrypted software copy is scrubbed. Back up any key you may need")
    click.echo("to export (e.g. `flask` export or the UI Key/PKCS#12 buttons) BEFORE")
    click.echo("migrating — afterwards export is refused.")

    if dry_run:
        click.echo("\n--dry-run: no changes made.")
        return
    if not yes:
        click.confirm("\nProceed with migration?", abort=True)

    secret = current_app.config["MASTER_PASSPHRASE"]
    backend = get_backend("softhsm")
    migrated = 0
    for ca in cas:
        key = decrypt_private_key(ca.private_key_enc, secret)
        label = _key_label()
        backend.import_ca_key(key, label=label, secret=secret)
        ca.key_backend = "softhsm"
        ca.key_label = label
        # CORE-3: prove the token can actually sign for this CA BEFORE destroying
        # the only software copy — a silent/partial import must not brick it.
        backend.verify_signing_key(ca)
        ca.private_key_enc = b""
        db.session.add(ca)
        db.session.commit()
        migrated += 1
        click.echo(f"Migrated [{ca.id}] {ca.name} -> HSM ({label})")
    click.echo(f"\nDone. {migrated} CA key(s) migrated.")


certs_cli = AppGroup("certs", help="Certificate lifecycle utilities.")


@certs_cli.command("expiring")
@click.option("--days", type=int, default=None,
              help="Warning window in days (default: CERT_EXPIRY_WARNING_DAYS).")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
def certs_expiring(days, as_json):
    """List certificates and CAs expiring within N days (includes already-expired)."""
    from .models.certificate import Certificate

    warning = days if days is not None else current_app.config.get("CERT_EXPIRY_WARNING_DAYS", 30)

    items = []
    for c in Certificate.query.filter_by(is_revoked=False).all():
        d = c.days_until_expiry
        if d is not None and d <= warning:
            items.append({"type": "certificate", "id": c.id, "name": c.common_name,
                          "days_until_expiry": d, "status": c.expiry_status})
    for ca in CertificateAuthority.query.filter_by(is_revoked=False).all():
        d = ca.days_until_expiry
        if d is not None and d <= warning:
            items.append({"type": "ca", "id": ca.id, "name": ca.common_name,
                          "days_until_expiry": d, "status": ca.expiry_status})
    items.sort(key=lambda x: x["days_until_expiry"])

    if as_json:
        import json
        click.echo(json.dumps(items))
        return
    if not items:
        click.echo(f"Nothing expiring within {warning} days.")
        return
    for it in items:
        click.echo(f"[{it['type']}:{it['id']}] {it['name']} — "
                   f"{it['days_until_expiry']}d ({it['status']})")


@certs_cli.command("recompute-expiry")
@click.option("--dry-run", is_flag=True, help="Show changes without writing.")
def recompute_expiry(dry_run):
    """Recompute each certificate's stored notAfter from its PEM.

    Fixes PKI-3 on rows issued before the fix (the stored notAfter overstated
    expiry). Idempotent — safe to re-run.
    """
    from cryptography import x509
    from .models.certificate import Certificate

    changed = 0
    for c in Certificate.query.all():
        try:
            cert = x509.load_pem_x509_certificate(c.certificate_pem.encode())
        except Exception:
            click.echo(f"[{c.id}] {c.common_name}: unreadable PEM, skipped", err=True)
            continue
        real = cert.not_valid_after_utc.replace(tzinfo=None)
        if c.not_after != real:
            click.echo(f"[{c.id}] {c.common_name}: {c.not_after} -> {real}")
            if not dry_run:
                c.not_after = real
            changed += 1
    if dry_run:
        click.echo(f"--dry-run: {changed} row(s) would change.")
    else:
        db.session.commit()
        click.echo(f"Updated {changed} row(s).")


users_cli = AppGroup("users", help="User account utilities.")


@users_cli.command("unlock")
@click.argument("username")
def unlock_user(username):
    """Clear a brute-force lockout / failed-attempt counter for USERNAME (AUTH-4).

    Recovery path when an account (including the last admin) is locked out and
    no second admin is available to use the UI.
    """
    from .models.user import User
    from .services import auth_service

    user = User.query.filter_by(username=username).first()
    if user is None:
        raise click.ClickException(f"No user named {username!r}.")
    auth_service.clear_lockout(user)
    db.session.commit()
    click.echo(f"Cleared lockout for {username!r}.")


crl_cli = AppGroup("crl", help="CRL utilities.")


@crl_cli.command("refresh")
@click.option("--all", "refresh_all", is_flag=True,
              help="Regenerate every signing CA's CRL, not only expired ones.")
def crl_refresh(refresh_all):
    """Regenerate CRLs whose nextUpdate has passed (PKI-1).

    Cron this (e.g. daily) to keep published CRLs fresh without a built-in
    scheduler; --all forces regeneration regardless of expiry.
    """
    from datetime import datetime, timezone
    from cryptography import x509
    from .models.ca import CertificateAuthority
    from .services import crl_service

    secret = current_app.config["MASTER_PASSPHRASE"]
    now = datetime.now(timezone.utc)
    refreshed = 0
    for ca in CertificateAuthority.query.filter_by(is_revoked=False).all():
        if not ca.has_signing_key:
            continue
        stale = True
        if not refresh_all and ca.crl_pem:
            try:
                nu = x509.load_pem_x509_crl(ca.crl_pem.encode()).next_update_utc
                stale = nu is None or nu <= now
            except Exception:
                stale = True
        if refresh_all or stale:
            crl_service.generate_crl(ca, secret)
            refreshed += 1
            click.echo(f"Refreshed CRL for [{ca.id}] {ca.name}")
    click.echo(f"Done. {refreshed} CRL(s) refreshed.")


metrics_cli = AppGroup("metrics-token", help="Prometheus /metrics bearer-token management (2.7.0).")


@metrics_cli.command("create")
@click.option("--name", required=True, help="Unique, human-readable token name.")
@click.option("--expires-in-days", type=int, required=True,
              help="Days until the token expires (required, must be > 0).")
def create_metrics_token(name, expires_in_days):
    """Create a dedicated /metrics bearer token. The secret is printed ONCE.

    The token is valid only for GET /metrics — it is not a user account and
    grants no other access. Scrape with an `Authorization: Bearer <token>`
    header (never Basic auth / `-u`).
    """
    from datetime import datetime, timedelta, timezone
    from .services import metrics_token_service

    if expires_in_days <= 0:
        raise click.ClickException("--expires-in-days must be a positive integer.")
    expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).replace(tzinfo=None)
    try:
        plaintext, row = metrics_token_service.create(name, expires_at)
    except ValueError as exc:
        raise click.ClickException(str(exc))

    click.echo(f"Created metrics token '{row.name}' (expires {row.expires_at.date()} UTC).")
    click.echo("")
    click.echo(f"    {plaintext}")
    click.echo("")
    click.echo("This secret is shown ONCE and cannot be recovered — store it now.")


@metrics_cli.command("list")
def list_metrics_tokens():
    """List metrics tokens and their status (never shows the secret)."""
    from .services import metrics_token_service

    tokens = metrics_token_service.list_all()
    if not tokens:
        click.echo("No metrics tokens.")
        return
    click.echo(f"{'ID':>3}  {'NAME':<20} {'STATUS':<8} {'EXPIRES':<11} "
               f"{'LAST USED':<17} TOKEN-ID")
    for t in tokens:
        last = t.last_used_at.strftime("%Y-%m-%d %H:%M") if t.last_used_at else "-"
        exp = t.expires_at.strftime("%Y-%m-%d") if t.expires_at else "-"
        click.echo(f"{t.id:>3}  {t.name[:20]:<20} {t.status:<8} {exp:<11} "
                   f"{last:<17} {t.token_id}")


@metrics_cli.command("revoke")
@click.argument("name_or_id")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def revoke_metrics_token(name_or_id, yes):
    """Revoke a metrics token by NAME_OR_ID (it stops working immediately)."""
    from .services import metrics_token_service

    row = metrics_token_service.get(name_or_id)
    if row is None:
        raise click.ClickException(f"No metrics token matching {name_or_id!r}.")
    if row.revoked:
        click.echo(f"Token '{row.name}' is already revoked.")
        return
    if not yes:
        click.confirm(f"Revoke metrics token '{row.name}'?", abort=True)
    metrics_token_service.revoke(row.id)
    click.echo(f"Revoked metrics token '{row.name}'.")
