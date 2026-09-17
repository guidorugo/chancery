"""Flask CLI commands for CA key-backend management (A1).

`flask keys migrate-to-hsm` moves software CA signing keys into the PKCS#11
token. This is intentionally one-way: after migration the key is non-extractable
and the encrypted software copy is scrubbed, so the trust anchor can no longer be
read off the host. Back up any key you might need to export BEFORE migrating.
"""
import json

import click
from flask import current_app
from flask.cli import AppGroup

from .extensions import db
from .models.ca import CertificateAuthority
from .services.crypto_utils import decrypt_private_key
from .services.keybackend import get_backend, hsm_available
from .services.ca_service import _key_label

keys_cli = AppGroup("keys", help="CA key-backend management.")


def _cli_audit(action, target_type, target_id=None, details=None):
    """Audit a CLI mutation through the shared system-actor path (G10-2, G13-1):
    username 'cli', no user id, and the row also feeds the webhook stream.
    Added to the session only; the caller commits."""
    from .services import audit_service
    audit_service.log_action(action, target_type=target_type, target_id=target_id,
                             details=details, actor="cli")


@keys_cli.command("migrate-to-hsm")
@click.option("--ca-id", type=int, default=None,
              help="Migrate only this CA (default: every software-keyed CA).")
@click.option("--dry-run", is_flag=True,
              help="Show what would migrate without changing anything.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def migrate_to_hsm(ca_id, dry_run, yes):
    """Move software CA signing keys into the PKCS#11 token (IRREVERSIBLE)."""
    # G13-1: an unattended bulk migration of EVERY CA is too easy to run by
    # accident; --yes only skips the prompt for one explicitly named CA.
    if yes and ca_id is None:
        raise click.ClickException(
            "--yes requires --ca-id: migrating every CA must be confirmed interactively.")
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
        try:
            # CORE-3: prove the token can actually sign for this CA BEFORE
            # destroying the only software copy — a silent/partial import must
            # not brick it.
            backend.verify_signing_key(ca)
        except Exception as exc:
            # G13-1: leave the CA exactly as it was (software-backed, key
            # intact) and don't leave an orphaned private object in the token.
            db.session.rollback()
            try:
                destroyed = backend.destroy_key(label)
            except Exception as cleanup_exc:  # pragma: no cover - token-specific
                destroyed = f"cleanup failed: {cleanup_exc}"
            _cli_audit("migrate_to_hsm_failed", "ca", ca.id,
                       {"label": label, "objects_destroyed": destroyed,
                        "error": exc.__class__.__name__})
            db.session.commit()
            raise click.ClickException(
                f"Verification failed for [{ca.id}] {ca.name}: {exc}. The token object "
                f"was removed and the software key left untouched ({migrated} CA key(s) "
                "migrated before the failure).")
        ca.private_key_enc = b""
        db.session.add(ca)
        _cli_audit("migrate_to_hsm", "ca", ca.id, {"label": label})
        db.session.commit()
        migrated += 1
        click.echo(f"Migrated [{ca.id}] {ca.name} -> HSM ({label})")
    click.echo(f"\nDone. {migrated} CA key(s) migrated.")


@keys_cli.command("check-passphrase")
def check_passphrase():
    """Confirm the running MASTER_PASSPHRASE opens every kind of stored ciphertext."""
    from .services import passphrase_service
    report = passphrase_service.check(current_app.config["MASTER_PASSPHRASE"])
    failed = False
    for entry in report:
        if entry["ok"] is None:
            status = "no ciphertext"
        elif entry["ok"]:
            status = "ok"
        else:
            status, failed = "FAIL", True
        name = f"{entry['table']}.{entry['column']}"
        click.echo(f"{name:<44} {entry['rows']:>5} row(s)  {status:<13} ({entry['kind']})")
    if failed:
        raise click.ClickException(
            "MASTER_PASSPHRASE does not decrypt the database — the running secret is not the one the "
            "data was written with (wrong file, or a rotation without the matching secret swap).")
    click.echo("OK: the running passphrase decrypts every stored ciphertext kind.")


@keys_cli.command("rotate-passphrase")
@click.option("--new-file", required=True, type=click.Path(dir_okay=False, allow_dash=True),
              help="File holding the NEW passphrase ('-' = stdin). Never pass it on the command line.")
@click.option("--dry-run", is_flag=True, help="Verify and re-wrap in memory, then roll back.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def rotate_passphrase(new_file, dry_run, yes):
    """Re-wrap every stored private key and secret under a NEW master passphrase.

    Procedure (Docker): write the new value to a file, run this command with
    `--new-file -` fed from that file, replace secrets/master_passphrase with
    it, then `docker compose up -d --force-recreate`. Between the commit and
    the recreate the app cannot decrypt anything (issuance/OCSP fail), so do
    the three steps back to back. `flask keys check-passphrase` afterwards
    confirms the swap.
    """
    from .services import passphrase_service
    current = current_app.config["MASTER_PASSPHRASE"]
    if new_file == "-":
        raw = click.get_text_stream("stdin").read()
    else:
        with open(new_file, "r", encoding="utf-8") as fh:
            raw = fh.read()
    try:
        new = passphrase_service.validate_new_passphrase(raw, current)
    except passphrase_service.PassphraseError as exc:
        raise click.ClickException(str(exc))

    report = passphrase_service.check(current)
    total = sum(e["rows"] for e in report)
    for entry in report:
        click.echo(f"  {entry['table']}.{entry['column']}: {entry['rows']} row(s) ({entry['kind']})")
    if any(e["ok"] is False for e in report):
        raise click.ClickException("The current MASTER_PASSPHRASE does not decrypt the database; "
                                   "fix that first (`flask keys check-passphrase`).")
    click.echo(f"{total} ciphertext(s) will be re-wrapped under the new passphrase "
               f"({'DRY RUN' if dry_run else 'one transaction'}).")
    if not dry_run and not yes:
        click.confirm("Proceed?", abort=True)

    try:
        stats = passphrase_service.rotate(current, new)
    except passphrase_service.PassphraseError as exc:
        raise click.ClickException(str(exc))

    if dry_run:
        db.session.rollback()
        click.echo("--dry-run: every blob re-wrapped and verified in memory; nothing written.")
        return
    _cli_audit("rotate_passphrase", "config", details={"rewrapped": stats})
    db.session.commit()
    click.echo("Rotated: " + ", ".join(f"{k}={v}" for k, v in stats.items()))
    click.echo("")
    click.echo("NEXT, without delay — the running app still holds the OLD passphrase:")
    click.echo("  1. replace the secret file with the new value, e.g.")
    click.echo("       cp secrets/master_passphrase.new secrets/master_passphrase && chmod 600 secrets/master_passphrase")
    click.echo("  2. docker compose up -d --force-recreate   (a bind-mounted secret needs the recreate)")
    click.echo("  3. docker compose exec -u app app flask keys check-passphrase")


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
        _cli_audit("recompute_expiry", "certificate", None, {"changed": changed})
        db.session.commit()
        click.echo(f"Updated {changed} row(s).")


@certs_cli.command("backfill-issuers")
@click.option("--dry-run", is_flag=True, help="Show changes without writing.")
def backfill_issuers(dry_run):
    """Backfill CSR signed_by / certificate issued_by from the audit log.

    Rows issued before 2.10.0/2.11.0 predate the columns, but every signing
    was audit-logged (sign_csr / create_certificate) with the acting user —
    recover the identity from there. Idempotent: only NULL fields are filled,
    existing values are never overwritten.
    """
    import json
    from .models.audit_log import AuditLog
    from .models.certificate import Certificate
    from .models.csr import CertificateSigningRequest

    csrs_filled = certs_filled = 0

    for entry in AuditLog.query.filter_by(action="sign_csr").all():
        if not entry.user_id:
            continue
        csr = (db.session.get(CertificateSigningRequest, entry.target_id)
               if entry.target_id else None)
        if csr is not None and csr.signed_by is None and csr.status == "approved":
            click.echo(f"csr [{csr.id}] {csr.common_name}: signed_by <- "
                       f"{entry.username} ({entry.user_id})")
            if not dry_run:
                csr.signed_by = entry.user_id
            csrs_filled += 1
        cert_id = None
        if entry.details:
            try:
                cert_id = json.loads(entry.details).get("certificate_id")
            except (ValueError, TypeError):
                pass
        if cert_id is None and csr is not None:
            cert_id = csr.certificate_id
        cert = db.session.get(Certificate, cert_id) if cert_id else None
        if cert is not None and cert.issued_by is None:
            click.echo(f"certificate [{cert.id}] {cert.common_name}: issued_by <- "
                       f"{entry.username} ({entry.user_id})")
            if not dry_run:
                cert.issued_by = entry.user_id
            certs_filled += 1

    for entry in AuditLog.query.filter_by(action="create_certificate").all():
        if not entry.user_id or not entry.target_id:
            continue
        cert = db.session.get(Certificate, entry.target_id)
        if cert is not None and cert.issued_by is None:
            click.echo(f"certificate [{cert.id}] {cert.common_name}: issued_by <- "
                       f"{entry.username} ({entry.user_id})")
            if not dry_run:
                cert.issued_by = entry.user_id
            certs_filled += 1

    if dry_run:
        click.echo(f"--dry-run: {csrs_filled} CSR(s), {certs_filled} "
                   "certificate(s) would be filled.")
    else:
        _cli_audit("backfill_issuers", "certificate", None,
                   {"csrs": csrs_filled, "certificates": certs_filled})
        db.session.commit()
        click.echo(f"Filled {csrs_filled} CSR(s), {certs_filled} certificate(s).")


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
    _cli_audit("unlock_user", "user", user.id, {"username": username})
    db.session.commit()
    click.echo(f"Cleared lockout for {username!r}.")


@users_cli.command("reset-2fa")
@click.argument("username")
def reset_2fa_user(username):
    """Clear USERNAME's TOTP second factor (lost authenticator); they can enrol again (F13)."""
    from .models.user import User
    from .routes.auth import _clear_totp
    from .services import auth_service

    user = User.query.filter_by(username=username).first()
    if user is None:
        raise click.ClickException(f"No user named {username!r}.")
    if not user.totp_enabled:
        click.echo(f"Two-factor authentication is not enabled for {username!r}.")
        return
    _clear_totp(user)
    auth_service.bump_session_version(user)
    _cli_audit("totp_reset", "user", user.id, {"username": username})
    db.session.commit()
    from .services import totp_service
    click.echo(f"Cleared the second factor for {username!r}; their sessions were logged out.")
    if totp_service.enforced_for(user, current_app.config):
        click.echo("REQUIRE_2FA applies to this account: they must enrol an authenticator again at their next login.")


@users_cli.command("reset-password")
@click.argument("username")
@click.option("--new-file", required=True, type=click.Path(dir_okay=False, allow_dash=True),
              help="File holding the new password (`-` = stdin); never pass it on the command line.")
def reset_password_user(username, new_file):
    """Break-glass: set USERNAME's password from a file or stdin (2.28.0).

    For the case no other administrator can do it from the Users page. The
    account must change the password again at its next login, any lockout is
    cleared and every session / cached Basic-Auth credential is dropped.
    """
    from .models.user import User
    from .services import auth_service

    user = User.query.filter_by(username=username).first()
    if user is None:
        raise click.ClickException(f"No user named {username!r}.")
    if not user.has_usable_password():
        raise click.ClickException(f"{username!r} is a directory (LDAP) account; its password is not managed here.")
    if new_file == "-":
        raw = click.get_text_stream("stdin").read()
    else:
        with open(new_file, "r", encoding="utf-8") as fh:
            raw = fh.read()
    new_password = raw.rstrip("\r\n")
    min_len = current_app.config.get("MIN_PASSWORD_LENGTH", 12)
    if len(new_password) < min_len:
        raise click.ClickException(f"The new password must be at least {min_len} characters.")
    user.set_password(new_password)
    user.must_change_password = True
    auth_service.clear_lockout(user)
    auth_service.bump_session_version(user)
    _cli_audit("reset_user_password", "user", user.id, {"username": username, "break_glass": True})
    db.session.commit()
    click.echo(f"Password set for {username!r}; they must choose a new one at their next login. "
               "Sessions and any lockout were cleared.")


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
        if not ca.has_signing_key or ca.approval_status == "pending":
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
            _cli_audit("crl_refreshed", "ca", ca.id,
                       {"trigger": "cli", "all": refresh_all, "crl_number": ca.crl_number})
            db.session.commit()
            refreshed += 1
            click.echo(f"Refreshed CRL for [{ca.id}] {ca.name}")
    click.echo(f"Done. {refreshed} CRL(s) refreshed.")


scheduler_cli = AppGroup("scheduler", help="Background scheduler (2.17.0, F8).")


@scheduler_cli.command("status")
def scheduler_status():
    """Show the scheduler lease, each job's last run, this process's view, and the effective config."""
    from .services import scheduler_service
    click.echo(json.dumps(scheduler_service.status(), indent=2, default=str))


@scheduler_cli.command("tick")
@click.option("--force", is_flag=True,
              help="Run every job now, even if another worker holds the lease or a job's interval "
                   "(the daily expiry-events pass) has not elapsed.")
def scheduler_tick(force):
    """Run one scheduler pass now: CRL refresh for CAs whose CRL is due, and the
    daily expiry-events pass when it is due (or always, with --force)."""
    from .services import scheduler_service
    summary = scheduler_service.tick(force=force)
    click.echo(json.dumps(summary, indent=2, default=str))
    if not summary["lease"]:
        raise click.ClickException("Another worker holds the scheduler lease; use --force to run anyway.")


ocsp_cli = AppGroup("ocsp", help="OCSP responder utilities (2.24.0, F7).")


@ocsp_cli.command("rotate-responders")
@click.option("--ca-id", type=int, default=None, help="Only this CA (default: every signing-capable CA).")
@click.option("--force", is_flag=True, help="Issue a new responder certificate even if the current one is fresh.")
def ocsp_rotate_responders(ca_id, force):
    """Issue/renew delegated OCSP responder certificates (OCSP_DELEGATED_RESPONDER).

    Without --force only CAs whose responder is missing, expired or within
    OCSP_RESPONDER_RENEW_BEFORE_DAYS of expiry get a new one.
    """
    from .models.ca import CertificateAuthority
    from .services import ocsp_service

    secret = current_app.config["MASTER_PASSPHRASE"]
    query = CertificateAuthority.signing_capable()
    if ca_id is not None:
        query = query.filter_by(id=ca_id)
    cas = query.all()
    if ca_id is not None and not cas:
        raise click.ClickException(f"CA {ca_id} not found or not signing-capable.")
    if not ocsp_service.delegated_enabled():
        click.echo("Note: OCSP_DELEGATED_RESPONDER is off — responses still use the CA key until it is enabled.")
    rotated = 0
    for ca in cas:
        if ocsp_service.ca_expired(ca):
            click.echo(f"CA {ca.id} ({ca.name}): expired — skipped")
            continue
        try:
            if ocsp_service.ensure_responder(ca, secret, force=force):
                _cli_audit("ocsp_responder_rotated", target_type="ca", target_id=ca.id,
                           details={"trigger": "cli", "force": force, **ocsp_service.responder_status(ca)})
                db.session.commit()
                rotated += 1
                click.echo(f"CA {ca.id} ({ca.name}): new responder, valid until {ocsp_service.responder_status(ca)['not_after']}")
            else:
                click.echo(f"CA {ca.id} ({ca.name}): responder still fresh")
        except Exception as exc:
            db.session.rollback()
            click.echo(f"CA {ca.id} ({ca.name}): FAILED — {exc}", err=True)
    click.echo(f"Rotated {rotated} responder(s).")


api_token_cli = AppGroup("api-token", help="Scoped API tokens (2.26.0, F12).")


@api_token_cli.command("create")
@click.option("--user", "username", required=True, help="Owner account (the token never exceeds its role).")
@click.option("--name", required=True, help="Token name (unique per user).")
@click.option("--scopes", default="read", show_default=True, help="Comma-separated: read,issue,revoke,admin.")
@click.option("--expires-in-days", type=int, required=True, help="Lifetime in days (≤ API_TOKEN_MAX_DAYS).")
def api_token_create(username, name, scopes, expires_in_days):
    """Create a scoped API token; the secret is printed once."""
    from .models.user import User
    from .services import api_token_service
    user = User.query.filter_by(username=username).first()
    if user is None:
        raise click.ClickException(f"User '{username}' not found.")
    try:
        plaintext, row = api_token_service.create(user, name, scopes.split(","), expires_in_days, actor="cli")
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        raise click.ClickException(str(exc))
    click.echo(f"Created token '{row.name}' for {user.username} (id {row.id}, scopes {','.join(row.scopes)}, "
               f"expires {row.expires_at:%Y-%m-%d}).")
    click.echo("Secret (shown once):")
    click.echo(plaintext)


@api_token_cli.command("list")
@click.option("--user", "username", default=None, help="Only this account's tokens.")
def api_token_list(username):
    """List API tokens."""
    from .models.user import User
    from .services import api_token_service
    if username:
        user = User.query.filter_by(username=username).first()
        if user is None:
            raise click.ClickException(f"User '{username}' not found.")
        rows = api_token_service.list_for_user(user)
    else:
        rows = api_token_service.list_all()
    if not rows:
        click.echo("No API tokens.")
        return
    for r in rows:
        used = r.last_used_at.strftime("%Y-%m-%d %H:%M") if r.last_used_at else "never"
        click.echo(f"{r.id:>3}  {r.user.username:<16} {r.name:<24} {r.status:<8} scopes={','.join(r.scopes):<22} "
                   f"expires={r.expires_at:%Y-%m-%d} last_used={used} token_id={r.token_id}")


@api_token_cli.command("revoke")
@click.argument("token")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def api_token_revoke(token, yes):
    """Revoke an API token by id or token_id."""
    from .services import api_token_service
    row = api_token_service.get(token)
    if row is None:
        raise click.ClickException(f"API token '{token}' not found.")
    if not yes:
        click.confirm(f"Revoke API token '{row.name}' of {row.user.username}?", abort=True)
    api_token_service.revoke(row, actor="cli")
    db.session.commit()
    click.echo(f"Revoked API token '{row.name}' ({row.user.username}).")


profiles_cli = AppGroup("profiles", help="Certificate profile utilities (2.13.0, F1).")


@profiles_cli.command("list")
def list_profiles():
    """List certificate profiles."""
    from .services import profile_service
    rows = profile_service.list_profiles()
    if not rows:
        click.echo("No profiles.")
        return
    for p in rows:
        certs, csrs = profile_service.usage_counts(p)
        flags = ("builtin " if p.is_builtin else "") + ("" if p.enabled else "DISABLED ")
        click.echo(f"[{p.id}] {p.key:<16} {p.name:<24} {flags}certs={certs} csrs={csrs}")


@profiles_cli.command("export")
def export_profiles():
    """Print every profile as JSON (importable with `profiles import`)."""
    from .services import profile_service
    click.echo(json.dumps(profile_service.export_all(), indent=2))


@profiles_cli.command("import")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--replace", is_flag=True, help="Overwrite profiles whose key already exists.")
def import_profiles(path, replace):
    """Import profiles from a JSON file produced by `profiles export`."""
    from .services import profile_service
    with open(path, encoding="utf-8") as fh:
        items = json.load(fh)
    if not isinstance(items, list):
        raise click.ClickException("Expected a JSON list of profiles.")
    try:
        created, updated = profile_service.import_profiles(items, replace=replace)
    except ValueError as exc:
        db.session.rollback()
        raise click.ClickException(str(exc))
    _cli_audit("import_profiles", "config", details={"created": created, "updated": updated,
                                                     "replace": replace, "file": path})
    db.session.commit()
    click.echo(f"Imported: {created} created, {updated} updated.")


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
