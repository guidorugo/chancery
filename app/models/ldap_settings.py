from datetime import datetime, timezone

from ..extensions import db


class LdapSettings(db.Model):
    """Directory-authentication settings managed from the admin UI.

    A single row (id=1). When present it takes precedence over the LDAP_*
    environment variables; deleting it reverts the app to the env config.
    The bind password is stored Fernet-encrypted under MASTER_PASSPHRASE
    (bind_password_enc), never in cleartext.
    """

    __tablename__ = "ldap_settings"

    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, nullable=False, default=False)
    server_uri = db.Column(db.String(500), nullable=False, default="")
    use_starttls = db.Column(db.Boolean, nullable=False, default=False)
    tls_verify = db.Column(db.Boolean, nullable=False, default=True)
    allow_plaintext = db.Column(db.Boolean, nullable=False, default=False)
    # CA cert is stored as PEM text (pasted in the UI) rather than a file path,
    # so no file has to be mounted into the container.
    ca_cert_pem = db.Column(db.Text, nullable=False, default="")
    user_dn_template = db.Column(db.String(500), nullable=False, default="")
    bind_dn = db.Column(db.String(500), nullable=False, default="")
    bind_password_enc = db.Column(db.LargeBinary, nullable=True)
    user_search_base = db.Column(db.String(500), nullable=False, default="")
    user_filter = db.Column(db.String(500), nullable=False, default="(uid={username})")
    admin_group_dn = db.Column(db.String(500), nullable=False, default="")
    requester_group_dn = db.Column(db.String(500), nullable=False, default="")
    group_member_attr = db.Column(db.String(100), nullable=False, default="memberOf")
    timeout_seconds = db.Column(db.Integer, nullable=False, default=5)
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
