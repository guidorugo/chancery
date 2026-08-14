from datetime import datetime, timezone

from ..extensions import db


class WebhookSettings(db.Model):
    """Admin-saved webhook notification settings (2.10.0).

    A single row (id=1). When present it takes precedence over the WEBHOOK_*
    environment variables; deleting it reverts the app to the env config.
    The signing secret is stored Fernet-encrypted under MASTER_PASSPHRASE
    (secret_enc), never in cleartext. `events` is a CSV of audit action names
    ("all" = every action).
    """

    __tablename__ = "webhook_settings"

    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, nullable=False, default=False)
    url = db.Column(db.String(500), nullable=False, default="")
    secret_enc = db.Column(db.LargeBinary, nullable=True)
    events = db.Column(db.Text, nullable=False, default="")
    timeout_seconds = db.Column(db.Integer, nullable=False, default=5)

    updated_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
