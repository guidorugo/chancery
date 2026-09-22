"""F20 (3.7.0): three validity tiers — leaf 1825 (5y), intermediate 3650 (10y),
root 7300 (20y). The leaf clamp to the issuing CA's expiry and the per-profile
`max_validity_days` still win when tighter. Existing objects are untouched;
caps apply only at issuance."""
from datetime import datetime, timedelta, timezone

import pytest

from app.services import ca_service, cert_service
from app.services.policy import bounded_not_after

PASS = "test-passphrase"
NOW = datetime.now(timezone.utc)


class TestBoundedNotAfter:
    def test_leaf_cap_is_1825(self):
        assert bounded_not_after(NOW, 1825, is_ca=False)          # ok at the ceiling
        with pytest.raises(ValueError, match="certificate validity 1826 days exceeds the maximum of 1825"):
            bounded_not_after(NOW, 1826, is_ca=False)

    def test_intermediate_cap_is_3650(self):
        assert bounded_not_after(NOW, 3650, is_ca=True, is_intermediate=True)
        with pytest.raises(ValueError, match="intermediate CA validity 3651 days exceeds the maximum of 3650"):
            bounded_not_after(NOW, 3651, is_ca=True, is_intermediate=True)

    def test_root_cap_is_7300(self):
        assert bounded_not_after(NOW, 7300, is_ca=True)
        with pytest.raises(ValueError, match="root CA validity 7301 days exceeds the maximum of 7300"):
            bounded_not_after(NOW, 7301, is_ca=True)

    def test_root_cap_higher_than_intermediate(self):
        # 5000 days is fine for a root but not for an intermediate.
        assert bounded_not_after(NOW, 5000, is_ca=True)
        with pytest.raises(ValueError, match="exceeds the maximum of 3650"):
            bounded_not_after(NOW, 5000, is_ca=True, is_intermediate=True)

    def test_config_override(self, app, monkeypatch):
        # monkeypatch.setitem auto-reverts, so this never leaks into other tests.
        with app.app_context():
            monkeypatch.setitem(app.config, "MAX_CERT_VALIDITY_DAYS", 825)
            with pytest.raises(ValueError, match="exceeds the maximum of 825"):
                bounded_not_after(NOW, 900, is_ca=False)

    def test_leaf_still_clamped_to_ca_expiry(self):
        ca_na = NOW.replace(tzinfo=None) + timedelta(days=100)
        out = bounded_not_after(NOW, 1825, ca_not_after=ca_na, is_ca=False)
        assert out <= ca_na.replace(tzinfo=timezone.utc)


class TestIssuance:
    def test_five_year_leaf_issues(self, db):
        ca = ca_service.create_root_ca("Tier Root", {"CN": "Tier Root"}, "EC", 256, 7300, PASS)
        db.session.commit()
        cert = cert_service.create_certificate(ca, {"CN": "long.example.com"}, ["DNS:long.example.com"],
                                               1825, PASS, key_type="EC", key_size=256)
        db.session.commit()
        assert (cert.not_after - cert.not_before).days in (1824, 1825)

    def test_leaf_over_1825_refused(self, db):
        ca = ca_service.create_root_ca("Tier Root 2", {"CN": "Tier Root 2"}, "EC", 256, 7300, PASS)
        db.session.commit()
        with pytest.raises(ValueError, match="exceeds the maximum of 1825"):
            cert_service.create_certificate(ca, {"CN": "toolong.example.com"}, ["DNS:toolong.example.com"],
                                            2000, PASS, key_type="EC", key_size=256)

    def test_root_up_to_7300_and_over_refused(self, db):
        ca = ca_service.create_root_ca("Twenty Year Root", {"CN": "Twenty Year Root"}, "EC", 256, 7300, PASS)
        db.session.commit()
        assert (ca.not_after - ca.not_before).days in (7299, 7300)
        with pytest.raises(ValueError, match="root CA validity .* exceeds the maximum of 7300"):
            ca_service.create_root_ca("Too Long Root", {"CN": "Too Long Root"}, "EC", 256, 7301, PASS)

    def test_intermediate_capped_at_3650_even_under_a_long_root(self, db):
        root = ca_service.create_root_ca("Long Root", {"CN": "Long Root"}, "EC", 256, 7300, PASS)
        db.session.commit()
        inter = ca_service.create_intermediate_ca("Ten Year Inter", root, {"CN": "Ten Year Inter"},
                                                  "EC", 256, 3650, PASS)
        db.session.commit()
        assert (inter.not_after - inter.not_before).days in (3649, 3650)
        with pytest.raises(ValueError, match="intermediate CA validity .* exceeds the maximum of 3650"):
            ca_service.create_intermediate_ca("Too Long Inter", root, {"CN": "Too Long Inter"},
                                              "EC", 256, 5000, PASS)
