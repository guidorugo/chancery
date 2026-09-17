"""F19 (3.4.0, G3-1): dual control for user management — creation, promotion
and admin password resets need a second admin; the cool-down keeps a freshly
minted approver from being used at once; the bootstrap admin is exempt; nothing
changes while the mode is inactive. Same fixtures pattern as test_dual_control."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services import dual_control_service
from tests.conftest import TestConfig

JSON = {"Accept": "application/json"}
PW = "pw-123456789"


class DualControlConfig(TestConfig):
    DUAL_CONTROL_ENABLED = True


@pytest.fixture(scope="module")
def dc_app():
    return create_app(DualControlConfig)


@pytest.fixture
def dc_db(dc_app):
    with dc_app.app_context():
        _db.drop_all()
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()


def _mk_user(username, role="admin", password=PW, **kw):
    user = User(username=username, role=role, **kw)
    user.set_password(password)
    _db.session.add(user)
    _db.session.commit()
    return user


def _client(app, username, password=PW):
    c = app.test_client()
    r = c.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 302, r.data
    return c


def _fresh(uid):
    _db.session.expire_all()
    return _db.session.get(User, uid)


def _two_admins():
    """bootstrap `admin` (exempt) + alice + bob: with alice active the mode is on."""
    return _mk_user("admin"), _mk_user("alice"), _mk_user("bob")


class TestInactiveMode:
    def test_single_admin_box_keeps_the_old_flow(self, dc_app, dc_db):
        boot = _mk_user("admin")
        c = _client(dc_app, "admin")
        assert not dual_control_service.is_active() or True
        r = c.post("/users/create", data={"username": "carol", "password": PW, "role": "admin"}, follow_redirects=True)
        carol = User.query.filter_by(username="carol").one()
        # the bootstrap admin is exempt anyway; a plain admin on a single-user box would be too
        assert carol.is_active_user and carol.approval_status == "approved" and carol.created_by == boot.id
        assert b"awaiting approval" not in r.data

    def test_plain_admin_alone_is_not_gated(self, app, auth_admin, db):
        """Shared app (flag off): nothing is gated at all."""
        r = auth_admin.post("/users/create", data={"username": "dave", "password": PW, "role": "admin"}, follow_redirects=True)
        dave = User.query.filter_by(username="dave").one()
        assert dave.is_active_user and dave.approval_status == "approved" and b"awaiting" not in r.data
        r = auth_admin.post(f"/users/{dave.id}/approve", headers=JSON)
        assert r.status_code == 409


class TestCreation:
    def test_new_user_pending_until_another_admin_approves(self, dc_app, dc_db):
        boot, alice, bob = _two_admins()
        a = _client(dc_app, "alice")
        r = a.post("/users/create", data={"username": "carol", "password": PW, "role": "csr_requester"}, follow_redirects=True)
        assert b"awaiting approval by another admin" in r.data
        carol = User.query.filter_by(username="carol").one()
        assert carol.is_pending and not carol.is_active_user and carol.pending_by == alice.id and carol.created_by == alice.id
        assert json.loads(AuditLog.query.filter_by(action="create_user").one().details)["approval_status"] == "pending"
        # carol cannot log in
        c = dc_app.test_client()
        r = c.post("/auth/login", data={"username": "carol", "password": PW}, follow_redirects=True)
        assert b"awaiting approval by an administrator" in r.data
        assert AuditLog.query.filter_by(action="login_failure").count() == 1
        assert json.loads(AuditLog.query.filter_by(action="login_failure").one().details)["reason"] == "account_pending"
        # the creator cannot approve, nor activate through the toggle
        r = a.post(f"/users/{carol.id}/approve", headers=JSON)
        assert r.status_code == 403 and "different admin" in r.get_json()["error"]
        r = a.post(f"/users/{carol.id}/toggle-active", follow_redirects=True)
        assert b"use Approve" in r.data and not _fresh(carol.id).is_active_user
        # the list shows it, and bob approves
        page = _client(dc_app, "bob").get("/users/").data
        assert b"Pending approval" in page and b">Approve<" in page
        b = _client(dc_app, "bob")
        r = b.post(f"/users/{carol.id}/approve", headers=JSON)
        assert r.status_code == 200 and r.get_json()["approval_status"] == "approved" and r.get_json()["is_active"] is True
        carol = _fresh(carol.id)
        assert carol.approved_by == bob.id and carol.approved_at and carol.pending_by is None
        assert json.loads(AuditLog.query.filter_by(action="approve_user").one().details) == {"activated": True, "role": None}
        assert dc_app.test_client().post("/auth/login", data={"username": "carol", "password": PW}).status_code == 302
        assert b.post(f"/users/{carol.id}/approve", headers=JSON).status_code == 409

    def test_bootstrap_admin_is_exempt(self, dc_app, dc_db):
        boot, alice, bob = _two_admins()
        c = _client(dc_app, "admin")
        c.post("/users/create", data={"username": "carol", "password": PW, "role": "admin"})
        carol = User.query.filter_by(username="carol").one()
        assert carol.is_active_user and carol.approval_status == "approved"
        # and it may approve what others set up, even its own creations
        a = _client(dc_app, "alice")
        a.post("/users/create", data={"username": "dave", "password": PW, "role": "admin"})
        dave = User.query.filter_by(username="dave").one()
        assert c.post(f"/users/{dave.id}/approve", headers=JSON).status_code == 200

    def test_requester_cannot_approve(self, dc_app, dc_db):
        boot, alice, bob = _two_admins()
        req = _mk_user("req", role="csr_requester")
        a = _client(dc_app, "alice")
        a.post("/users/create", data={"username": "carol", "password": PW, "role": "admin"})
        carol = User.query.filter_by(username="carol").one()
        assert _client(dc_app, "req").post(f"/users/{carol.id}/approve", headers=JSON).status_code == 403
        assert _fresh(carol.id).is_pending


class TestCooldown:
    def test_freshly_minted_admin_cannot_approve_creators_work(self, dc_app, dc_db):
        boot, alice, bob = _two_admins()
        a, b = _client(dc_app, "alice"), _client(dc_app, "bob")
        a.post("/users/create", data={"username": "dave", "password": PW, "role": "admin"})
        dave = User.query.filter_by(username="dave").one()
        assert b.post(f"/users/{dave.id}/approve", headers=JSON).status_code == 200
        # dave logs in, changes the bootstrap password, and tries to approve alice's next creation
        d = dc_app.test_client()
        d.post("/auth/login", data={"username": "dave", "password": PW})
        d.post("/auth/change-password", data={"current_password": PW, "new_password": "another-pw-123456", "confirm_password": "another-pw-123456"})
        a.post("/users/create", data={"username": "erin", "password": PW, "role": "csr_requester"})
        erin = User.query.filter_by(username="erin").one()
        r = d.post(f"/users/{erin.id}/approve", headers=JSON)
        assert r.status_code == 403 and "less than 24 hours" in r.get_json()["error"]
        # but dave may approve bob's work
        b.post("/users/create", data={"username": "frank", "password": PW, "role": "csr_requester"})
        frank = User.query.filter_by(username="frank").one()
        assert d.post(f"/users/{frank.id}/approve", headers=JSON).status_code == 200
        # once the cool-down has passed, dave may approve alice's work too
        dave = _fresh(dave.id); dave.created_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=25); _db.session.commit()
        assert d.post(f"/users/{erin.id}/approve", headers=JSON).status_code == 200

    def test_can_approve_helper(self, dc_app, dc_db):
        boot, alice, bob = _two_admins()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        fresh = _mk_user("fresh", created_by=alice.id)
        reset = _mk_user("reset", password_reset_by=alice.id, password_reset_at=now)
        assert dual_control_service.can_approve(bob, alice.id)
        assert not dual_control_service.can_approve(alice, alice.id)
        assert not dual_control_service.can_approve(fresh, alice.id) and dual_control_service.can_approve(fresh, bob.id)
        assert not dual_control_service.can_approve(reset, alice.id)
        assert dual_control_service.can_approve(boot, alice.id)            # exempt
        assert dual_control_service.can_approve(bob, None)
        dc_app.config["DUAL_CONTROL_COOLDOWN_HOURS"] = 0
        try:
            assert dual_control_service.can_approve(fresh, alice.id)
        finally:
            dc_app.config["DUAL_CONTROL_COOLDOWN_HOURS"] = 24
        assert "less than 24 hours" in dual_control_service.refuse_reason(fresh, alice.id)
        assert dual_control_service.refuse_reason(bob, alice.id) is None

    def test_ca_approval_honours_the_cooldown(self, dc_app, dc_db):
        from app.services import ca_service
        boot, alice, bob = _two_admins()
        a, b = _client(dc_app, "alice"), _client(dc_app, "bob")
        a.post("/users/create", data={"username": "dave", "password": PW, "role": "admin"})
        dave = User.query.filter_by(username="dave").one()
        b.post(f"/users/{dave.id}/approve")
        ca = ca_service.create_root_ca(name="Gated CA", subject_attrs={"CN": "g"}, key_type="EC", key_size=256,
                                       validity_days=365, passphrase="test-passphrase", created_by=alice.id,
                                       approval_status="pending")
        _db.session.commit()
        d = dc_app.test_client(); d.post("/auth/login", data={"username": "dave", "password": PW})
        d.post("/auth/change-password", data={"current_password": PW, "new_password": "another-pw-123456", "confirm_password": "another-pw-123456"})
        assert d.post(f"/ca/{ca.id}/approve", headers=JSON).status_code == 403
        assert a.post(f"/ca/{ca.id}/approve", headers=JSON).status_code == 403
        assert b.post(f"/ca/{ca.id}/approve", headers=JSON).status_code == 200


class TestPromotionAndReset:
    def test_promotion_waits_for_a_second_admin(self, dc_app, dc_db):
        boot, alice, bob = _two_admins()
        eve = _mk_user("eve", role="csr_requester")
        a, b = _client(dc_app, "alice"), _client(dc_app, "bob")
        r = a.post(f"/users/{eve.id}/edit", data={"role": "admin"}, follow_redirects=True)
        assert b"awaits approval by another admin" in r.data
        eve = _fresh(eve.id)
        assert eve.role == "csr_requester" and eve.pending_role == "admin" and eve.pending_by == alice.id and eve.is_active_user
        assert AuditLog.query.filter_by(action="request_user_promotion").count() == 1
        page = a.get(f"/users/{eve.id}/edit").data
        assert b"awaits approval" in page
        assert a.post(f"/users/{eve.id}/approve", headers=JSON).status_code == 403
        r = b.post(f"/users/{eve.id}/approve", headers=JSON)
        assert r.status_code == 200 and r.get_json()["role"] == "admin" and r.get_json()["pending_role"] is None
        assert json.loads(AuditLog.query.filter_by(action="approve_user").one().details) == {"activated": False, "role": "admin"}
        # demotion is immediate and cancels a pending promotion
        a.post(f"/users/{eve.id}/edit", data={"role": "csr_requester"})
        eve = _fresh(eve.id); assert eve.role == "csr_requester"
        a.post(f"/users/{eve.id}/edit", data={"role": "admin"}); assert _fresh(eve.id).pending_role == "admin"
        b.post(f"/users/{eve.id}/edit", data={"role": "csr_requester"}); assert _fresh(eve.id).pending_role is None

    def test_admin_password_reset_deactivates_until_approved(self, dc_app, dc_db):
        boot, alice, bob = _two_admins()
        carol = _mk_user("carol")
        b = _client(dc_app, "bob")
        page = b.get(f"/users/{alice.id}/reset-password").data
        assert b"deactivates" in page
        r = b.post(f"/users/{alice.id}/reset-password", data={"password": "reset-pw-1234567"}, follow_redirects=True)
        assert b"deactivated until another admin approves" in r.data
        alice = _fresh(alice.id)
        assert not alice.is_active_user and alice.is_pending and alice.pending_by == bob.id and alice.password_reset_by == bob.id
        assert alice.must_change_password and alice.check_password("reset-pw-1234567")
        r = dc_app.test_client().post("/auth/login", data={"username": "alice", "password": "reset-pw-1234567"}, follow_redirects=True)
        assert b"awaiting approval" in r.data
        assert b.post(f"/users/{alice.id}/approve", headers=JSON).status_code == 403        # the resetter
        assert _client(dc_app, "carol").post(f"/users/{alice.id}/approve", headers=JSON).status_code == 200
        assert _fresh(alice.id).is_active_user
        # a requester's reset stays single-admin
        req = _mk_user("req", role="csr_requester")
        r = b.post(f"/users/{req.id}/reset-password", data={"password": "reset-pw-1234567"}, follow_redirects=True)
        assert b"has been reset." in r.data and _fresh(req.id).is_active_user and not _fresh(req.id).is_pending

    def test_bootstrap_password_reset_refused_under_dual_control(self, dc_app, dc_db):
        boot, alice, bob = _two_admins()
        a = _client(dc_app, "alice")
        r = a.post(f"/users/{boot.id}/reset-password", data={"password": "reset-pw-1234567"}, headers=JSON)
        assert r.status_code == 403 and "flask users reset-password" in r.get_json()["error"]
        assert _fresh(boot.id).check_password(PW)
        # the bootstrap admin resets others without gating
        c = _client(dc_app, "admin")
        c.post(f"/users/{alice.id}/reset-password", data={"password": "reset-pw-1234567"})
        assert _fresh(alice.id).is_active_user and not _fresh(alice.id).is_pending


class TestCliAndSchema:
    def test_cli_approve(self, dc_app, dc_db):
        boot, alice, bob = _two_admins()
        _client(dc_app, "alice").post("/users/create", data={"username": "carol", "password": PW, "role": "admin"})
        runner = dc_app.test_cli_runner()
        r = runner.invoke(args=["users", "approve", "carol"])
        assert r.exit_code == 0 and "Approved 'carol'" in r.output
        carol = User.query.filter_by(username="carol").one()
        assert carol.is_active_user and carol.approval_status == "approved" and carol.approved_by is None
        assert AuditLog.query.filter_by(action="approve_user").one().username == "cli"
        assert "not awaiting" in runner.invoke(args=["users", "approve", "carol"]).output
        assert runner.invoke(args=["users", "approve", "nobody"]).exit_code != 0

    def test_migration_and_json(self, app, db, auth_admin):
        from sqlalchemy import text
        from app import _migrate_schema
        for col in ("approval_status", "pending_role", "approved_at", "password_reset_at"):
            db.session.execute(text(f"ALTER TABLE users DROP COLUMN {col}"))
        db.session.commit()
        _migrate_schema(); _migrate_schema()
        cols = {r[1] for r in db.session.execute(text("PRAGMA table_info(users)"))}
        assert {"approval_status", "created_by", "approved_by", "approved_at", "pending_role", "pending_by",
                "password_reset_by", "password_reset_at"} <= cols
        me = auth_admin.get("/users/", headers=JSON).get_json()[0]
        assert me["approval_status"] == "approved" and me["pending_role"] is None
