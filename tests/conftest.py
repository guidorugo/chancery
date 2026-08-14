import os
import shutil
import subprocess

import pytest

from app import create_app
from app.config import Config
from app.extensions import db as _db
from app.models.user import User


def _find_softhsm_module():
    env = os.environ.get("SOFTHSM2_MODULE")
    if env and os.path.exists(env):
        return env
    for p in (
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
    ):
        if os.path.exists(p):
            return p
    return None


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = "test-secret"
    MASTER_PASSPHRASE = "test-passphrase"
    WTF_CSRF_ENABLED = False
    # The test client runs over HTTP; secure cookies would not persist, so
    # opt out (mirrors the plain-HTTP reference deployment).
    SESSION_COOKIE_SECURE = False
    # UPDATE_CHECK_ENABLED ships on by default, but the suite must stay offline
    # and deterministic — the footer context processor calls check() on every
    # render. Tests that want it on use an explicit config (see test_update_check).
    UPDATE_CHECK_ENABLED = False
    # RATE_LIMIT_ENABLED ships on by default too, but shared per-IP counters
    # across the session would make unrelated tests flaky — pin it off here and
    # test it with an explicit config (see test_rate_limiting).
    RATE_LIMIT_ENABLED = False
    # PKI-2: OCSP response cache off in tests for determinism — the differential
    # HSM OCSP tests re-sign and compare, so a cache must not return the first
    # result. The cache itself is exercised in test_crl_ocsp_availability.
    OCSP_RESPONSE_CACHE_TTL_SECONDS = 0
    # Dual control off regardless of the developer's environment; the mode is
    # exercised with an explicit config in test_dual_control.
    DUAL_CONTROL_ENABLED = False


@pytest.fixture(scope="session")
def app():
    app = create_app(TestConfig)
    return app


@pytest.fixture(autouse=True)
def db(app):
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_user(db):
    user = User(username="testadmin", role="admin")
    user.set_password("adminpass")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def csr_requester(db):
    user = User(username="testrequester", role="csr_requester")
    user.set_password("requesterpass")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def auth_admin(client, admin_user):
    client.post("/auth/login", data={
        "username": "testadmin",
        "password": "adminpass",
    })
    return client


@pytest.fixture
def auth_csr_requester(client, csr_requester):
    client.post("/auth/login", data={
        "username": "testrequester",
        "password": "requesterpass",
    })
    return client


@pytest.fixture
def inactive_user(db):
    user = User(username="inactiveuser", role="admin", is_active_user=False)
    user.set_password("inactivepass")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture(autouse=True)
def _clear_basic_auth_cache(app):
    """Credentials cached by one test must never satisfy another."""
    cache = getattr(app, "basic_auth_cache", None)
    if cache is not None:
        cache.clear()
    yield


@pytest.fixture(scope="session")
def softhsm_token(tmp_path_factory):
    """Provision a throwaway SoftHSM token for the session (A1 Phase 2).

    Skips cleanly where SoftHSM / python-pkcs11 are unavailable, so the default
    software test run is unaffected; CI installs softhsm2 so the HSM path runs.
    SOFTHSM2_CONF must be set before the first pkcs11.lib() call, hence session
    scope + tmp_path_factory.
    """
    pytest.importorskip("pkcs11")
    if not shutil.which("softhsm2-util"):
        pytest.skip("softhsm2-util not installed")
    module = _find_softhsm_module()
    if not module:
        pytest.skip("libsofthsm2.so not found")

    tokendir = tmp_path_factory.mktemp("softhsm-tokens")
    conf = tmp_path_factory.mktemp("softhsm-conf") / "softhsm2.conf"
    conf.write_text(
        f"directories.tokendir = {tokendir}\n"
        "objectstore.backend = file\n"
        "log.level = ERROR\n"
    )
    os.environ["SOFTHSM2_CONF"] = str(conf)

    label, so_pin, user_pin = "certmgr-test", "12345678", "1234"
    # --module points softhsm2-util at the same library python-pkcs11 loads
    # (required when the module is not at its compiled-in default path).
    subprocess.run(
        ["softhsm2-util", "--init-token", "--free",
         "--label", label, "--so-pin", so_pin, "--pin", user_pin,
         "--module", module],
        check=True, capture_output=True,
    )
    return {"module": module, "label": label, "user_pin": user_pin, "so_pin": so_pin}
