"""G14-2 (3.5.0): the reference deployment stays hardened — read-only root
filesystem with tmpfs scratch, capability drop, non-root, access log wiring,
precompiled bytecode. Textual checks on the shipped artefacts."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_compose_read_only_rootfs_and_tmpfs():
    compose = (ROOT / "docker-compose.yml").read_text()
    assert re.search(r"^\s+read_only: true$", compose, re.M)
    assert re.search(r"^\s+- /tmp:rw,nosuid,noexec,size=\d+m", compose, re.M)
    assert re.search(r"^\s+- /home/app:rw,nosuid,noexec,size=\d+m,uid=1000,gid=1000", compose, re.M)
    assert "no-new-privileges:true" in compose and re.search(r"cap_drop:\n\s+- ALL", compose)
    assert "ACCESS_LOG=${ACCESS_LOG:-true}" in compose and "PYTHONDONTWRITEBYTECODE=1" in compose
    # persistent state is confined to the data volume
    assert "./data:/app/data" in compose and "AUDIT_ARCHIVE_DIR=${AUDIT_ARCHIVE_DIR:-}" in compose


def test_entrypoint_access_log_and_worker_tmp():
    entry = (ROOT / "entrypoint-app.sh").read_text()
    assert "--worker-tmp-dir /dev/shm" in entry
    assert "--access-logfile -" in entry and "%(U)s" in entry and "%(q)s" not in entry
    assert 'ACCESS_LOG:-true' in entry


def test_dockerfile_precompiles_bytecode():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "compileall" in dockerfile and "PYTHONDONTWRITEBYTECODE=1" in dockerfile
