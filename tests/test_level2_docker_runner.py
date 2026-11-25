"""Level 2 runner tests against a REAL isolated Docker daemon + pinned nektos/act v0.2.98.

Every test uses local git fixture repositories created on the fly (no GitHub access required).
Covers all required Level 2 checks:
1. A passing commit ends "passed"; a failing commit ends "failed" with the failing step's log stored.
2. The repo's own workflow runs unchanged; a replacement workflow and overlay files are applied when given.
3. A step that hangs is killed at the timeout and the run is "timed_out".
4. Cancelling a running job stops it and leaves no containers.
5. A workflow with a Postgres service container passes.
6. Two runs submitted together execute one after the other on one slot.
7. The callback URL receives the run ID and final status.
8. After each run nothing is left behind: no workspace directory, and `docker ps -a` on the slot's
   daemon shows no job containers.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from act_ci.app import create_app
from act_ci.config import Settings
from act_ci.models import TriggerRunRequest
from act_ci.runner import RunnerWorker
from act_ci.ui_routes import ADMIN_PRINCIPAL
from tests.conftest import init_local_git_fixture

# Lightweight Alpine/Debian image with bash + node/sh or standard tools for fast local runner tests
TEST_RUNNER_IMAGE = os.environ.get("ACT_CI_TEST_RUNNER_IMAGE", "node:20-bookworm-slim")


def _slot_docker_host() -> str | None:
    """Require an explicit isolated slot Docker daemon URI (e.g. DinD sidecar) for Level 2 tests."""
    host = os.environ.get("ACT_CI_TEST_DOCKER_HOST")
    if not host:
        return None
    docker_bin = shutil.which("docker")
    act_bin = os.environ.get("ACT_CI_ACT_BINARY") or shutil.which("act")
    if not docker_bin or not act_bin:
        return None
    res = subprocess.run(
        [docker_bin, "-H", host, "info"],
        capture_output=True,
        timeout=10,
    )
    return host if res.returncode == 0 else None


pytestmark = pytest.mark.docker


@pytest.fixture
def real_docker_env(tmp_path: Path) -> tuple[Settings, str]:
    docker_host = _slot_docker_host()
    if not docker_host:
        pytest.skip(
            "Level 2 requires ACT_CI_TEST_DOCKER_HOST pointing to an isolated Docker/DinD daemon plus `docker` and `act`"
        )
    act_bin = os.environ.get("ACT_CI_ACT_BINARY") or shutil.which("act")
    assert act_bin is not None
    settings = Settings(
        data_dir=tmp_path / "data",
        host="127.0.0.1",
        port=8080,
        docker_host=docker_host,
        act_binary=act_bin,
        git_binary="git",
        docker_binary="docker",
        master_key_env="level2-real-docker-master-key-0123456789abcdef",
        csrf_secret_env="level2-real-docker-csrf-secret-0123456789abcdef",
        allow_local_repos=True,
        prune_interval_seconds=0,
        prune_until="168h",
        enable_worker=True,
    )
    return settings, docker_host


def _assert_slot_clean(settings: Settings, docker_host: str) -> None:
    """Verify no workspace directory and zero containers remain on the slot daemon (`docker ps -a`)."""
    if settings.slot_workspace_root.exists():
        leftover_ws = list(settings.slot_workspace_root.iterdir())
        assert leftover_ws == [], f"Workspace directory left behind: {leftover_ws}"
    if settings.slot_temp_root.exists():
        leftover_tmp = list(settings.slot_temp_root.iterdir())
        assert leftover_tmp == [], f"Temp directory left behind: {leftover_tmp}"

    ps_out = subprocess.run(
        ["docker", "-H", docker_host, "ps", "-a", "--format", "{{.ID}} {{.Names}} {{.Status}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert ps_out == "", f"Leftover containers on slot daemon:\n{ps_out}"


async def _wait_for_run(svc, run_id: str, timeout_s: float = 180.0):
    deadline = asyncio.get_running_loop().time() + timeout_s
    while asyncio.get_running_loop().time() < deadline:
        st = svc.get_run_status(ADMIN_PRINCIPAL, run_id)
        if st.status in ("passed", "failed", "cancelled", "timed_out"):
            return st
        await asyncio.sleep(0.25)
    raise TimeoutError(f"Run {run_id} did not reach terminal state within {timeout_s}s")


@pytest.mark.asyncio
async def test_level2_passing_failing_overlay_replacement_and_callback(
    real_docker_env: tuple[Settings, str], tmp_path: Path
) -> None:
    settings, docker_host = real_docker_env

    # Start a tiny local callback receiver
    received_callbacks: list[dict[str, Any]] = []

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            received_callbacks.append(json.loads(raw.decode("utf-8")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass

    cb_server = HTTPServer(("127.0.0.1", 0), CallbackHandler)
    cb_port = cb_server.server_address[1]
    cb_thread = threading.Thread(target=cb_server.serve_forever, daemon=True)
    cb_thread.start()

    repo_dir = tmp_path / "repo-basic"
    sha_pass = init_local_git_fixture(
        repo_dir,
        {
            "greeting.txt": "UNCHANGED_REPO_CONTENT\n",
            ".github/workflows/ci.yml": (
                "name: RepoCI\n"
                "on: [push]\n"
                "jobs:\n"
                "  verify:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - name: Print greeting\n"
                "        run: cat greeting.txt\n"
            ),
        },
    )
    # Create a second commit that fails
    (repo_dir / ".github/workflows/ci.yml").write_text(
        "name: RepoCI\n"
        "on: [push]\n"
        "jobs:\n"
        "  verify:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Intentional failure\n"
        "        run: |\n"
        "          echo 'ABOUT_TO_FAIL_MARKER'\n"
        "          exit 42\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "failing commit"], cwd=repo_dir, check=True)
    sha_fail = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True
    ).stdout.strip()

    app = create_app(settings)
    svc = app.state.service
    worker: RunnerWorker = app.state.worker
    svc.create_repo_admin(
        name="basic",
        git_url=str(repo_dir),
        default_image=TEST_RUNNER_IMAGE,
        timeout_seconds=120,
        secrets_dict={"SUPER_SECRET": "MASK_ME_IN_REAL_ACT_778899"},
    )

    await worker.start()
    try:
        # 1. Passing commit (repo's own workflow unchanged) + callback URL
        r1 = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="basic",
                ref=sha_pass,
                callback_url=f"http://127.0.0.1:{cb_port}/hook",
            ),
        )
        res1 = await _wait_for_run(svc, r1.id)
        assert res1.status == "passed"
        assert res1.commit_sha == sha_pass
        logs1 = svc.get_run_logs(ADMIN_PRINCIPAL, r1.id)
        assert "UNCHANGED_REPO_CONTENT" in logs1.raw_log
        _assert_slot_clean(settings, docker_host)
        assert received_callbacks[-1] == {"run_id": r1.id, "status": "passed"}

        # 2. Failing commit -> ends "failed" with failing step's log stored
        r2 = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="basic",
                ref=sha_fail,
                callback_url=f"http://127.0.0.1:{cb_port}/hook",
            ),
        )
        res2 = await _wait_for_run(svc, r2.id)
        assert res2.status == "failed"
        logs2 = svc.get_run_logs(ADMIN_PRINCIPAL, r2.id)
        assert "ABOUT_TO_FAIL_MARKER" in logs2.raw_log
        _assert_slot_clean(settings, docker_host)
        assert received_callbacks[-1] == {"run_id": r2.id, "status": "failed"}

        # 3. Overlay files + replacement workflow applied on top of failing commit -> passes!
        r3 = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="basic",
                ref=sha_fail,
                overlay={"extra/added_test.txt": "OVERLAY_APPLIED_OK\n"},
                replacement_workflow=(
                    "name: ReplacementCI\n"
                    "on: [push]\n"
                    "jobs:\n"
                    "  check-overlay:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - name: Verify overlay and secret masking\n"
                    "        env:\n"
                    "          S: ${{ secrets.SUPER_SECRET }}\n"
                    "        run: |\n"
                    "          grep -q 'OVERLAY_APPLIED_OK' extra/added_test.txt\n"
                    "          echo \"OVERLAY_VERIFIED secret=$S\"\n"
                ),
            ),
        )
        res3 = await _wait_for_run(svc, r3.id)
        assert res3.status == "passed"
        logs3 = svc.get_run_logs(ADMIN_PRINCIPAL, r3.id)
        assert "OVERLAY_VERIFIED" in logs3.raw_log
        assert "MASK_ME_IN_REAL_ACT_778899" not in logs3.raw_log
        _assert_slot_clean(settings, docker_host)
    finally:
        cb_server.shutdown()
        await worker.stop()


@pytest.mark.asyncio
async def test_level2_timeout_and_cancel_and_two_runs_queue(
    real_docker_env: tuple[Settings, str], tmp_path: Path
) -> None:
    settings, docker_host = real_docker_env
    repo_dir = tmp_path / "repo-timing"
    init_local_git_fixture(repo_dir)

    app = create_app(settings)
    svc = app.state.service
    worker: RunnerWorker = app.state.worker

    svc.create_repo_admin(
        name="short-timeout-repo",
        git_url=str(repo_dir),
        default_image=TEST_RUNNER_IMAGE,
        timeout_seconds=8,
    )
    svc.create_repo_admin(
        name="normal-repo",
        git_url=str(repo_dir),
        default_image=TEST_RUNNER_IMAGE,
        timeout_seconds=120,
    )

    await worker.start()
    try:
        # 1. Hanging step killed at timeout -> "timed_out" and zero leftover containers
        r_timeout = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="short-timeout-repo",
                ref="main",
                replacement_workflow=(
                    "name: Hang\n"
                    "on: [push]\n"
                    "jobs:\n"
                    "  hang:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - name: Sleep forever\n"
                    "        run: sleep 120\n"
                ),
            ),
        )
        res_to = await _wait_for_run(svc, r_timeout.id, timeout_s=45.0)
        assert res_to.status == "timed_out"
        _assert_slot_clean(settings, docker_host)

        # 2. Cancel a running job -> stops it and leaves zero containers on slot daemon
        r_cancel = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="normal-repo",
                ref="main",
                replacement_workflow=(
                    "name: CancelMe\n"
                    "on: [push]\n"
                    "jobs:\n"
                    "  long:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - name: Running marker\n"
                    "        run: |\n"
                    "          echo 'CONTAINER_IS_LIVE'\n"
                    "          sleep 90\n"
                ),
            ),
        )
        # Wait until container is genuinely running inside DinD
        for _ in range(80):
            ps = subprocess.run(
                ["docker", "-H", docker_host, "ps", "-q"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if ps:
                break
            await asyncio.sleep(0.25)
        svc.cancel_run(ADMIN_PRINCIPAL, r_cancel.id)
        res_cancel = await _wait_for_run(svc, r_cancel.id, timeout_s=45.0)
        assert res_cancel.status == "cancelled"
        _assert_slot_clean(settings, docker_host)

        # 3. Two runs submitted together execute one after the other on one slot
        run_a = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="normal-repo",
                ref="main",
                replacement_workflow=(
                    "name: SeqA\n"
                    "on: [push]\n"
                    "jobs:\n"
                    "  same-job-name:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - name: Work A\n"
                    "        run: |\n"
                    "          sleep 2\n"
                    "          echo 'DONE_A'\n"
                ),
            ),
        )
        run_b = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="normal-repo",
                ref="main",
                replacement_workflow=(
                    "name: SeqB\n"
                    "on: [push]\n"
                    "jobs:\n"
                    "  same-job-name:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - name: Work B\n"
                    "        run: echo 'DONE_B'\n"
                ),
            ),
        )
        done_a = await _wait_for_run(svc, run_a.id, timeout_s=90.0)
        done_b = await _wait_for_run(svc, run_b.id, timeout_s=90.0)
        assert done_a.status == "passed"
        assert done_b.status == "passed"
        assert done_a.finished_at is not None and done_b.started_at is not None
        assert done_b.started_at >= done_a.finished_at
        _assert_slot_clean(settings, docker_host)
    finally:
        await worker.stop()


@pytest.mark.asyncio
async def test_level2_postgres_service_container_workflow(
    real_docker_env: tuple[Settings, str], tmp_path: Path
) -> None:
    settings, docker_host = real_docker_env
    repo_dir = tmp_path / "repo-pg"
    init_local_git_fixture(
        repo_dir,
        {
            ".github/workflows/postgres.yml": (
                "name: PostgresServiceCheck\n"
                "on: [push]\n"
                "jobs:\n"
                "  db-integration:\n"
                "    runs-on: ubuntu-latest\n"
                "    services:\n"
                "      postgres:\n"
                "        image: postgres:16-alpine\n"
                "        env:\n"
                "          POSTGRES_USER: ciuser\n"
                "          POSTGRES_PASSWORD: cipassword\n"
                "          POSTGRES_DB: cidb\n"
                "        ports:\n"
                "          - 5432:5432\n"
                "        options: >-\n"
                "          --health-cmd=\"pg_isready -U ciuser -d cidb\"\n"
                "          --health-interval=2s\n"
                "          --health-timeout=3s\n"
                "          --health-retries=15\n"
                "    steps:\n"
                "      - name: Query Postgres service container\n"
                "        run: |\n"
                "          node -e '\n"
                "            const net = require(\"net\");\n"
                "            const hosts = [\"postgres\", \"localhost\", \"127.0.0.1\"];\n"
                "            (async () => {\n"
                "              for (let attempt = 0; attempt < 20; attempt++) {\n"
                "                for (const h of hosts) {\n"
                "                  const ok = await new Promise((res) => {\n"
                "                    const s = net.createConnection({host: h, port: 5432}, () => { s.end(); res(true); });\n"
                "                    s.on(\"error\", () => res(false));\n"
                "                  });\n"
                "                  if (ok) { console.log(\"POSTGRES_CONNECTED_ON=\" + h); process.exit(0); }\n"
                "                }\n"
                "                await new Promise(r => setTimeout(r, 1000));\n"
                "              }\n"
                "              process.exit(1);\n"
                "            })();\n"
                "          '\n"
            )
        },
    )

    app = create_app(settings)
    svc = app.state.service
    worker: RunnerWorker = app.state.worker
    svc.create_repo_admin(
        name="pg-repo",
        git_url=str(repo_dir),
        default_image=TEST_RUNNER_IMAGE,
        timeout_seconds=180,
    )

    await worker.start()
    try:
        r_pg = svc.trigger_run(
            ADMIN_PRINCIPAL, TriggerRunRequest(repo="pg-repo", ref="main")
        )
        res_pg = await _wait_for_run(svc, r_pg.id, timeout_s=180.0)
        logs_pg = svc.get_run_logs(ADMIN_PRINCIPAL, r_pg.id)
        assert res_pg.status == "passed", f"Postgres service run failed:\n{logs_pg.raw_log}"
        assert "POSTGRES_CONNECTED_ON=" in logs_pg.raw_log
        _assert_slot_clean(settings, docker_host)
    finally:
        await worker.stop()
