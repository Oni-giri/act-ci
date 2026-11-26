"""Regression tests covering all security & reliability review fixes (ISSUE-01 through ISSUE-07)."""

from __future__ import annotations

import asyncio
import dataclasses
import re
import socket
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from act_ci.app import create_app
from act_ci.config import Settings, load_settings
from act_ci.db import STEP_LOG_TRUNCATION_MARKER
from act_ci.models import TriggerRunRequest, ValidationApiError
from act_ci.runner import RunnerWorker
from act_ci.security import CSRF_COOKIE_NAME, CsrfSigner
from act_ci.service import (
    MAX_OVERLAY_FILE_BYTES,
    MAX_OVERLAY_TOTAL_BYTES,
    MAX_REPLACEMENT_WORKFLOW_BYTES,
    validate_callback_url,
)
from act_ci.ui_routes import ADMIN_PRINCIPAL, _parse_dotenv_secrets
from tests.conftest import init_local_git_fixture


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m is not None, "CSRF token missing from HTML"
    return m.group(1)


# ---------------------------------------------------------------------------
# ISSUE-01: SSRF / callback_url validation & DNS-resolution guard
# ---------------------------------------------------------------------------


def test_callback_url_blocks_loopback_link_local_docker_and_allows_lan_tailscale() -> None:
    # Allowed LAN & Tailscale URLs
    assert (
        validate_callback_url("http://192.168.1.50:9000/ci-done")
        == "http://192.168.1.50:9000/ci-done"
    )
    assert (
        validate_callback_url("http://100.90.12.34:8080/hook")
        == "http://100.90.12.34:8080/hook"
    )
    assert (
        validate_callback_url("https://agent-box.tailnet.ts.net/hook")
        == "https://agent-box.tailnet.ts.net/hook"
    )

    # Disallowed SSRF targets by default
    disallowed = [
        "http://127.0.0.1:2375/containers/json",
        "http://[::1]:8080/hook",
        "http://localhost:8080/hook",
        "http://sub.localhost:8080/hook",
        "http://0.0.0.0:8080/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://[fe80::1]:8080/hook",
        "http://docker:2375/images/prune",
        "http://host.docker.internal:8080/hook",
        "http://user:pass@example.com/hook",
    ]
    for bad in disallowed:
        with pytest.raises(ValidationApiError):
            validate_callback_url(bad, allow_loopback=False)

    # Loopback allowed ONLY when allow_loopback=True, while metadata & docker remain blocked
    assert (
        validate_callback_url("http://127.0.0.1:9999/hook", allow_loopback=True)
        == "http://127.0.0.1:9999/hook"
    )
    with pytest.raises(ValidationApiError):
        validate_callback_url("http://169.254.169.254/latest", allow_loopback=True)
    with pytest.raises(ValidationApiError):
        validate_callback_url("http://docker:2375/version", allow_loopback=True)


@pytest.mark.asyncio
async def test_runner_callback_dns_rebinding_to_loopback_or_metadata_blocked(
    test_settings: Settings,
) -> None:
    app = create_app(test_settings)
    svc = app.state.service
    worker: RunnerWorker = app.state.worker

    svc.create_repo_admin(
        name="cb-repo",
        git_url="https://github.com/example/cb-repo.git",
    )
    run = svc.trigger_run(
        ADMIN_PRINCIPAL,
        TriggerRunRequest(
            repo="cb-repo",
            ref="main",
            callback_url="http://rebind.example.test:9000/hook",
        ),
    )

    # Simulate DNS resolving rebind.example.test -> 169.254.169.254
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 9000))
    ]
    loop = asyncio.get_running_loop()
    with (
        patch.object(loop, "getaddrinfo", return_value=fake_addrinfo),
        patch("httpx.AsyncClient.post") as mock_post,
    ):
        await worker._deliver_callback(
            "http://rebind.example.test:9000/hook", run.id, "passed"
        )
        mock_post.assert_not_called()

    row = app.state.db.get_run(run.id)
    assert row is not None
    assert row["callback_status"] == "delivery_failed"


# ---------------------------------------------------------------------------
# ISSUE-02: Session-bound CSRF, TTL, and Origin / Referer enforcement
# ---------------------------------------------------------------------------


def test_csrf_session_cookie_binding_ttl_and_origin_enforcement(
    test_settings: Settings,
) -> None:
    signer = CsrfSigner(b"0123456789abcdef0123456789abcdef", ttl_seconds=60)
    sid_a = signer.generate_session_id()
    sid_b = signer.generate_session_id()
    t0 = int(time.time())

    tok = signer.issue(session_id=sid_a, now=t0)
    assert signer.verify(tok, session_id=sid_a, now=t0 + 10) is True
    # Wrong session cookie rejected
    assert signer.verify(tok, session_id=sid_b, now=t0 + 10) is False
    # Expired token rejected
    assert signer.verify(tok, session_id=sid_a, now=t0 + 61) is False

    app = create_app(test_settings)
    with TestClient(app) as client_a, TestClient(app) as client_b:
        page_a = client_a.get("/repos")
        assert page_a.status_code == 200
        assert CSRF_COOKIE_NAME in client_a.cookies
        csrf_a = _extract_csrf(page_a.text)

        # Submitting client_a's CSRF token from client_b (different/no session cookie) MUST fail
        client_b.get("/repos")
        cross_session = client_b.post(
            "/repos",
            data={
                "csrf_token": csrf_a,
                "name": "stolen-csrf",
                "git_url": "https://github.com/example/r.git",
            },
        )
        assert cross_session.status_code == 403

        # Cross-origin Origin header MUST fail even with valid session cookie + CSRF token
        bad_origin = client_a.post(
            "/repos",
            data={
                "csrf_token": csrf_a,
                "name": "evil-origin",
                "git_url": "https://github.com/example/r.git",
            },
            headers={"Origin": "https://evil.example.org"},
        )
        assert bad_origin.status_code == 403

        # Cross-origin Referer header MUST fail
        bad_referer = client_a.post(
            "/repos",
            data={
                "csrf_token": csrf_a,
                "name": "evil-referer",
                "git_url": "https://github.com/example/r.git",
            },
            headers={"Referer": "https://evil.example.org/phish"},
        )
        assert bad_referer.status_code == 403

        # Matching Origin succeeds
        good_origin = client_a.post(
            "/repos",
            data={
                "csrf_token": csrf_a,
                "name": "valid-origin",
                "git_url": "https://github.com/example/r.git",
            },
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert good_origin.status_code == 303


# ---------------------------------------------------------------------------
# ISSUE-03: ACT_CI_ALLOW_LOCAL_REPOS defaults to False
# ---------------------------------------------------------------------------


def test_allow_local_repos_defaults_to_false(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ACT_CI_ALLOW_LOCAL_REPOS", raising=False)
    cfg = load_settings()
    assert cfg.allow_local_repos is False
    assert cfg.allow_loopback_callbacks is False

    strict_cfg = dataclasses.replace(cfg, data_dir=tmp_path / "strict-data", enable_worker=False)
    app = create_app(strict_cfg)
    with pytest.raises(ValidationApiError):
        app.state.service.create_repo_admin(
            name="local-attempt",
            git_url="/etc/passwd",
        )
    with pytest.raises(ValidationApiError):
        app.state.service.create_repo_admin(
            name="file-url-attempt",
            git_url="file:///tmp/some-repo",
        )


# ---------------------------------------------------------------------------
# ISSUE-04: Payload byte-size caps & per-step log truncation cap
# ---------------------------------------------------------------------------


def test_overlay_and_replacement_workflow_size_limits_and_step_log_cap(
    test_settings: Settings,
) -> None:
    app = create_app(test_settings)
    svc = app.state.service
    db = app.state.db
    svc.create_repo_admin(
        name="cap-repo",
        git_url="https://github.com/example/cap-repo.git",
    )

    # Single overlay file > 1 MiB rejected
    with pytest.raises(ValidationApiError, match="exceeds maximum size"):
        svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="cap-repo",
                overlay={"big.txt": "x" * (MAX_OVERLAY_FILE_BYTES + 1)},
            ),
        )

    # Total overlay > 4 MiB across multiple files rejected
    chunk = "y" * (900 * 1024)
    with pytest.raises(ValidationApiError, match="Total overlay size"):
        svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="cap-repo",
                overlay={f"f{i}.txt": chunk for i in range(5)},
            ),
        )
    assert MAX_OVERLAY_TOTAL_BYTES == 4 * 1024 * 1024

    # replacement_workflow > 512 KiB rejected
    with pytest.raises(ValidationApiError, match="replacement_workflow cannot exceed"):
        svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="cap-repo",
                replacement_workflow="z" * (MAX_REPLACEMENT_WORKFLOW_BYTES + 1),
            ),
        )

    # Per-step log cap truncates cleanly with marker and preserves subsequent status update
    run = svc.trigger_run(ADMIN_PRINCIPAL, TriggerRunRequest(repo="cap-repo"))
    db.upsert_step_log(
        run.id,
        job_id="j1",
        job_name="Job",
        step_id="s1",
        step_name="Noisy Step",
        status="running",
        append_text="A" * 600,
        max_log_chars=1000,
    )
    db.upsert_step_log(
        run.id,
        job_id="j1",
        job_name="Job",
        step_id="s1",
        step_name="Noisy Step",
        status="passed",
        exit_code=0,
        append_text="B" * 800,
        max_log_chars=1000,
    )
    logs = svc.get_run_logs(ADMIN_PRINCIPAL, run.id)
    step_out = logs.jobs[0].steps[0]
    assert step_out.status == "passed"
    assert step_out.exit_code == 0
    assert step_out.log.startswith("A" * 600 + "B" * 400)
    assert STEP_LOG_TRUNCATION_MARKER in step_out.log


# ---------------------------------------------------------------------------
# ISSUE-05 & ISSUE-06: Dotenv unquoting, Dockerfile SHA-256, and git clean tree
# ---------------------------------------------------------------------------


def test_dotenv_secrets_parser_unquotes_single_double_and_export_lines() -> None:
    parsed = _parse_dotenv_secrets(
        '# Comment\n'
        'PLAIN=alpha123\n'
        'DOUBLE="hello\\nworld \\"quoted\\""\n'
        "SINGLE='raw\\nliteral'\n"
        'export EXPORTED="tok_xyz"\n'
    )
    assert parsed == {
        "PLAIN": "alpha123",
        "DOUBLE": 'hello\nworld "quoted"',
        "SINGLE": "raw\\nliteral",
        "EXPORTED": "tok_xyz",
    }


def test_dockerfile_verifies_sha256_for_both_act_and_docker_cli() -> None:
    dockerfile_text = (Path(__file__).resolve().parent.parent / "Dockerfile").read_text(
        encoding="utf-8"
    )
    assert "DOCKER_CLI_SHA256_AMD64=" in dockerfile_text
    assert "DOCKER_CLI_SHA256_ARM64=" in dockerfile_text
    assert 'echo "${DOCKER_SHA}  /tmp/docker.tgz" | sha256sum -c -' in dockerfile_text


def test_replacement_workflow_keeps_git_status_clean_via_info_exclude(
    test_settings: Settings, tmp_path: Path
) -> None:
    import subprocess

    ws_dir = tmp_path / "ws"
    init_local_git_fixture(ws_dir)
    run_tmp = tmp_path / "tmp"
    run_tmp.mkdir()

    app = create_app(test_settings)
    worker: RunnerWorker = app.state.worker
    enc_payload = app.state.secret_box.encrypt_str(
        '{"replacement_workflow": "name: Override\\non: [push]\\n"}'
    )
    wf_rel = worker._apply_overlay_and_workflow(
        run_row={"encrypted_payload": enc_payload, "workflow_path": None},
        workspace_dir=ws_dir,
        run_tmp_dir=run_tmp,
    )
    assert wf_rel == ".github/workflows/__act_ci_replacement__.yml"
    assert (ws_dir / wf_rel).is_file()

    # git status --porcelain inside workspace MUST remain completely clean!
    porcelain = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ws_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert porcelain == ""


@pytest.mark.asyncio
async def test_stream_stdout_preserves_lines_across_slow_pauses(
    tmp_path: Path,
) -> None:
    """Regression test: partial/paused stdout lines >100ms must not be dropped by readline cancellation."""
    import stat as stat_mod

    repo_dir = tmp_path / "slow-repo"
    init_local_git_fixture(repo_dir)
    stub_act = tmp_path / "slow_act.py"
    stub_act.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys, time\n"
        "sys.stdout.write(json.dumps({'jobID': 'j1', 'job': 'J', 'stepID': 's1', 'step': 'S', 'rawOutput': True, 'msg': 'FIRST_LINE'}) + '\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(0.25)\n"
        "sys.stdout.write('{\"jobID\": \"j1\", \"job\": \"J\", \"stepID\": \"s1\", \"step\": \"S\", \"rawOutput\": true, ')\n"
        "sys.stdout.flush()\n"
        "time.sleep(0.25)\n"
        "sys.stdout.write('\"msg\": \"SPLIT_ACROSS_PAUSE\"}\\n')\n"
        "sys.stdout.write(json.dumps({'jobID': 'j1', 'job': 'J', 'stepID': 's1', 'step': 'S', 'executionResult': 'success', 'msg': 'ok'}) + '\\n')\n"
        "sys.stdout.flush()\n",
        encoding="utf-8",
    )
    stub_act.chmod(stub_act.stat().st_mode | stat_mod.S_IXUSR)

    cfg = Settings(
        data_dir=tmp_path / "data",
        host="127.0.0.1",
        port=8080,
        docker_host="unix:///nonexistent/dind.sock",
        act_binary=str(stub_act),
        git_binary="git",
        docker_binary="nonexistent-docker-bin",
        master_key_env="0123456789abcdef0123456789abcdef",
        csrf_secret_env="level2-real-docker-csrf-secret-0123456789abcdef",
        allow_local_repos=True,
        prune_interval_seconds=0,
        prune_until="168h",
        enable_worker=True,
        allow_loopback_callbacks=True,
    )
    app = create_app(cfg)
    svc = app.state.service
    worker: RunnerWorker = app.state.worker
    svc.create_repo_admin(name="slow", git_url=str(repo_dir))
    await worker.start()
    try:
        r = svc.trigger_run(ADMIN_PRINCIPAL, TriggerRunRequest(repo="slow", ref="main"))
        for _ in range(80):
            st = svc.get_run_status(ADMIN_PRINCIPAL, r.id)
            if st.status in ("passed", "failed"):
                break
            await asyncio.sleep(0.05)
        logs = svc.get_run_logs(ADMIN_PRINCIPAL, r.id)
        assert st.status == "passed"
        assert "FIRST_LINE" in logs.raw_log
        assert "SPLIT_ACROSS_PAUSE" in logs.raw_log
    finally:
        await worker.stop()
