"""Level 1 unit & integration tests for Milestone 2 (runner logic without Docker) and Milestone 3 (Web UI)."""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from act_ci.app import create_app
from act_ci.config import Settings
from act_ci.models import TriggerRunRequest
from act_ci.runner import RunnerWorker, map_act_json_event, parse_act_json_line
from act_ci.ui_routes import ADMIN_PRINCIPAL
from tests.conftest import init_local_git_fixture


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m is not None, "CSRF token missing from HTML page"
    return m.group(1)


def test_act_command_flags_verified_against_act_v0_2_98_help(test_settings: Settings) -> None:
    """Verify every flag emitted by build_act_command uses copy mode (no -b/--bind) and valid act flags."""
    app = create_app(test_settings)
    worker: RunnerWorker = app.state.worker
    cmd = worker.build_act_command(
        default_image="catthehacker/ubuntu:act-22.04",
        event_name="push",
        workflow_arg=".github/workflows/ci.yml",
        workspace_dir=Path("/tmp/ws"),
        secret_file=Path("/tmp/secrets"),
    )
    assert "-b" not in cmd
    assert "--bind" not in cmd
    assert "--json" in cmd
    assert "--rm" in cmd
    assert "--no-cache-server" in cmd
    assert "--container-daemon-socket" in cmd
    idx = cmd.index("--container-daemon-socket")
    assert cmd[idx + 1] == "-"
    assert "-C" in cmd
    assert "-W" in cmd
    assert "--secret-file" in cmd

    # If the pinned act v0.2.98 binary is available locally, verify --help documents every flag we pass!
    act_bin = Path("/tmp/act-bin/act")
    if act_bin.exists():
        import subprocess

        help_out = subprocess.run(
            [str(act_bin), "--help"], check=True, capture_output=True, text=True
        ).stdout
        used_long_flags = [
            tok for tok in cmd if tok.startswith("--")
        ]
        for fl in used_long_flags:
            assert fl in help_out, f"Flag {fl} not documented in act v0.2.98 --help"


def test_act_json_parser_groups_jobs_and_steps() -> None:
    line1 = json.dumps(
        {
            "job": "Unit Tests",
            "jobID": "unit",
            "step": "Run pytest",
            "stepID": "pytest",
            "stage": "Main",
            "rawOutput": True,
            "msg": "collected 12 items\n",
            "time": "2026-11-25T20:00:01Z",
        }
    )
    ev1 = parse_act_json_line(line1)
    assert ev1 is not None
    mapped1 = map_act_json_event(ev1)
    assert mapped1["job_id"] == "unit"
    assert mapped1["step_id"] == "pytest"
    assert mapped1["append_text"] == "collected 12 items\n"
    assert mapped1["status"] is None

    line2 = json.dumps(
        {
            "job": "Unit Tests",
            "jobID": "unit",
            "step": "Run pytest",
            "stepID": "pytest",
            "stage": "Main",
            "executionResult": "failure",
            "msg": "exitcode '1': failure",
        }
    )
    mapped2 = map_act_json_event(parse_act_json_line(line2))  # type: ignore[arg-type]
    assert mapped2["status"] == "failed"
    assert mapped2["exit_code"] == 1


@pytest.mark.asyncio
async def test_runner_lifecycle_with_stub_act_clone_overlay_timeout_queue_and_cleanup(
    tmp_path: Path,
) -> None:
    """Test full RunnerWorker git clone, overlay, replacement workflow, sequential slot queue,
    timeout kill, workspace deletion, and callback using a deterministic stub `act` script."""
    repo_dir = tmp_path / "fixture-repo"
    sha1 = init_local_git_fixture(
        repo_dir,
        {
            "hello.txt": "original\n",
            ".github/workflows/ci.yml": "name: RepoWF\non: [push]\n",
        },
    )

    stub_act = tmp_path / "stub_act.py"
    stub_act.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys, time\n"
        "args = sys.argv[1:]\n"
        "ws = pathlib.Path(args[args.index('-C') + 1])\n"
        "wf = args[args.index('-W') + 1] if '-W' in args else '.github/workflows/ci.yml'\n"
        "wf_text = (ws / wf).read_text(encoding='utf-8')\n"
        "hello_text = (ws / 'hello.txt').read_text(encoding='utf-8')\n"
        "print(json.dumps({'jobID':'build','job':'Build','stepID':'s1','step':'Check','stage':'Main','rawOutput':True,'msg':f'hello={hello_text.strip()} wf_len={len(wf_text)}\\n'}), flush=True)\n"
        "if 'SLEEP_HANG' in wf_text:\n"
        "    time.sleep(30)\n"
        "if 'FAIL_NOW' in wf_text:\n"
        "    print(json.dumps({'jobID':'build','job':'Build','stepID':'s1','step':'Check','stage':'Main','executionResult':'failure','msg':'step failed'}), flush=True)\n"
        "    sys.exit(1)\n"
        "print(json.dumps({'jobID':'build','job':'Build','stepID':'s1','step':'Check','stage':'Main','executionResult':'success','msg':'step passed'}), flush=True)\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    stub_act.chmod(os.stat(stub_act).st_mode | stat.S_IEXEC)

    settings = Settings(
        data_dir=tmp_path / "app-data",
        host="127.0.0.1",
        port=8080,
        docker_host="unix:///nonexistent/docker.sock",
        act_binary=str(stub_act),
        git_binary="git",
        docker_binary="nonexistent-docker-cli",
        master_key_env="runner-test-master-key-minimum-32-bytes!!",
        csrf_secret_env="SI_SECRET_SECRET_09C009B1",
        allow_local_repos=True,
        prune_interval_seconds=0,
        prune_until="168h",
        enable_worker=True,
    )
    app = create_app(settings)
    svc = app.state.service
    worker: RunnerWorker = app.state.worker

    svc.create_repo_admin(
        name="local-fixture",
        git_url=str(repo_dir),
        timeout_seconds=2,
        secrets_dict={"MY_SEC": "TOP_SECRET_VALUE_999"},
    )

    await worker.start()
    try:
        # 1. Passing run with overlay
        r_pass = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="local-fixture",
                ref=sha1,
                overlay={"hello.txt": "overlaid-by-caller\n"},
            ),
        )
        # 2. Failing run with replacement workflow
        r_fail = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="local-fixture",
                ref="main",
                replacement_workflow="name: Fail\n# FAIL_NOW TOP_SECRET_VALUE_999\n",
            ),
        )
        # 3. Hanging run that hits the 2s timeout
        r_hang = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(
                repo="local-fixture",
                ref="main",
                replacement_workflow="name: Hang\n# SLEEP_HANG\n",
            ),
        )

        # Wait until all 3 finish sequentially on slot-0
        for _ in range(80):
            statuses = [
                svc.get_run_status(ADMIN_PRINCIPAL, rid).status
                for rid in (r_pass.id, r_fail.id, r_hang.id)
            ]
            if all(s in ("passed", "failed", "cancelled", "timed_out") for s in statuses):
                break
            await asyncio.sleep(0.1)

        s_pass = svc.get_run_status(ADMIN_PRINCIPAL, r_pass.id)
        s_fail = svc.get_run_status(ADMIN_PRINCIPAL, r_fail.id)
        s_hang = svc.get_run_status(ADMIN_PRINCIPAL, r_hang.id)

        assert s_pass.status == "passed"
        assert s_pass.commit_sha == sha1
        pass_logs = svc.get_run_logs(ADMIN_PRINCIPAL, r_pass.id)
        assert "hello=overlaid-by-caller" in pass_logs.raw_log

        assert s_fail.status == "failed"
        assert s_hang.status == "timed_out"

        # Verify sequential execution on slot-0: r_fail started_at >= r_pass finished_at
        assert s_pass.finished_at is not None and s_fail.started_at is not None
        assert s_fail.started_at >= s_pass.finished_at

        # Verify workspace and temp directories were completely deleted after every run
        assert list(settings.slot_workspace_root.iterdir()) == []
        assert list(settings.slot_temp_root.iterdir()) == []
    finally:
        await worker.stop()


def test_web_ui_pages_filters_forms_and_csrf(client: TestClient) -> None:
    # 1. Runs list loads empty state with Omakase canvas, CSS, and sentence-case heading
    r_home = client.get("/")
    assert r_home.status_code == 200
    assert "Workflow runs" in r_home.text
    assert 'data-theme="auto"' in r_home.text
    assert 'class="om-app om-canvas"' in r_home.text
    assert 'class="om-ic"' in r_home.text
    assert "/ui-assets/omakase/icons/" not in r_home.text
    assert "/ui-assets/omakase/css/omakase.css" in r_home.text

    # Verify Omakase stylesheet and icons are served and protected from bearer tokens
    css_resp = client.get("/ui-assets/omakase/css/omakase.css")
    assert css_resp.status_code == 200
    assert "--canvas:" in css_resp.text
    assert '[data-theme="dark"]' in css_resp.text
    assert client.get("/ui-assets/../ui_routes.py").status_code == 404

    # 2. Repos page: create and edit repo, verify CSRF enforcement
    r_repos = client.get("/repos")
    assert r_repos.status_code == 200
    csrf = _extract_csrf(r_repos.text)

    # Missing CSRF rejected
    bad_csrf = client.post(
        "/repos",
        data={"name": "no-csrf", "git_url": "https://github.com/example/repo.git"},
    )
    assert bad_csrf.status_code == 403

    # Valid repo creation
    create_repo = client.post(
        "/repos",
        data={
            "csrf_token": csrf,
            "name": "ui-app",
            "git_url": "https://github.com/example/ui-app.git",
            "credential_type": "none",
            "default_image": "catthehacker/ubuntu:act-22.04",
            "timeout_seconds": "600",
            "secrets_text": "API_KEY=secret_ui_val_12345\n",
        },
        follow_redirects=True,
    )
    assert create_repo.status_code == 200
    assert "ui-app" in create_repo.text
    assert "secret_ui_val_12345" not in create_repo.text
    assert "1 key(s)" in create_repo.text

    # 3. Trigger a run via UI "Run" button
    trig = client.post(
        "/runs/trigger",
        data={"csrf_token": csrf, "repo": "ui-app", "ref": "main"},
        follow_redirects=False,
    )
    assert trig.status_code == 303
    run_path = trig.headers["location"]
    assert run_path.startswith("/runs/run_")

    # 4. Run detail page + live polling JSON endpoint
    detail = client.get(run_path)
    assert detail.status_code == 200
    assert "ui-app" in detail.text
    live = client.get(f"{run_path}/live")
    assert live.status_code == 200
    assert live.json()["run"]["status"] == "queued"

    # 5. Filter runs list by repo and status
    assert "ui-app" in client.get("/runs?repo=ui-app&status=queued").text
    assert run_path.split("/")[-1] not in client.get("/runs?repo=ui-app&status=passed").text

    # 6. Cancel queued run from UI
    cancel = client.post(
        f"{run_path}/cancel",
        data={"csrf_token": csrf},
        follow_redirects=True,
    )
    assert cancel.status_code == 200
    assert "Cancelled" in cancel.text
