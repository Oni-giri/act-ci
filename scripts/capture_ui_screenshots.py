#!/usr/bin/env python3
"""Render Act-CI Omakase UI screens at 1440x1000 via headless Chromium for visual verification."""

from __future__ import annotations

import os
import tempfile
import threading
import time
from pathlib import Path

import uvicorn
from playwright.sync_api import sync_playwright

from act_ci.app import create_app
from act_ci.config import Settings
from act_ci.models import TriggerRunRequest
from act_ci.ui_routes import ADMIN_PRINCIPAL


def main() -> None:
    out_dir = Path("/tmp/actci-ui-screenshots")
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        settings = Settings(
            data_dir=Path(td) / "data",
            host="127.0.0.1",
            port=18755,
            docker_host="unix:///nonexistent/docker.sock",
            act_binary="act",
            git_binary="git",
            docker_binary="docker",
            master_key_env="screenshot-master-key-0123456789abcdef012345",
            csrf_secret_env="SI_SECRET_SECRET_D7Z6781T",
            allow_local_repos=True,
            prune_interval_seconds=0,
            prune_until="168h",
            enable_worker=False,
        )
        app = create_app(settings)
        svc = app.state.service
        db = app.state.db

        svc.create_repo_admin(
            name="periscope",
            git_url="https://github.com/Oni-giri/periscope.git",
            credential_type="token",
            credential_value="ghp_demo_readonly_token_1234567890",
            secrets_dict={"DATABASE_URL": "postgres://demo/db", "API_KEY": "secret"},
        )
        svc.create_repo_admin(
            name="browser-pier",
            git_url="https://github.com/Oni-giri/browser-pier.git",
            credential_type="none",
        )
        svc.create_repo_admin(
            name="act-ci",
            git_url="https://github.com/Oni-giri/act-ci.git",
            credential_type="deploy_key",
            credential_value="-----BEGIN OPENSSH PRIVATE KEY-----\ndemo\n-----END OPENSSH PRIVATE KEY-----",
        )

        _, op_tok = svc.create_token(name="impl-claude", role="operator")
        _, vw_tok = svc.create_token(name="reviewer-opus", role="viewer")

        op_principal = svc.authenticate_bearer(
            f"Bearer {op_tok}", source="mcp", attempted_action="runs.trigger"
        )
        vw_principal = svc.authenticate_bearer(
            f"Bearer {vw_tok}", source="api", attempted_action="runs.list"
        )

        r1 = svc.trigger_run(
            op_principal,
            TriggerRunRequest(
                repo="periscope",
                ref="main",
                overlay={"tests/test_rate_limit.py": "def test_429(): assert True\n"},
                private=True,
            ),
        )
        db.set_run_commit_sha(r1.id, "5f3a9c18d4e011223344556677889900aabbccdd")
        db.upsert_step_log(
            r1.id,
            job_id="verify",
            job_name="Verify holdout suite",
            step_id="1",
            step_name="Set up job",
            stage="Pre",
            status="passed",
            exit_code=0,
            append_text="Pulling catthehacker/ubuntu:act-22.04\n",
        )
        db.upsert_step_log(
            r1.id,
            job_id="verify",
            job_name="Verify holdout suite",
            step_id="2",
            step_name="Run pytest suite",
            stage="Main",
            status="passed",
            exit_code=0,
            append_text="collected 24 items\n24 passed in 3.42s\n",
        )
        db.finish_run(r1.id, status="passed", exit_code=0)

        r2 = svc.trigger_run(
            op_principal,
            TriggerRunRequest(repo="browser-pier", ref="feat/webrtc-clipboard"),
        )
        db.set_run_commit_sha(r2.id, "9b21e04aa11223344556677889900aabbccddeeff")
        db.upsert_step_log(
            r2.id,
            job_id="lint-and-test",
            job_name="Lint and unit tests",
            step_id="1",
            step_name="Check out repository",
            stage="Main",
            status="passed",
            exit_code=0,
            append_text="Checked out 9b21e04a\n",
        )
        db.upsert_step_log(
            r2.id,
            job_id="lint-and-test",
            job_name="Lint and unit tests",
            step_id="2",
            step_name="Run clipboard integration check",
            stage="Main",
            status="failed",
            exit_code=1,
            append_text="AssertionError: expected empty clipboard after handback\nexitcode '1': failure\n",
        )
        db.finish_run(
            r2.id,
            status="failed",
            exit_code=1,
            error_message="act exited with code 1",
        )

        r3 = svc.trigger_run(
            ADMIN_PRINCIPAL,
            TriggerRunRequest(repo="act-ci", ref="HEAD"),
        )
        svc.list_runs(vw_principal)
        try:
            svc.get_run_logs(vw_principal, r1.id)
        except Exception:
            pass

        config = uvicorn.Config(app, host="127.0.0.1", port=18755, log_level="warning")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        time.sleep(1.5)

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                for slug, url in [
                    ("runs-list", "http://127.0.0.1:18755/runs"),
                    ("run-detail", f"http://127.0.0.1:18755/runs/{r2.id}"),
                    ("repos", "http://127.0.0.1:18755/repos"),
                    ("tokens", "http://127.0.0.1:18755/tokens"),
                    ("activity", "http://127.0.0.1:18755/activity"),
                ]:
                    page.goto(url, wait_until="networkidle")
                    page.wait_for_timeout(300)
                    page.screenshot(path=str(out_dir / f"{slug}.png"), full_page=False)
                browser.close()
        finally:
            server.should_exit = True
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
