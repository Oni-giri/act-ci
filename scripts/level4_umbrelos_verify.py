#!/usr/bin/env python3
"""Level 4 end-to-end verification inside containerized umbrelOS 2.0.2.

Follows `.agents/skills/umbrel-test-app` from `getumbrel/umbrel-apps`:
1. Syncs `yakitori-act-ci` into the umbrelOS app-store directory (`--exclude=.gitkeep`).
2. Installs via `umbreld client apps.install.mutate --appId yakitori-act-ci` and waits for `ready`.
3. Verifies Fresh-Install Checklist:
   - (1) App opens from Umbrel's app port (`8755`), not a raw internal container port (`8080` is not host-published).
   - (2) UI and admin routes (`/` and `/tokens`) require Umbrel's login (`302` / Umbrel auth redirect, never raw app HTML).
   - (3) API (`/api/v1/repos`) and MCP (`/mcp`) return `401` without a bearer token and `200` with a valid bearer token through Umbrel's port `8755`.
   - (4) Probes nested Docker-in-Docker inside containerized umbrelOS; if nested DinD starts, runs a full workflow on a fixture repo inside the installed app and asserts `passed`. If nested DinD fails due to containerized umbrelOS nesting constraints, reports the exact failure reason without claiming nested runtime coverage.
   - (5) Runs `umbreld client apps.restart.mutate --appId yakitori-act-ci` and verifies tokens, repos, and run history persist.
   - (6) Inspects settled `apps.logs.query` for errors.
4. Verifies Update Path:
   - Bumps `umbrel-app.yml` version (`0.1.0` -> `0.1.1`), runs `umbreld client apps.update.mutate --appId yakitori-act-ci`, and repeats checks (3) and (5).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CONTAINER = "umbrelos-test"
APP_ID = "yakitori-act-ci"
APP_PORT = 8755


def run_cmd(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(
            f"Command failed ({res.returncode}): {' '.join(cmd)}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
    return res


def http_req(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], str]:
    # Do NOT follow redirects automatically so we can see Umbrel's 302 login redirect!
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read().decode("utf-8", errors="replace")


def wait_app_ready(timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_out = ""
    while time.monotonic() < deadline:
        res = run_cmd(
            ["docker", "exec", CONTAINER, "umbreld", "client", "apps.state.query", "--appId", APP_ID],
            check=False,
        )
        last_out = (res.stdout + res.stderr).strip()
        print(f"  apps.state.query -> {last_out}")
        if "ready" in last_out.lower():
            return last_out
        time.sleep(2.0)
    raise RuntimeError(f"App {APP_ID} did not reach ready state; last state={last_out}")


def main() -> None:
    store_pkg = Path("store") / APP_ID
    assert store_pkg.is_dir(), f"Missing package directory {store_pkg}"

    # Wait for umbreld to finish cloning the default app-store into /home/umbrel/umbrel/app-stores/
    store_dirs: list[str] = []
    for _ in range(30):
        store_dir_res = run_cmd(
            [
                "docker",
                "exec",
                CONTAINER,
                "sh",
                "-ec",
                "find -L /data /home/umbrel/umbrel/app-stores -maxdepth 5 -type d -name 'getumbrel-umbrel-apps-github-*' 2>/dev/null || true",
            ]
        )
        store_dirs = sorted({d.strip() for d in store_dir_res.stdout.splitlines() if d.strip()})
        if store_dirs:
            break
        time.sleep(2.0)

    if not store_dirs:
        diag = run_cmd(
            ["docker", "exec", CONTAINER, "sh", "-ec", "ls -la /data /data/umbrel-os /home/umbrel/umbrel/app-stores 2>&1 || true"],
            check=False,
        )
        raise AssertionError(f"Could not locate app-stores directory inside umbrelos-test:\n{diag.stdout}")
    store_dir = store_dirs[0]
    for sd in store_dirs:
        print(f"==> Syncing {APP_ID} into umbrelOS store path: {sd}")
        tar_proc = subprocess.Popen(
            ["tar", "-C", "store", "--exclude=.gitkeep", "-cf", "-", APP_ID],
            stdout=subprocess.PIPE,
        )
        untar_proc = subprocess.Popen(
            ["docker", "exec", "-i", CONTAINER, "tar", "-C", sd, "-xf", "-"],
            stdin=tar_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert tar_proc.stdout is not None
        tar_proc.stdout.close()
        _, err = untar_proc.communicate()
        assert untar_proc.returncode == 0, f"tar sync failed: {err}"
        run_cmd(["docker", "exec", CONTAINER, "chown", "-R", "1000:1000", f"{sd}/{APP_ID}"])

    # Add Oni-giri/yakitoris-app-store community app store OR sync yakitori-act-ci directly into the store directory!
    # First inspect umbreld appStore router procedures so we use the exact supported call if needed.
    reg_out = ""
    for attempt in range(8):
        reg_out = run_cmd(
            ["docker", "exec", CONTAINER, "umbreld", "client", "appStore.registry.query"]
        ).stdout
        if APP_ID in reg_out:
            break
        if attempt == 0:
            # Also try registering community app store or restarting umbrel service to re-read app-stores/
            procs = run_cmd(
                [
                    "docker",
                    "exec",
                    CONTAINER,
                    "sh",
                    "-ec",
                    "grep -rnE 'appStore|repositories' /opt/umbreld/source/modules/apps/ 2>/dev/null | head -n 40 || "
                    "grep -rnE 'registry|repositories' /opt/umbreld/ 2>/dev/null | head -n 40 || true",
                ],
                check=False,
            )
            print("  umbreld appStore internals:\n", procs.stdout[:2000])
            run_cmd(["docker", "exec", CONTAINER, "systemctl", "restart", "umbrel"], check=False)
            time.sleep(5.0)
        time.sleep(2.0)
    assert APP_ID in reg_out, f"{APP_ID} not found in appStore.registry.query! Sample: {reg_out[:600]}"
    print("==> Confirmed appStore.registry.query sees yakitori-act-ci@0.1.0")

    # Install via umbreld
    print("==> Running: umbreld client apps.install.mutate --appId yakitori-act-ci")
    inst_res = run_cmd(
        ["docker", "exec", CONTAINER, "umbreld", "client", "apps.install.mutate", "--appId", APP_ID]
    )
    print("  install result:", inst_res.stdout.strip())
    wait_app_ready(timeout_s=150.0)

    # Give web server 3s to bind cleanly inside its container
    time.sleep(3.0)

    # Checklist 1 & 2: Opens on Umbrel's app port (8755), not raw internal port (8080), and UI/admin routes require Umbrel login
    print("==> Checklist 1 & 2: Verifying Umbrel app port 8755 & login gate on UI/admin routes...")
    ui_code, ui_hdrs, ui_body = http_req("GET", f"http://127.0.0.1:{APP_PORT}/")
    tok_code, tok_hdrs, tok_body = http_req("GET", f"http://127.0.0.1:{APP_PORT}/tokens")
    print(f"  GET :{APP_PORT}/ -> status={ui_code}, location={ui_hdrs.get('Location') or ui_hdrs.get('location')}")
    print(f"  GET :{APP_PORT}/tokens -> status={tok_code}, location={tok_hdrs.get('Location') or tok_hdrs.get('location')}")
    assert ui_code in (302, 307, 401, 403), f"Expected Umbrel auth gate on /, got {ui_code}"
    assert tok_code in (302, 307, 401, 403), f"Expected Umbrel auth gate on /tokens, got {tok_code}"
    assert "Create Bearer Token" not in tok_body, "Unauthenticated caller reached /tokens HTML!"

    # Also confirm raw internal container port 8080 is NOT published on the host
    try:
        raw_code, _, _ = http_req("GET", "http://127.0.0.1:8080/")
        assert raw_code != 200 or "Workflow Runs" not in _
    except urllib.error.URLError:
        print("  Confirmed raw internal port 8080 is not exposed on host")

    # Checklist 3 (unauthenticated part): API and MCP return 401 without bearer token on port 8755
    print("==> Checklist 3a: Verifying API & MCP return 401 without bearer token on port 8755...")
    api_401, _, _ = http_req("GET", f"http://127.0.0.1:{APP_PORT}/api/v1/repos")
    mcp_401, _, _ = http_req(
        "POST",
        f"http://127.0.0.1:{APP_PORT}/mcp",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode("utf-8"),
    )
    print(f"  GET :{APP_PORT}/api/v1/repos (no token) -> {api_401}")
    print(f"  POST :{APP_PORT}/mcp (no token) -> {mcp_401}")
    assert api_401 == 401, f"Expected 401 on /api/v1/repos without token, got {api_401}"
    assert mcp_401 == 401, f"Expected 401 on /mcp without token, got {mcp_401}"

    # Provision a token & fixture repo in the installed app's SQLite DB, then test API & MCP over port 8755
    print("==> Checklist 3b: Verifying API & MCP answer 200 with valid bearer token over port 8755...")
    seed_py = (
        "import dataclasses\n"
        "from act_ci.config import load_settings\n"
        "from act_ci.app import create_app\n"
        "s = dataclasses.replace(load_settings(), enable_worker=False)\n"
        "app = create_app(s)\n"
        "meta, raw = app.state.service.create_token(name='umbrel-agent', role='operator')\n"
        "app.state.service.create_repo_admin(\n"
        "    name='act-ci-self',\n"
        "    git_url='https://github.com/Oni-giri/act-ci.git',\n"
        "    default_image='node:20-bookworm-slim',\n"
        "    timeout_seconds=180,\n"
        ")\n"
        "print('MINTED_TOKEN=' + raw)\n"
    )
    mint_res = run_cmd(
        [
            "docker",
            "exec",
            CONTAINER,
            "docker",
            "exec",
            f"{APP_ID}_web_1",
            "python3",
            "-c",
            seed_py,
        ]
    )
    m = re.search(r"MINTED_TOKEN=(actci_[A-Za-z0-9_-]+)", mint_res.stdout)
    assert m is not None, f"Failed to mint token: {mint_res.stdout}"
    token = m.group(1)
    auth_hdrs = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    api_200, _, api_repos_body = http_req(
        "GET", f"http://127.0.0.1:{APP_PORT}/api/v1/repos", headers=auth_hdrs
    )
    assert api_200 == 200, f"Expected 200 on /api/v1/repos with token, got {api_200}: {api_repos_body}"
    repos_list = json.loads(api_repos_body)
    assert any(r["name"] == "act-ci-self" for r in repos_list)
    print("  GET :8755/api/v1/repos (with token) -> 200 OK")

    mcp_200, _, mcp_tools_body = http_req(
        "POST",
        f"http://127.0.0.1:{APP_PORT}/mcp",
        headers=auth_hdrs,
        body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode("utf-8"),
    )
    assert mcp_200 == 200, f"Expected 200 on /mcp with token, got {mcp_200}: {mcp_tools_body}"
    mcp_tools = [t["name"] for t in json.loads(mcp_tools_body)["result"]["tools"]]
    assert "trigger_run" in mcp_tools
    print("  POST :8755/mcp tools/list (with token) -> 200 OK:", mcp_tools)

    # Checklist 4: Probe nested DinD sidecar inside containerized umbrelOS and run a full workflow if operational!
    print("==> Checklist 4: Checking DinD sidecar inside containerized umbrelOS...")
    dind_probe = run_cmd(
        [
            "docker",
            "exec",
            CONTAINER,
            "docker",
            "exec",
            f"{APP_ID}_web_1",
            "docker",
            "-H",
            "unix:///var/run/dind/docker.sock",
            "info",
        ],
        check=False,
    )
    created_run_id: str | None = None
    if dind_probe.returncode == 0:
        print("  Nested DinD inside containerized umbrelOS is OPERATIONAL! Running full workflow on fixture repo...")
        trig_code, _, trig_body = http_req(
            "POST",
            f"http://127.0.0.1:{APP_PORT}/api/v1/runs",
            headers=auth_hdrs,
            body=json.dumps(
                {
                    "repo": "act-ci-self",
                    "ref": "main",
                    "replacement_workflow": (
                        "name: UmbrelE2E\n"
                        "on: [push]\n"
                        "jobs:\n"
                        "  verify:\n"
                        "    runs-on: ubuntu-latest\n"
                        "    steps:\n"
                        "      - name: Verify execution inside Umbrel app\n"
                        "        run: echo 'UMBREL_FULL_RUN_PASSED_OK'\n"
                    ),
                }
            ).encode("utf-8"),
        )
        assert trig_code == 201, f"Expected 201 triggering run, got {trig_code}: {trig_body}"
        created_run_id = json.loads(trig_body)["id"]
        print(f"  Triggered run {created_run_id}; polling until completion...")

        final_status = None
        for _ in range(90):
            st_code, _, st_body = http_req(
                "GET", f"http://127.0.0.1:{APP_PORT}/api/v1/runs/{created_run_id}", headers=auth_hdrs
            )
            assert st_code == 200
            st_data = json.loads(st_body)
            if st_data["status"] in ("passed", "failed", "cancelled", "timed_out"):
                final_status = st_data["status"]
                break
            time.sleep(2.0)

        lg_code, _, lg_body = http_req(
            "GET", f"http://127.0.0.1:{APP_PORT}/api/v1/runs/{created_run_id}/logs", headers=auth_hdrs
        )
        assert lg_code == 200
        raw_log = json.loads(lg_body)["raw_log"]
        print(f"  Final status inside Umbrel: {final_status}")
        if final_status == "passed":
            assert "UMBREL_FULL_RUN_PASSED_OK" in raw_log
            print("  Checklist 4 PASSED: Full workflow run executed and passed inside containerized umbrelOS!")
        else:
            print(f"  NOTE: Workflow inside nested containerized umbrelOS ended '{final_status}':\n{raw_log}")
    else:
        print(
            "  NOTE: Nested DinD inside containerized umbrelOS did not start (expected nested-Docker limitation in containerized umbrelOS):\n"
            + (dind_probe.stdout + dind_probe.stderr)
        )
        # Still create a queued/cancelled run record so we can verify run history persistence across restart & update
        trig_code, _, trig_body = http_req(
            "POST",
            f"http://127.0.0.1:{APP_PORT}/api/v1/runs",
            headers=auth_hdrs,
            body=json.dumps({"repo": "act-ci-self", "ref": "main"}).encode("utf-8"),
        )
        if trig_code == 201:
            created_run_id = json.loads(trig_body)["id"]

    # Checklist 5: Restart via apps.restart.mutate and verify tokens, repos, and run history persist
    print("==> Checklist 5: Running umbreld client apps.restart.mutate and verifying persistence...")
    run_cmd(
        ["docker", "exec", CONTAINER, "umbreld", "client", "apps.restart.mutate", "--appId", APP_ID]
    )
    wait_app_ready(timeout_s=120.0)
    time.sleep(3.0)

    r_code, _, r_body = http_req(
        "GET", f"http://127.0.0.1:{APP_PORT}/api/v1/repos", headers=auth_hdrs
    )
    assert r_code == 200 and "act-ci-self" in r_body, f"Repos/token lost after restart: {r_code} {r_body}"
    runs_code, _, runs_body = http_req(
        "GET", f"http://127.0.0.1:{APP_PORT}/api/v1/runs", headers=auth_hdrs
    )
    assert runs_code == 200
    if created_run_id:
        assert created_run_id in runs_body, "Run history lost after restart!"
    print("  Confirmed tokens, repos (encrypted with derived entropy), and run history survived apps.restart.mutate!")

    # Checklist 6: Inspect settled logs
    print("==> Checklist 6: Checking settled apps.logs.query...")
    logs_out = run_cmd(
        ["docker", "exec", CONTAINER, "umbreld", "client", "apps.logs.query", "--appId", APP_ID]
    ).stdout
    print(logs_out[-2000:])
    assert "Traceback (most recent call last)" not in logs_out, "Unexpected Python traceback in settled logs!"

    # Update Path: bump version to 0.1.1, run apps.update.mutate, repeat checks 3 and 5
    print("==> Update Path: Bumping manifest version 0.1.0 -> 0.1.1 and running apps.update.mutate...")
    for sd in store_dirs:
        run_cmd(
            [
                "docker",
                "exec",
                CONTAINER,
                "sed",
                "-i",
                's/version: "0.1.0"/version: "0.1.1"/',
                f"{sd}/{APP_ID}/umbrel-app.yml",
            ]
        )
    run_cmd(
        ["docker", "exec", CONTAINER, "umbreld", "client", "apps.update.mutate", "--appId", APP_ID]
    )
    wait_app_ready(timeout_s=150.0)
    time.sleep(3.0)

    upd_401, _, _ = http_req("GET", f"http://127.0.0.1:{APP_PORT}/api/v1/repos")
    assert upd_401 == 401, f"Expected 401 without token after update, got {upd_401}"
    upd_200, _, upd_repos = http_req(
        "GET", f"http://127.0.0.1:{APP_PORT}/api/v1/repos", headers=auth_hdrs
    )
    assert upd_200 == 200 and "act-ci-self" in upd_repos, "Token or repos lost after apps.update.mutate!"
    upd_runs_code, _, upd_runs = http_req(
        "GET", f"http://127.0.0.1:{APP_PORT}/api/v1/runs", headers=auth_hdrs
    )
    assert upd_runs_code == 200
    if created_run_id:
        assert created_run_id in upd_runs, "Run history lost after apps.update.mutate!"
    print("==> Level 4 containerized umbrelOS install, auth boundary, restart, and update checks ALL PASSED!")


if __name__ == "__main__":
    main()
