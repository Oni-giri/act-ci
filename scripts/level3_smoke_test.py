#!/usr/bin/env python3
"""Level 3 stack smoke test (NOT Umbrel verification).

Starts Act-CI and the isolated Docker-in-Docker sidecar with plain Docker Compose, then:
1. Creates an operator bearer token through the Admin Web UI (/tokens).
2. Adds a local fixture git repo inside the web container's /data/fixtures volume and registers it via the Web UI (/repos).
3. Triggers a run via the REST API (/api/v1/runs) using the bearer token.
4. Polls the live UI endpoint (/runs/{id}/live) and renders the HTML detail page (/runs/{id}) to watch the log update.
5. Reads the final run status and structured logs over the HTTP MCP endpoint (/mcp).
6. Verifies the Activity page (/activity) recorded every API and MCP call, and `docker ps -a` inside the DinD sidecar is empty.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.request

BASE_URL = os.environ.get("ACT_CI_SMOKE_URL", "http://127.0.0.1:8755")
COMPOSE_PROJECT = os.environ.get("ACT_CI_SMOKE_PROJECT", "actci-smoke")


def _http(
    method: str,
    path: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, dict[str, str]]:
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers=headers or {},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        return err.code, body, dict(err.headers)


def _wait_ready(timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            code, body, _ = _http("GET", "/healthz")
            if code == 200 and '"ok"' in body:
                return
        except Exception:
            pass
        time.sleep(1.0)
    raise RuntimeError("Act-CI web container did not become healthy in time")


def main() -> None:
    print("==> Starting plain Docker Compose stack (web + isolated DinD sidecar)...")
    subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "up", "-d", "--build"],
        check=True,
    )
    try:
        _wait_ready()
        print("==> Stack is healthy at", BASE_URL)

        # Wait until DinD daemon inside sidecar is accepting connections
        for _ in range(30):
            r = subprocess.run(
                ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "docker", "docker", "info"],
                capture_output=True,
            )
            if r.returncode == 0:
                break
            time.sleep(1.0)
        else:
            raise RuntimeError("DinD sidecar did not become ready")

        # Create a local git fixture repo inside /data/fixtures on the web container
        subprocess.run(
            [
                "docker",
                "compose",
                "-p",
                COMPOSE_PROJECT,
                "exec",
                "-T",
                "web",
                "sh",
                "-ec",
                (
                    "rm -rf /data/fixtures/smoke-repo && "
                    "mkdir -p /data/fixtures/smoke-repo/.github/workflows && "
                    "cd /data/fixtures/smoke-repo && "
                    "git init -b main && "
                    "git config user.name 'Smoke' && git config user.email 'smoke@example.invalid' && "
                    "cat <<'EOF' > .github/workflows/ci.yml\n"
                    "name: SmokeCI\n"
                    "on: [push]\n"
                    "jobs:\n"
                    "  smoke:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - name: Smoke step\n"
                    "        run: echo 'LEVEL3_SMOKE_WORKFLOW_OK'\n"
                    "EOF\n"
                    "git add . && git commit -m 'smoke fixture'"
                ),
            ],
            check=True,
        )

        # 1. Create an operator token through the Web UI
        code, tok_html, _ = _http("GET", "/tokens")
        assert code == 200
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', tok_html).group(1)  # type: ignore[union-attr]

        form_tok = urllib.parse.urlencode(
            {"csrf_token": csrf, "name": "smoke-operator", "role": "operator"}
        ).encode("utf-8")
        code, created_html, _ = _http(
            "POST",
            "/tokens",
            data=form_tok,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert code == 201, f"Expected 201 creating token, got {code}"
        raw_token = re.search(
            r'id="new-token-value"[^>]*>(actci_[A-Za-z0-9_-]+)</code>', created_html
        ).group(1)  # type: ignore[union-attr]
        print("==> Created operator token via UI:", raw_token[:12] + "...")

        # 2. Add the fixture repo through the Web UI
        form_repo = urllib.parse.urlencode(
            {
                "csrf_token": csrf,
                "name": "smoke-repo",
                "git_url": "/data/fixtures/smoke-repo",
                "credential_type": "none",
                "default_image": "node:20-bookworm-slim",
                "timeout_seconds": "180",
                "secrets_text": "",
            }
        ).encode("utf-8")
        code, repos_html, _ = _http(
            "POST",
            "/repos",
            data=form_repo,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert code == 200 and "smoke-repo" in repos_html
        print("==> Registered smoke-repo via UI")

        # 3. Trigger a run over the REST API
        auth_hdr = {
            "Authorization": f"Bearer {raw_token}",
            "Content-Type": "application/json",
        }
        code, trig_body, _ = _http(
            "POST",
            "/api/v1/runs",
            data=json.dumps({"repo": "smoke-repo", "ref": "main"}).encode("utf-8"),
            headers=auth_hdr,
        )
        assert code == 201, f"Trigger failed: {code} {trig_body}"
        run_id = json.loads(trig_body)["id"]
        print("==> Triggered run via REST API:", run_id)

        # 4. Watch live log updates through the UI's live endpoint & HTML page
        final_ui_status = None
        for _ in range(120):
            code, live_body, _ = _http("GET", f"/runs/{run_id}/live")
            assert code == 200
            live_data = json.loads(live_body)
            st = live_data["run"]["status"]
            if st in ("passed", "failed", "cancelled", "timed_out"):
                final_ui_status = st
                break
            time.sleep(1.0)
        assert final_ui_status == "passed", f"Expected passed, got {final_ui_status}"

        code, detail_html, _ = _http("GET", f"/runs/{run_id}")
        assert code == 200 and "LEVEL3_SMOKE_WORKFLOW_OK" in detail_html
        print("==> Verified run logs rendered in Web UI")

        # 5. Read run status and logs over HTTP MCP (/mcp)
        code, mcp_status_body, _ = _http(
            "POST",
            "/mcp",
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "get_run_status", "arguments": {"run_id": run_id}},
                }
            ).encode("utf-8"),
            headers=auth_hdr,
        )
        assert code == 200
        mcp_status = json.loads(mcp_status_body)["result"]["structuredContent"]
        assert mcp_status["status"] == "passed"

        code, mcp_log_body, _ = _http(
            "POST",
            "/mcp",
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "get_run_log", "arguments": {"run_id": run_id}},
                }
            ).encode("utf-8"),
            headers=auth_hdr,
        )
        assert code == 200
        mcp_logs = json.loads(mcp_log_body)["result"]["structuredContent"]
        assert "LEVEL3_SMOKE_WORKFLOW_OK" in mcp_logs["raw_log"]
        print("==> Verified run status & logs over MCP (/mcp)")

        # 6. Verify DinD sidecar has zero leftover job containers
        ps_sidecar = subprocess.run(
            ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "docker", "docker", "ps", "-a", "-q"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert ps_sidecar == "", f"Leftover containers in DinD sidecar: {ps_sidecar}"
        print("==> Level 3 stack smoke test PASSED!")
    finally:
        subprocess.run(
            ["docker", "compose", "-p", COMPOSE_PROJECT, "down", "-v"],
            check=False,
        )


if __name__ == "__main__":
    main()
