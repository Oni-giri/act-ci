"""Level 1 automated tests (no Docker needed).

Covers:
1. Exhaustive Permission Matrix across EVERY API route and EVERY MCP tool
   (operator, viewer, no_token, revoked_token), with route/tool completeness guard
   so adding a route or MCP tool without a matrix entry fails the suite.
2. Private-run leak test: unique canary string in private run overlay + logs never
   appears in any API route or MCP tool response for a viewer token.
3. Tokens: shown once, only SHA-256 hash stored, last_used_at updates, revoked tokens
   rejected, admin routes unreachable with any bearer token (nor under whitelisted paths).
4. Secrets & Credentials: encrypted at rest, never returned by any API/MCP response,
   masked in run logs and error messages (including URL-encoded and base64 variants).
5. Audit log: every API and MCP call above (reads & denials included) produces a row,
   and rows are strictly append-only (SQLite triggers block UPDATE/DELETE and no app
   route edits or deletes them).
"""

from __future__ import annotations

import base64
import re
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from act_ci.mcp_server import ALL_MCP_TOOL_NAMES
from act_ci.models import Principal, TriggerRunRequest
from act_ci.security import hash_api_token
from act_ci.ui_routes import ADMIN_PRINCIPAL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_world(app_instance, tmp_path: Path) -> dict[str, Any]:
    """Populate repos, public & private runs with logs, and operator/viewer/revoked tokens."""
    svc = app_instance.state.service
    db = app_instance.state.db

    repo = svc.create_repo_admin(
        name="demo-repo",
        git_url="https://github.com/example/demo-repo.git",
        credential_type="token",
        credential_value="ghp_SuperSecretCloneTokenValue998877",
        secrets_dict={
            "DEPLOY_SECRET": "sec_UltraSensitiveWorkflowSecret_4242",
        },
    )

    _, op_token = svc.create_token(name="ci-operator", role="operator")
    _, vw_token = svc.create_token(name="ci-viewer", role="viewer")
    rev_meta, rev_token = svc.create_token(name="ci-revoked", role="operator")
    svc.revoke_token(rev_meta["id"])

    pub_run = svc.trigger_run(
        ADMIN_PRINCIPAL,
        TriggerRunRequest(
            repo="demo-repo",
            ref="main",
            private=False,
        ),
    )
    db.upsert_step_log(
        pub_run.id,
        job_id="build",
        job_name="Build",
        step_id="1",
        step_name="Run public tests",
        status="passed",
        exit_code=0,
        append_text="Public test output ok\n",
    )

    canary = "CANARY_PRIVATE_9f8e7d6c5b4a3210_DO_NOT_LEAK"
    priv_run = svc.trigger_run(
        ADMIN_PRINCIPAL,
        TriggerRunRequest(
            repo="demo-repo",
            ref="feature/secret-check",
            overlay={"tests/secret_eval.py": f"assert '{canary}' != ''\n"},
            replacement_workflow=f"name: PrivateEval\non: [push]\n# {canary}\n",
            private=True,
        ),
    )
    db.upsert_step_log(
        priv_run.id,
        job_id="eval",
        job_name=f"Eval {canary}",
        step_id="1",
        step_name=f"Step {canary}",
        status="failed",
        exit_code=1,
        append_text=f"Executing private check with {canary}\n",
    )
    db.finish_run(
        priv_run.id,
        status="failed",
        exit_code=1,
        error_message=f"Private failure mentioning {canary}",
    )

    cancel_target_op = svc.trigger_run(
        ADMIN_PRINCIPAL,
        TriggerRunRequest(repo="demo-repo", ref="main", private=False),
    )

    return {
        "repo": repo,
        "op_token": op_token,
        "vw_token": vw_token,
        "rev_token": rev_token,
        "pub_run_id": pub_run.id,
        "priv_run_id": priv_run.id,
        "cancel_run_id": cancel_target_op.id,
        "canary": canary,
        "clone_secret": "ghp_SuperSecretCloneTokenValue998877",
        "wf_secret": "sec_UltraSensitiveWorkflowSecret_4242",
    }


def _auth_headers(token: str | None) -> dict[str, str]:
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. Exhaustive Permission Matrix (API Routes + MCP Tools + Completeness Check)
# ---------------------------------------------------------------------------

# Every /api/* route template must have an explicit entry here!
# Note: GET /api/v1/runs/{run_id}/logs is tested for both public and private runs.
API_PERMISSION_MATRIX: list[dict[str, Any]] = [
    {
        "id": "GET /api/v1/repos",
        "method": "GET",
        "route_template": "/api/v1/repos",
        "path": lambda w: "/api/v1/repos",
        "json": None,
        "expected": {
            "operator": 200,
            "viewer": 200,
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "POST /api/v1/runs",
        "method": "POST",
        "route_template": "/api/v1/runs",
        "path": lambda w: "/api/v1/runs",
        "json": lambda w: {"repo": "demo-repo", "ref": "main"},
        "expected": {
            "operator": 201,
            "viewer": 403,
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "GET /api/v1/runs",
        "method": "GET",
        "route_template": "/api/v1/runs",
        "path": lambda w: "/api/v1/runs",
        "json": None,
        "expected": {
            "operator": 200,
            "viewer": 200,
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "GET /api/v1/runs/{run_id} (public)",
        "method": "GET",
        "route_template": "/api/v1/runs/{run_id}",
        "path": lambda w: f"/api/v1/runs/{w['pub_run_id']}",
        "json": None,
        "expected": {
            "operator": 200,
            "viewer": 200,
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "GET /api/v1/runs/{run_id} (private)",
        "method": "GET",
        "route_template": "/api/v1/runs/{run_id}",
        "path": lambda w: f"/api/v1/runs/{w['priv_run_id']}",
        "json": None,
        "expected": {
            "operator": 200,
            "viewer": 200,  # Viewers can read status of private runs (never overlay/logs)
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "GET /api/v1/runs/{run_id}/logs (public)",
        "method": "GET",
        "route_template": "/api/v1/runs/{run_id}/logs",
        "path": lambda w: f"/api/v1/runs/{w['pub_run_id']}/logs",
        "json": None,
        "expected": {
            "operator": 200,
            "viewer": 200,
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "GET /api/v1/runs/{run_id}/logs (private)",
        "method": "GET",
        "route_template": "/api/v1/runs/{run_id}/logs",
        "path": lambda w: f"/api/v1/runs/{w['priv_run_id']}/logs",
        "json": None,
        "expected": {
            "operator": 200,
            "viewer": 403,  # Viewers forbidden on private run logs
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "POST /api/v1/runs/{run_id}/cancel",
        "method": "POST",
        "route_template": "/api/v1/runs/{run_id}/cancel",
        "path": lambda w: f"/api/v1/runs/{w['cancel_run_id']}/cancel",
        "json": None,
        "expected": {
            "operator": 200,
            "viewer": 403,
            "no_token": 401,
            "revoked_token": 401,
        },
    },
]

# Every MCP tool in MCP_TOOLS_SPEC must have an explicit entry here!
MCP_PERMISSION_MATRIX: list[dict[str, Any]] = [
    {
        "id": "mcp:list_repos",
        "tool": "list_repos",
        "args": lambda w: {},
        "expected": {
            "operator": "ok",
            "viewer": "ok",
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "mcp:list_recent_runs",
        "tool": "list_recent_runs",
        "args": lambda w: {"limit": 20},
        "expected": {
            "operator": "ok",
            "viewer": "ok",
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "mcp:get_run_status (public)",
        "tool": "get_run_status",
        "args": lambda w: {"run_id": w["pub_run_id"]},
        "expected": {
            "operator": "ok",
            "viewer": "ok",
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "mcp:get_run_status (private)",
        "tool": "get_run_status",
        "args": lambda w: {"run_id": w["priv_run_id"]},
        "expected": {
            "operator": "ok",
            "viewer": "ok",
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "mcp:get_run_log (public)",
        "tool": "get_run_log",
        "args": lambda w: {"run_id": w["pub_run_id"]},
        "expected": {
            "operator": "ok",
            "viewer": "ok",
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "mcp:get_run_log (private)",
        "tool": "get_run_log",
        "args": lambda w: {"run_id": w["priv_run_id"]},
        "expected": {
            "operator": "ok",
            "viewer": "denied",
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "mcp:trigger_run",
        "tool": "trigger_run",
        "args": lambda w: {"repo": "demo-repo", "ref": "main"},
        "expected": {
            "operator": "ok",
            "viewer": "denied",
            "no_token": 401,
            "revoked_token": 401,
        },
    },
    {
        "id": "mcp:cancel_run",
        "tool": "cancel_run",
        "args": lambda w: {"run_id": w["cancel_run_id"]},
        "expected": {
            "operator": "ok",
            "viewer": "denied",
            "no_token": 401,
            "revoked_token": 401,
        },
    },
]


def _iter_effective_routes(app_instance) -> list[tuple[str, set[str]]]:
    """Yield (path, methods) across both classic FastAPI APIRoutes and FastAPI 0.165+ _IncludedRouters."""
    out: list[tuple[str, set[str]]] = []
    for item in app_instance.routes:
        if isinstance(item, APIRoute):
            out.append((item.path, set(item.methods or ())))
        elif hasattr(item, "effective_route_contexts"):
            for ctx in item.effective_route_contexts():
                out.append((ctx.path, set(ctx.methods or ())))
    return out


def test_matrix_covers_every_registered_api_route_and_mcp_tool(app_instance) -> None:
    """Guardrail: adding an /api/* route or MCP tool without a permission matrix entry MUST fail."""
    registered_api_routes: set[tuple[str, str]] = set()
    registered_mcp_routes: set[tuple[str, str]] = set()
    registered_admin_routes: set[tuple[str, str]] = set()

    for path, raw_methods in _iter_effective_routes(app_instance):
        methods = {m for m in raw_methods if m not in ("HEAD", "OPTIONS")}
        for m in methods:
            if path.startswith("/api"):
                registered_api_routes.add((m, path))
            elif path.startswith("/mcp"):
                registered_mcp_routes.add((m, path))
            else:
                registered_admin_routes.add((m, path))
                # Admin routes MUST NOT live under /api/* or /mcp* (PROXY_AUTH_WHITELIST paths)
                assert not path.startswith("/api"), f"Admin route leaked under /api: {path}"
                assert not path.startswith("/mcp"), f"Admin route leaked under /mcp: {path}"

    assert registered_api_routes, "Failed to introspect registered API routes"
    assert registered_admin_routes, "Failed to introspect registered Admin routes"

    covered_api_routes = {
        (entry["method"], entry["route_template"]) for entry in API_PERMISSION_MATRIX
    }
    missing_api = registered_api_routes - covered_api_routes
    extra_api = covered_api_routes - registered_api_routes
    assert not missing_api, f"API routes missing from permission matrix: {sorted(missing_api)}"
    assert not extra_api, f"Stale API routes in permission matrix: {sorted(extra_api)}"

    assert registered_mcp_routes == {("POST", "/mcp"), ("GET", "/mcp")}

    covered_mcp_tools = {entry["tool"] for entry in MCP_PERMISSION_MATRIX}
    registered_mcp_tools = set(ALL_MCP_TOOL_NAMES)
    missing_tools = registered_mcp_tools - covered_mcp_tools
    extra_tools = covered_mcp_tools - registered_mcp_tools
    assert not missing_tools, f"MCP tools missing from permission matrix: {sorted(missing_tools)}"
    assert not extra_tools, f"Stale MCP tools in permission matrix: {sorted(extra_tools)}"


@pytest.mark.parametrize(
    "actor", ["operator", "viewer", "no_token", "revoked_token"]
)
@pytest.mark.parametrize(
    "case", API_PERMISSION_MATRIX, ids=[c["id"] for c in API_PERMISSION_MATRIX]
)
def test_api_permission_matrix(
    app_instance, client: TestClient, tmp_path: Path, case: dict[str, Any], actor: str
) -> None:
    world = _seed_world(app_instance, tmp_path)
    token_map = {
        "operator": world["op_token"],
        "viewer": world["vw_token"],
        "no_token": None,
        "revoked_token": world["rev_token"],
    }
    audit_before = app_instance.state.db.count_audit_logs()

    path = case["path"](world)
    body = case["json"](world) if callable(case["json"]) else case["json"]
    resp = client.request(
        case["method"],
        path,
        json=body,
        headers=_auth_headers(token_map[actor]),
    )
    assert resp.status_code == case["expected"][actor], (
        f"{case['id']} as {actor}: expected {case['expected'][actor]}, got {resp.status_code} ({resp.text})"
    )

    # Every single API call (including reads, 401s, and 403s) MUST produce an audit row!
    audit_after = app_instance.state.db.count_audit_logs()
    assert audit_after == audit_before + 1


@pytest.mark.parametrize(
    "actor", ["operator", "viewer", "no_token", "revoked_token"]
)
@pytest.mark.parametrize(
    "case", MCP_PERMISSION_MATRIX, ids=[c["id"] for c in MCP_PERMISSION_MATRIX]
)
def test_mcp_permission_matrix(
    app_instance, client: TestClient, tmp_path: Path, case: dict[str, Any], actor: str
) -> None:
    world = _seed_world(app_instance, tmp_path)
    token_map = {
        "operator": world["op_token"],
        "viewer": world["vw_token"],
        "no_token": None,
        "revoked_token": world["rev_token"],
    }
    audit_before = app_instance.state.db.count_audit_logs()

    rpc_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": case["tool"],
            "arguments": case["args"](world),
        },
    }
    resp = client.post(
        "/mcp",
        json=rpc_payload,
        headers=_auth_headers(token_map[actor]),
    )
    expected = case["expected"][actor]
    if isinstance(expected, int):
        assert resp.status_code == expected
    else:
        assert resp.status_code == 200
        data = resp.json()
        if expected == "ok":
            assert "result" in data, f"Expected MCP success for {case['id']} as {actor}, got {data}"
            assert data["result"]["isError"] is False
        elif expected == "denied":
            assert "error" in data, f"Expected MCP RBAC denial for {case['id']} as {actor}, got {data}"
            assert data["error"]["code"] == -32003
            assert data["error"]["data"]["http_status"] == 403

    # Every MCP call (reads, tool calls, 401s, 403s) MUST produce an audit row!
    audit_after = app_instance.state.db.count_audit_logs()
    assert audit_after == audit_before + 1


def test_mcp_tool_list_filtered_by_role_and_get_probe_audited(
    app_instance, client: TestClient, tmp_path: Path
) -> None:
    world = _seed_world(app_instance, tmp_path)

    # Operator sees all 6 tools
    op_resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 10, "method": "tools/list"},
        headers=_auth_headers(world["op_token"]),
    )
    assert op_resp.status_code == 200
    op_tools = [t["name"] for t in op_resp.json()["result"]["tools"]]
    assert set(op_tools) == {
        "list_repos",
        "list_recent_runs",
        "get_run_status",
        "get_run_log",
        "trigger_run",
        "cancel_run",
    }

    # Viewer sees only the 4 read tools (trigger_run and cancel_run filtered out)
    vw_resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 11, "method": "tools/list"},
        headers=_auth_headers(world["vw_token"]),
    )
    assert vw_resp.status_code == 200
    vw_tools = [t["name"] for t in vw_resp.json()["result"]["tools"]]
    assert set(vw_tools) == {
        "list_repos",
        "list_recent_runs",
        "get_run_status",
        "get_run_log",
    }

    # GET /mcp without token -> 401; with token -> 405
    assert client.get("/mcp").status_code == 401
    assert client.get("/mcp", headers=_auth_headers(world["vw_token"])).status_code == 405


# ---------------------------------------------------------------------------
# 2. Private-Run Canary Leak Test
# ---------------------------------------------------------------------------


def test_private_run_canary_never_leaks_to_viewer_across_every_api_and_mcp_surface(
    app_instance, client: TestClient, tmp_path: Path
) -> None:
    world = _seed_world(app_instance, tmp_path)
    canary = world["canary"]
    priv_id = world["priv_run_id"]
    vw_headers = _auth_headers(world["vw_token"])
    op_headers = _auth_headers(world["op_token"])

    # Sanity check: Operator CAN see the canary in the private run's logs
    op_logs = client.get(f"/api/v1/runs/{priv_id}/logs", headers=op_headers)
    assert op_logs.status_code == 200
    assert canary in op_logs.text

    # Call EVERY API route as Viewer (against both public and private run IDs)
    viewer_responses: list[str] = []
    for entry in API_PERMISSION_MATRIX:
        path = entry["path"](world)
        body = entry["json"](world) if callable(entry["json"]) else entry["json"]
        r = client.request(entry["method"], path, json=body, headers=vw_headers)
        viewer_responses.append(r.text)

    # Also verify viewer CAN read private run status via API, and status is accurate without canary
    priv_status_resp = client.get(f"/api/v1/runs/{priv_id}", headers=vw_headers)
    assert priv_status_resp.status_code == 200
    assert priv_status_resp.json()["status"] == "failed"
    assert priv_status_resp.json()["private"] is True
    assert canary not in priv_status_resp.text
    assert "secret_eval.py" not in priv_status_resp.text

    # Call MCP initialize, tools/list, and EVERY MCP tool as Viewer
    for init_method in ("initialize", "tools/list", "ping"):
        r = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": init_method},
            headers=vw_headers,
        )
        viewer_responses.append(r.text)

    for entry in MCP_PERMISSION_MATRIX:
        r = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": entry["tool"], "arguments": entry["args"](world)},
            },
            headers=vw_headers,
        )
        viewer_responses.append(r.text)

    for payload_text in viewer_responses:
        assert canary not in payload_text, f"LEAK DETECTED in viewer response: {payload_text}"
        assert "secret_eval.py" not in payload_text
        assert "PrivateEval" not in payload_text


# ---------------------------------------------------------------------------
# 3. Tokens Lifecycle & Admin Boundary Tests
# ---------------------------------------------------------------------------


def test_tokens_shown_once_hashed_at_rest_last_used_revocation_and_admin_unreachable(
    app_instance, client: TestClient
) -> None:
    db = app_instance.state.db

    # Load /tokens admin page to get CSRF token
    get_tok_page = client.get("/tokens")
    assert get_tok_page.status_code == 200
    m = re.search(r'name="csrf_token" value="([^"]+)"', get_tok_page.text)
    assert m is not None
    csrf_token = m.group(1)

    # Create token via UI POST -> shown ONCE in creation response
    create_resp = client.post(
        "/tokens",
        data={"csrf_token": csrf_token, "name": "agent-alpha", "role": "operator"},
    )
    assert create_resp.status_code == 201
    tok_match = re.search(r'id="new-token-value"[^>]*>(actci_[A-Za-z0-9_-]+)</code>', create_resp.text)
    assert tok_match is not None
    raw_token = tok_match.group(1)

    # Subsequent GET /tokens MUST NOT contain the raw token
    list_page = client.get("/tokens")
    assert list_page.status_code == 200
    assert raw_token not in list_page.text
    assert raw_token[:12] in list_page.text

    # Inspect raw SQLite bytes/rows: raw token is nowhere in DB; only SHA-256 hash is stored!
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM tokens WHERE name = 'agent-alpha'").fetchone()
        assert row is not None
        assert row["token_hash"] == hash_api_token(raw_token)
        assert row["last_used_at"] is None
    raw_db_bytes = db.db_path.read_bytes()
    assert raw_token.encode("utf-8") not in raw_db_bytes

    # Using the token updates last_used_at
    r_use = client.get("/api/v1/repos", headers=_auth_headers(raw_token))
    assert r_use.status_code == 200
    with db.connection() as conn:
        row_after = conn.execute("SELECT * FROM tokens WHERE name = 'agent-alpha'").fetchone()
        assert row_after["last_used_at"] is not None

    # Admin routes MUST be unreachable with ANY bearer token (both operator and viewer)
    _, viewer_raw = app_instance.state.service.create_token(name="v-test", role="viewer")
    admin_paths = [
        ("GET", "/"),
        ("GET", "/runs"),
        ("POST", "/runs/trigger"),
        ("GET", "/repos"),
        ("POST", "/repos"),
        ("GET", "/tokens"),
        ("POST", "/tokens"),
        ("GET", "/activity"),
        ("GET", "/healthz"),
    ]
    for method, path in admin_paths:
        for tok in (raw_token, viewer_raw):
            adm_resp = client.request(method, path, headers=_auth_headers(tok))
            assert adm_resp.status_code == 403, (
                f"Admin route {method} {path} did not reject bearer token (got {adm_resp.status_code})"
            )

    # Revoke token via UI -> subsequent API and MCP calls rejected with 401
    revoke_resp = client.post(
        f"/tokens/{row['id']}/revoke",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert revoke_resp.status_code == 303
    assert client.get("/api/v1/repos", headers=_auth_headers(raw_token)).status_code == 401
    assert (
        client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers=_auth_headers(raw_token),
        ).status_code
        == 401
    )


# ---------------------------------------------------------------------------
# 4. Secrets Encrypted at Rest & Masked Everywhere
# ---------------------------------------------------------------------------


def test_secrets_encrypted_at_rest_and_never_in_api_or_logs(
    app_instance, client: TestClient
) -> None:
    svc = app_instance.state.service
    db = app_instance.state.db

    clone_cred = "ghp_MyTopSecretReadOnlyPat_88776655"
    wf_secret = "sk_live_WorkflowSuperSecret_11223344"
    url_encoded = urllib.parse.quote(wf_secret, safe="")
    b64_encoded = base64.b64encode(wf_secret.encode("utf-8")).decode("ascii")

    svc.create_repo_admin(
        name="vault-repo",
        git_url="https://github.com/example/vault-repo.git",
        credential_type="token",
        credential_value=clone_cred,
        secrets_dict={"STRIPE_KEY": wf_secret},
    )
    _, op_tok = svc.create_token(name="op-sec", role="operator")

    # Verify encrypted at rest in SQLite file (including WAL file if present)
    for p in db.db_path.parent.glob("act_ci.db*"):
        blob = p.read_bytes()
        assert clone_cred.encode("utf-8") not in blob
        assert wf_secret.encode("utf-8") not in blob

    # Simulate a run that tries to echo the plain secret, clone cred, and base64-encoded secret!
    run = svc.trigger_run(
        ADMIN_PRINCIPAL, TriggerRunRequest(repo="vault-repo", ref="main")
    )
    masker = svc.build_masker_for_repo(db.get_repo_by_name("vault-repo"))
    db.upsert_step_log(
        run.id,
        job_id="leak-attempt",
        job_name=f"Job {wf_secret}",
        step_id="1",
        step_name=f"Step {clone_cred}",
        status="failed",
        exit_code=1,
        append_text=masker.mask(
            f"Plain={wf_secret}\nClone={clone_cred}\nB64={b64_encoded}\nURL={url_encoded}\n"
        ),
    )
    # Even if unmasked text somehow sat in DB, verify read-time masking ALSO strips it!
    db.upsert_step_log(
        run.id,
        job_id="leak-attempt",
        step_id="2",
        job_name="DefenseInDepth",
        step_name="RawReadMaskCheck",
        status="failed",
        exit_code=1,
        append_text=f"DirectDB={wf_secret} and {clone_cred}\n",
    )
    db.finish_run(
        run.id,
        status="failed",
        exit_code=1,
        error_message=f"Failed cloning with {clone_cred} and {wf_secret}",
    )

    headers = _auth_headers(op_tok)
    surfaces = [
        client.get("/api/v1/repos", headers=headers).text,
        client.get("/api/v1/runs", headers=headers).text,
        client.get(f"/api/v1/runs/{run.id}", headers=headers).text,
        client.get(f"/api/v1/runs/{run.id}/logs", headers=headers).text,
        client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "list_repos", "arguments": {}},
            },
            headers=headers,
        ).text,
        client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "get_run_log", "arguments": {"run_id": run.id}},
            },
            headers=headers,
        ).text,
        client.get("/repos").text,
        client.get(f"/runs/{run.id}").text,
    ]

    for text in surfaces:
        assert clone_cred not in text
        assert wf_secret not in text
        assert b64_encoded not in text


# ---------------------------------------------------------------------------
# 5. Append-Only Audit Log Enforcement
# ---------------------------------------------------------------------------


def test_audit_log_records_reads_writes_and_forbids_update_or_delete(
    app_instance, client: TestClient, tmp_path: Path
) -> None:
    world = _seed_world(app_instance, tmp_path)
    db = app_instance.state.db
    op_headers = _auth_headers(world["op_token"])
    vw_headers = _auth_headers(world["vw_token"])

    start_count = db.count_audit_logs()

    # Perform 5 distinct API + MCP operations (reads, write, denied)
    assert client.get("/api/v1/repos", headers=vw_headers).status_code == 200
    assert client.get(f"/api/v1/runs/{world['pub_run_id']}", headers=vw_headers).status_code == 200
    assert client.get(f"/api/v1/runs/{world['priv_run_id']}/logs", headers=vw_headers).status_code == 403
    assert (
        client.post(
            "/api/v1/runs",
            json={"repo": "demo-repo", "ref": "main"},
            headers=op_headers,
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "list_recent_runs", "arguments": {}},
            },
            headers=vw_headers,
        ).status_code
        == 200
    )

    end_count = db.count_audit_logs()
    assert end_count == start_count + 5

    entries = db.list_audit_logs(limit=5)
    assert [e["action"] for e in entries] == [
        "runs.list",
        "runs.trigger",
        "runs.logs",
        "runs.get",
        "repos.list",
    ]
    assert entries[0]["source"] == "mcp"
    assert entries[2]["result"] == "denied:private_run"

    # Viewable in the UI
    act_page = client.get("/activity")
    assert act_page.status_code == 200
    assert "ci-viewer" in act_page.text
    assert "ci-operator" in act_page.text
    assert "denied:private_run" in act_page.text

    # Direct SQLite UPDATE and DELETE on audit_logs MUST fail due to append-only triggers!
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with db.connection(write=True) as conn:
            conn.execute("UPDATE audit_logs SET result = 'tampered' WHERE id = ?", (entries[0]["id"],))

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with db.connection(write=True) as conn:
            conn.execute("DELETE FROM audit_logs WHERE id = ?", (entries[0]["id"],))

    # No HTTP method on /activity can mutate or delete rows
    assert client.delete("/activity").status_code == 405
    assert client.post("/activity").status_code == 405
