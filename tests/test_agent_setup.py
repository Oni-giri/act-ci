"""Tests for agent-driven repository setup: MCP/API registration, global Git credential, migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from act_ci.app import create_app
from act_ci.config import Settings
from act_ci.db import Database
from act_ci.models import ApiError, RegisterRepoRequest
from act_ci.ui_routes import ADMIN_PRINCIPAL


def _op_headers(svc) -> dict[str, str]:
    _, tok = svc.create_token(name="agent", role="operator")
    return {"Authorization": f"Bearer {tok}"}


# ---------------------------------------------------------------------------
# Global Git credential
# ---------------------------------------------------------------------------


def test_global_credential_is_encrypted_never_returned_and_kept_when_blank(
    app_instance, tmp_path: Path
) -> None:
    svc = app_instance.state.service
    db = app_instance.state.db

    assert svc.get_global_git_credential_status()["configured"] is False

    status = svc.set_global_git_credential_admin(
        credential_type="token", credential_value="github_pat_GLOBAL_SECRET_123456"
    )
    assert status["configured"] is True
    assert status["type"] == "token"
    assert "github_pat_GLOBAL_SECRET_123456" not in str(status)
    assert "github_pat" not in str(svc.get_global_git_credential_status())

    # The plaintext never lands on disk
    for p in db.db_path.parent.glob("act_ci.db*"):
        assert b"github_pat_GLOBAL_SECRET_123456" not in p.read_bytes()

    # Saving again with a blank value keeps the credential (and its type)
    svc.set_global_git_credential_admin(credential_type="token", credential_value="")
    assert svc.get_global_git_credential_status()["configured"] is True
    stored = db.get_global_git_credential()
    assert svc.secret_box.decrypt_str(stored["encrypted_git_credential"]) == (
        "github_pat_GLOBAL_SECRET_123456"
    )

    # Replacing works, and disconnecting clears it
    svc.set_global_git_credential_admin(
        credential_type="deploy_key", credential_value="-----BEGIN KEY-----\nabc\n-----END KEY-----"
    )
    assert svc.get_global_git_credential_status()["type"] == "deploy_key"
    svc.set_global_git_credential_admin(credential_type="none", credential_value="")
    assert svc.get_global_git_credential_status()["configured"] is False


def test_global_credential_requires_a_value_the_first_time(app_instance) -> None:
    svc = app_instance.state.service
    with pytest.raises(ApiError):
        svc.set_global_git_credential_admin(credential_type="token", credential_value="   ")


def test_repo_with_global_credential_uses_it(app_instance) -> None:
    svc = app_instance.state.service
    repo = svc.create_repo_admin(
        name="global-repo",
        git_url="https://github.com/example/global-repo.git",
    )
    assert repo["credential_type"] == "global"
    assert repo["encrypted_credential"] == ""

    view = svc.list_repos(ADMIN_PRINCIPAL)[0]
    assert view.has_credential is True
    assert view.credential_type == "global"


# ---------------------------------------------------------------------------
# Migration: pre-existing v1 databases gain the global credential + global repos
# ---------------------------------------------------------------------------


def test_migration_upgrades_v1_database_without_losing_repos(tmp_path: Path) -> None:
    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE repos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            git_url TEXT NOT NULL,
            credential_type TEXT NOT NULL DEFAULT 'none'
                CHECK (credential_type IN ('none', 'token', 'deploy_key')),
            encrypted_credential TEXT NOT NULL DEFAULT '',
            default_image TEXT NOT NULL,
            timeout_seconds INTEGER NOT NULL DEFAULT 1800 CHECK (timeout_seconds >= 1),
            encrypted_secrets TEXT NOT NULL DEFAULT '',
            secret_keys_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        INSERT INTO repos (name, git_url, credential_type, default_image, created_at, updated_at)
        VALUES ('legacy', 'https://github.com/example/legacy.git', 'token', 'node:20', 't', 't');
        """
    )
    conn.commit()
    conn.close()

    db = Database(db_path)
    rows = db.list_repos()
    assert [r["name"] for r in rows] == ["legacy"]
    assert rows[0]["credential_type"] == "token"

    # The widened CHECK now accepts 'global'
    with db.connection(write=True) as c:
        c.execute("UPDATE repos SET credential_type = 'global' WHERE name = 'legacy'")
    assert db.list_repos()[0]["credential_type"] == "global"
    assert db.get_global_git_credential()["git_credential_type"] == "none"


# ---------------------------------------------------------------------------
# Agent-driven repository registration
# ---------------------------------------------------------------------------


def test_register_repo_over_mcp_and_api_is_idempotent_and_audited(
    app_instance, client: TestClient, tmp_path: Path
) -> None:
    svc = app_instance.state.service
    db = app_instance.state.db
    headers = _op_headers(svc)

    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "register_repo",
            "arguments": {
                "name": "agent-repo",
                "git_url": "https://github.com/example/agent-repo.git",
            },
        },
    }
    resp = client.post("/mcp", json=rpc, headers=headers)
    assert resp.status_code == 200
    payload = resp.json()["result"]["structuredContent"]
    assert payload["name"] == "agent-repo"
    assert payload["credential_type"] == "global"
    # Metadata only: the credential *type* may be reported, its value never.
    assert "credential_value" not in payload
    assert payload["credential_type"] == "global"

    # Re-registering the same name + url is a no-op, not a duplicate row
    resp2 = client.post("/mcp", json=rpc, headers=headers)
    assert resp2.status_code == 200
    assert len(svc.db.list_repos()) == 1

    # Audited on both calls
    audits = [a for a in db.list_audit_logs(limit=20) if a["action"] == "repos.register"]
    assert len(audits) == 2
    assert all(a["source"] == "mcp" and a["result"] == "ok" for a in audits)
    assert audits[0]["repo_name"] == "agent-repo"

    # The run path can now trigger on it (repo exists; the run itself just queues here)
    api = client.post(
        "/api/v1/runs",
        json={"repo": "agent-repo", "ref": "main"},
        headers=headers,
    )
    assert api.status_code == 201


def test_register_repo_rejects_non_allowlisted_git_hosts(
    app_instance, client: TestClient
) -> None:
    svc = app_instance.state.service
    headers = _op_headers(svc)

    rpc = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "register_repo",
            "arguments": {
                "name": "evil",
                "git_url": "https://gist.evil.example/repo.git",
            },
        },
    }
    resp = client.post("/mcp", json=rpc, headers=headers)
    assert resp.status_code == 200
    assert "error" in resp.json()
    assert svc.db.list_repos() == []

    # An already-known repo must not be silently re-pointed at another URL
    svc.create_repo_admin(name="known", git_url="https://github.com/example/known.git")
    with pytest.raises(ApiError):
        svc.register_repo(
            ADMIN_PRINCIPAL,
            RegisterRepoRequest(
                name="known", git_url="https://github.com/attacker/known.git"
            ),
        )


def test_viewer_and_revoked_tokens_cannot_register_repos(
    app_instance, client: TestClient
) -> None:
    svc = app_instance.state.service
    _, viewer_tok = svc.create_token(name="viewer-x", role="viewer")
    meta, revoked_tok = svc.create_token(name="revoked-x", role="operator")
    svc.revoke_token(meta["id"])

    body = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "register_repo",
            "arguments": {"name": "nope", "git_url": "https://github.com/e/nope.git"},
        },
    }
    assert client.post("/mcp", json=body, headers={"Authorization": f"Bearer {viewer_tok}"}).json()["error"]["code"] == -32003
    assert client.post("/mcp", json=body, headers={"Authorization": f"Bearer {revoked_tok}"}).status_code == 401
    assert svc.db.list_repos() == []


def test_local_repos_still_respect_allow_local_repos_setting(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path / "d",
        host="127.0.0.1",
        port=8080,
        docker_host="unix:///nonexistent.sock",
        act_binary="act",
        git_binary="git",
        docker_binary="docker",
        master_key_env="test-master-key-0123456789abcdefghijklmn",
        csrf_secret_env="SI_SECRET_SECRET_TEST0001",
        allow_local_repos=False,
        prune_interval_seconds=0,
        prune_until="168h",
        enable_worker=False,
    )
    app = create_app(settings)
    svc = app.state.service
    with pytest.raises(ApiError):
        svc.register_repo(
            ADMIN_PRINCIPAL,
            RegisterRepoRequest(name="local", git_url="/tmp/some-repo"),
        )
