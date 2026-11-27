"""SQLite persistence layer, automatic migrations, and append-only audit log."""

from __future__ import annotations

import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

VALID_ROLES = ("operator", "viewer")
VALID_CREDENTIAL_TYPES = ("global", "none", "token", "deploy_key")
VALID_GLOBAL_CREDENTIAL_TYPES = ("none", "token", "deploy_key")
VALID_RUN_STATUSES = (
    "queued",
    "running",
    "passed",
    "failed",
    "cancelled",
    "timed_out",
)
TERMINAL_RUN_STATUSES = ("passed", "failed", "cancelled", "timed_out")
MAX_STEP_LOG_CHARS = 2 * 1024 * 1024  # 2 MiB per step log cap
STEP_LOG_TRUNCATION_MARKER = "\n...[step log truncated at 2 MiB limit]...\n"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS repos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    git_url TEXT NOT NULL,
    credential_type TEXT NOT NULL DEFAULT 'global'
        CHECK (credential_type IN ('global', 'none', 'token', 'deploy_key')),
    encrypted_credential TEXT NOT NULL DEFAULT '',
    default_image TEXT NOT NULL,
    timeout_seconds INTEGER NOT NULL DEFAULT 1800 CHECK (timeout_seconds >= 1),
    encrypted_secrets TEXT NOT NULL DEFAULT '',
    secret_keys_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS global_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    git_credential_type TEXT NOT NULL DEFAULT 'none'
        CHECK (git_credential_type IN ('none', 'token', 'deploy_key')),
    encrypted_git_credential TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'viewer')),
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    repo_name TEXT NOT NULL,
    requested_ref TEXT NOT NULL,
    commit_sha TEXT,
    workflow_path TEXT,
    event_name TEXT,
    is_private INTEGER NOT NULL DEFAULT 0 CHECK (is_private IN (0, 1)),
    has_overlay INTEGER NOT NULL DEFAULT 0 CHECK (has_overlay IN (0, 1)),
    has_replacement_workflow INTEGER NOT NULL DEFAULT 0 CHECK (has_replacement_workflow IN (0, 1)),
    encrypted_payload TEXT NOT NULL DEFAULT '',
    callback_url TEXT,
    callback_status TEXT,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'passed', 'failed', 'cancelled', 'timed_out')),
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
    exit_code INTEGER,
    error_message TEXT,
    triggered_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_status_created ON runs(status, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_runs_repo_created ON runs(repo_name, created_at DESC);

CREATE TABLE IF NOT EXISTS run_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    job_id TEXT NOT NULL,
    job_name TEXT NOT NULL,
    step_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    stage TEXT NOT NULL DEFAULT 'Main',
    status TEXT NOT NULL DEFAULT 'running',
    exit_code INTEGER,
    started_at TEXT,
    finished_at TEXT,
    log_text TEXT NOT NULL DEFAULT '',
    UNIQUE(run_id, job_id, step_id)
);

CREATE INDEX IF NOT EXISTS idx_run_steps_run_seq ON run_steps(run_id, seq ASC);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('api', 'mcp')),
    token_id INTEGER,
    token_name TEXT NOT NULL,
    role TEXT,
    action TEXT NOT NULL,
    repo_name TEXT,
    run_id TEXT,
    result TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(id DESC);

CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only: DELETE is forbidden');
END;
"""


class Database:
    """Thread-safe SQLite repository with automatic migrations and WAL concurrency."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=15.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=10000;")
        return conn

    @contextmanager
    def connection(self, write: bool = False) -> Iterator[sqlite3.Connection]:
        if write:
            with self._write_lock:
                conn = self._connect()
                try:
                    conn.execute("BEGIN IMMEDIATE;")
                    yield conn
                    conn.execute("COMMIT;")
                except Exception:
                    try:
                        conn.execute("ROLLBACK;")
                    except sqlite3.Error:
                        pass
                    raise
                finally:
                    conn.close()
        else:
            conn = self._connect()
            try:
                yield conn
            finally:
                conn.close()

    def _migrate(self) -> None:
        with self._write_lock:
            conn = self._connect()
            try:
                conn.executescript(SCHEMA_SQL)
                now = utc_now_iso()
                cur1 = conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = 1"
                ).fetchone()
                if not cur1:
                    conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)",
                        (now,),
                    )

                # Migration 2: widen repos.credential_type CHECK to include 'global' on v1 databases
                # and seed singleton global_settings row.
                cur2 = conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = 2"
                ).fetchone()
                if not cur2:
                    table_sql_row = conn.execute(
                        "SELECT sql FROM sqlite_master WHERE type='table' AND name='repos'"
                    ).fetchone()
                    if table_sql_row and "'global'" not in (table_sql_row["sql"] or ""):
                        conn.execute("PRAGMA foreign_keys=OFF;")
                        conn.execute("BEGIN IMMEDIATE;")
                        try:
                            conn.execute(
                                """
                                CREATE TABLE repos_v2 (
                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    name TEXT NOT NULL UNIQUE,
                                    git_url TEXT NOT NULL,
                                    credential_type TEXT NOT NULL DEFAULT 'global'
                                        CHECK (credential_type IN ('global', 'none', 'token', 'deploy_key')),
                                    encrypted_credential TEXT NOT NULL DEFAULT '',
                                    default_image TEXT NOT NULL,
                                    timeout_seconds INTEGER NOT NULL DEFAULT 1800 CHECK (timeout_seconds >= 1),
                                    encrypted_secrets TEXT NOT NULL DEFAULT '',
                                    secret_keys_json TEXT NOT NULL DEFAULT '[]',
                                    created_at TEXT NOT NULL,
                                    updated_at TEXT NOT NULL
                                );
                                """
                            )
                            conn.execute(
                                """
                                INSERT INTO repos_v2 (
                                    id, name, git_url, credential_type, encrypted_credential,
                                    default_image, timeout_seconds, encrypted_secrets, secret_keys_json,
                                    created_at, updated_at
                                )
                                SELECT
                                    id, name, git_url, credential_type, encrypted_credential,
                                    default_image, timeout_seconds, encrypted_secrets, secret_keys_json,
                                    created_at, updated_at
                                FROM repos;
                                """
                            )
                            conn.execute("DROP TABLE repos;")
                            conn.execute("ALTER TABLE repos_v2 RENAME TO repos;")
                            seq_row = conn.execute("SELECT COALESCE(MAX(id), 0) AS m FROM repos").fetchone()
                            if seq_row and int(seq_row["m"]) > 0:
                                conn.execute("DELETE FROM sqlite_sequence WHERE name = 'repos';")
                                conn.execute(
                                    "INSERT INTO sqlite_sequence (name, seq) VALUES ('repos', ?);",
                                    (int(seq_row["m"]),),
                                )
                            conn.execute("COMMIT;")
                        except Exception:
                            conn.execute("ROLLBACK;")
                            raise
                        finally:
                            conn.execute("PRAGMA foreign_keys=ON;")

                    conn.execute(
                        """
                        INSERT OR IGNORE INTO global_settings (
                            id, git_credential_type, encrypted_git_credential, updated_at
                        ) VALUES (1, 'none', '', ?)
                        """,
                        (now,),
                    )
                    conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at) VALUES (2, ?)",
                        (now,),
                    )
                else:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO global_settings (
                            id, git_credential_type, encrypted_git_credential, updated_at
                        ) VALUES (1, 'none', '', ?)
                        """,
                        (now,),
                    )
            finally:
                conn.close()

    # ---- Global Git Credential ----

    def get_global_git_credential(self) -> dict[str, Any]:
        with self.connection(write=False) as conn:
            row = conn.execute(
                "SELECT git_credential_type, encrypted_git_credential, updated_at FROM global_settings WHERE id = 1"
            ).fetchone()
            if not row:
                return {
                    "git_credential_type": "none",
                    "encrypted_git_credential": "",
                    "updated_at": utc_now_iso(),
                }
            return dict(row)

    def set_global_git_credential(
        self,
        *,
        git_credential_type: str,
        encrypted_git_credential: str,
    ) -> dict[str, Any]:
        if git_credential_type not in VALID_GLOBAL_CREDENTIAL_TYPES:
            raise ValueError(f"Invalid global git_credential_type: {git_credential_type}")
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            conn.execute(
                """
                INSERT INTO global_settings (id, git_credential_type, encrypted_git_credential, updated_at)
                VALUES (1, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    git_credential_type = excluded.git_credential_type,
                    encrypted_git_credential = excluded.encrypted_git_credential,
                    updated_at = excluded.updated_at
                """,
                (git_credential_type, encrypted_git_credential, now),
            )
            row = conn.execute(
                "SELECT git_credential_type, encrypted_git_credential, updated_at FROM global_settings WHERE id = 1"
            ).fetchone()
            return dict(row)

    # ---- Tokens ----

    def insert_token(
        self,
        *,
        name: str,
        role: str,
        token_hash: str,
        token_prefix: str,
    ) -> dict[str, Any]:
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}")
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO tokens (name, role, token_hash, token_prefix, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, role, token_hash, token_prefix, now),
            )
            row = conn.execute(
                "SELECT id, name, role, token_prefix, created_at, last_used_at, revoked_at FROM tokens WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
            return dict(row)

    def get_token_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        with self.connection(write=False) as conn:
            row = conn.execute(
                "SELECT id, name, role, token_prefix, created_at, last_used_at, revoked_at FROM tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            return dict(row) if row else None

    def touch_token_last_used(self, token_id: int) -> str:
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            conn.execute(
                "UPDATE tokens SET last_used_at = ? WHERE id = ?",
                (now, token_id),
            )
        return now

    def list_tokens(self) -> list[dict[str, Any]]:
        with self.connection(write=False) as conn:
            rows = conn.execute(
                """
                SELECT id, name, role, token_prefix, created_at, last_used_at, revoked_at
                FROM tokens
                ORDER BY id DESC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def revoke_token(self, token_id: int) -> bool:
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            cur = conn.execute(
                "UPDATE tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?",
                (now, token_id),
            )
            return cur.rowcount > 0

    # ---- Audit Log (Append-Only) ----

    def append_audit(
        self,
        *,
        source: str,
        token_id: int | None,
        token_name: str,
        role: str | None,
        action: str,
        repo_name: str | None = None,
        run_id: str | None = None,
        result: str,
    ) -> int:
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO audit_logs (
                    created_at, source, token_id, token_name, role, action, repo_name, run_id, result
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    source,
                    token_id,
                    token_name,
                    role,
                    action,
                    repo_name,
                    run_id,
                    result,
                ),
            )
            return int(cur.lastrowid)

    def list_audit_logs(self, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        with self.connection(write=False) as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, source, token_id, token_name, role, action, repo_name, run_id, result
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]

    def count_audit_logs(self) -> int:
        with self.connection(write=False) as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM audit_logs").fetchone()
            return int(row["cnt"])

    # ---- Repos ----

    def create_repo(
        self,
        *,
        name: str,
        git_url: str,
        credential_type: str,
        encrypted_credential: str,
        default_image: str,
        timeout_seconds: int,
        encrypted_secrets: str,
        secret_keys_json: str,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO repos (
                    name, git_url, credential_type, encrypted_credential,
                    default_image, timeout_seconds, encrypted_secrets, secret_keys_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    git_url,
                    credential_type,
                    encrypted_credential,
                    default_image,
                    timeout_seconds,
                    encrypted_secrets,
                    secret_keys_json,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM repos WHERE id = ?", (cur.lastrowid,)
            ).fetchone()
            return dict(row)

    def update_repo(
        self,
        repo_id: int,
        *,
        name: str,
        git_url: str,
        credential_type: str,
        encrypted_credential: str,
        default_image: str,
        timeout_seconds: int,
        encrypted_secrets: str,
        secret_keys_json: str,
    ) -> dict[str, Any] | None:
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            cur = conn.execute(
                """
                UPDATE repos
                SET name = ?,
                    git_url = ?,
                    credential_type = ?,
                    encrypted_credential = ?,
                    default_image = ?,
                    timeout_seconds = ?,
                    encrypted_secrets = ?,
                    secret_keys_json = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    name,
                    git_url,
                    credential_type,
                    encrypted_credential,
                    default_image,
                    timeout_seconds,
                    encrypted_secrets,
                    secret_keys_json,
                    now,
                    repo_id,
                ),
            )
            if cur.rowcount == 0:
                return None
            # Keep denormalized repo_name on existing runs consistent
            conn.execute(
                "UPDATE runs SET repo_name = ? WHERE repo_id = ?",
                (name, repo_id),
            )
            row = conn.execute("SELECT * FROM repos WHERE id = ?", (repo_id,)).fetchone()
            return dict(row)

    def delete_repo(self, repo_id: int) -> bool:
        with self.connection(write=True) as conn:
            cur = conn.execute("DELETE FROM repos WHERE id = ?", (repo_id,))
            return cur.rowcount > 0

    def get_repo_by_id(self, repo_id: int) -> dict[str, Any] | None:
        with self.connection(write=False) as conn:
            row = conn.execute("SELECT * FROM repos WHERE id = ?", (repo_id,)).fetchone()
            return dict(row) if row else None

    def get_repo_by_name(self, name: str) -> dict[str, Any] | None:
        with self.connection(write=False) as conn:
            row = conn.execute("SELECT * FROM repos WHERE name = ?", (name,)).fetchone()
            return dict(row) if row else None

    def list_repos(self) -> list[dict[str, Any]]:
        with self.connection(write=False) as conn:
            rows = conn.execute("SELECT * FROM repos ORDER BY name ASC").fetchall()
            return [dict(r) for r in rows]

    # ---- Runs & Steps ----

    def create_run(
        self,
        *,
        repo_id: int,
        repo_name: str,
        requested_ref: str,
        workflow_path: str | None,
        event_name: str | None,
        is_private: bool,
        has_overlay: bool,
        has_replacement_workflow: bool,
        encrypted_payload: str,
        callback_url: str | None,
        triggered_by: str,
    ) -> dict[str, Any]:
        run_id = f"run_{uuid.uuid4().hex[:16]}"
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    id, repo_id, repo_name, requested_ref, workflow_path, event_name,
                    is_private, has_overlay, has_replacement_workflow, encrypted_payload,
                    callback_url, status, triggered_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)
                """,
                (
                    run_id,
                    repo_id,
                    repo_name,
                    requested_ref,
                    workflow_path,
                    event_name,
                    1 if is_private else 0,
                    1 if has_overlay else 0,
                    1 if has_replacement_workflow else 0,
                    encrypted_payload,
                    callback_url,
                    triggered_by,
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            return dict(row)

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connection(write=False) as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            return dict(row) if row else None

    def list_runs(
        self,
        *,
        repo_name: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if repo_name:
            clauses.append("repo_name = ?")
            params.append(repo_name)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 500)))
        with self.connection(write=False) as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM runs
                {where_sql}
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    def claim_next_queued_run(self) -> dict[str, Any] | None:
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            row = conn.execute(
                """
                SELECT * FROM runs
                WHERE status = 'queued'
                ORDER BY created_at ASC, rowid ASC
                LIMIT 1
                """
            ).fetchone()
            if not row:
                return None
            run_id = row["id"]
            if row["cancel_requested"]:
                conn.execute(
                    """
                    UPDATE runs
                    SET status = 'cancelled', started_at = COALESCE(started_at, ?), finished_at = ?
                    WHERE id = ?
                    """,
                    (now, now, run_id),
                )
                return None
            conn.execute(
                """
                UPDATE runs
                SET status = 'running', started_at = ?
                WHERE id = ? AND status = 'queued'
                """,
                (now, run_id),
            )
            updated = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            return dict(updated) if updated else None

    def recover_interrupted_runs(self) -> list[str]:
        """Mark runs left in 'running' state from an unclean shutdown as failed."""
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            rows = conn.execute(
                "SELECT id FROM runs WHERE status = 'running'"
            ).fetchall()
            ids = [r["id"] for r in rows]
            if ids:
                conn.execute(
                    """
                    UPDATE runs
                    SET status = 'failed',
                        error_message = 'Run interrupted by service restart',
                        finished_at = ?
                    WHERE status = 'running'
                    """,
                    (now,),
                )
            return ids

    def set_run_commit_sha(self, run_id: str, commit_sha: str) -> None:
        with self.connection(write=True) as conn:
            conn.execute(
                "UPDATE runs SET commit_sha = ? WHERE id = ?",
                (commit_sha, run_id),
            )

    def request_cancel_run(self, run_id: str) -> tuple[dict[str, Any] | None, bool]:
        """Request cancellation. If queued, transitions immediately to cancelled."""
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if not row:
                return None, False
            status = row["status"]
            if status in TERMINAL_RUN_STATUSES:
                return dict(row), False
            if status == "queued":
                conn.execute(
                    """
                    UPDATE runs
                    SET status = 'cancelled',
                        cancel_requested = 1,
                        finished_at = ?
                    WHERE id = ?
                    """,
                    (now, run_id),
                )
            else:
                conn.execute(
                    "UPDATE runs SET cancel_requested = 1 WHERE id = ?",
                    (run_id,),
                )
            updated = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            return dict(updated), True

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        exit_code: int | None = None,
        error_message: str | None = None,
    ) -> dict[str, Any] | None:
        if status not in TERMINAL_RUN_STATUSES:
            raise ValueError(f"Not a terminal status: {status}")
        now = utc_now_iso()
        with self.connection(write=True) as conn:
            # Finalize any still-running step rows
            step_final = "cancelled" if status in ("cancelled", "timed_out") else status
            conn.execute(
                """
                UPDATE run_steps
                SET status = CASE WHEN status = 'running' THEN ? ELSE status END,
                    finished_at = COALESCE(finished_at, ?)
                WHERE run_id = ?
                """,
                (step_final, now, run_id),
            )
            conn.execute(
                """
                UPDATE runs
                SET status = ?,
                    exit_code = ?,
                    error_message = ?,
                    finished_at = COALESCE(finished_at, ?)
                WHERE id = ?
                """,
                (status, exit_code, error_message, now, run_id),
            )
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            return dict(row) if row else None

    def set_callback_status(self, run_id: str, callback_status: str) -> None:
        with self.connection(write=True) as conn:
            conn.execute(
                "UPDATE runs SET callback_status = ? WHERE id = ?",
                (callback_status, run_id),
            )

    def upsert_step_log(
        self,
        run_id: str,
        *,
        job_id: str,
        job_name: str,
        step_id: str,
        step_name: str,
        stage: str = "Main",
        status: str | None = None,
        exit_code: int | None = None,
        append_text: str = "",
        timestamp: str | None = None,
        max_log_chars: int = MAX_STEP_LOG_CHARS,
    ) -> None:
        ts = timestamp or utc_now_iso()
        with self.connection(write=True) as conn:
            existing = conn.execute(
                """
                SELECT id, status, exit_code, started_at, finished_at, LENGTH(log_text) AS log_len
                FROM run_steps
                WHERE run_id = ? AND job_id = ? AND step_id = ?
                """,
                (run_id, job_id, step_id),
            ).fetchone()
            if not existing:
                seq_row = conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM run_steps WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                next_seq = int(seq_row["next_seq"])
                new_status = status or "running"
                finished = ts if new_status in ("passed", "failed", "skipped", "cancelled") else None
                initial_log = append_text
                if len(initial_log) > max_log_chars:
                    initial_log = initial_log[:max_log_chars] + STEP_LOG_TRUNCATION_MARKER
                conn.execute(
                    """
                    INSERT INTO run_steps (
                        run_id, seq, job_id, job_name, step_id, step_name, stage,
                        status, exit_code, started_at, finished_at, log_text
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        next_seq,
                        job_id,
                        job_name,
                        step_id,
                        step_name,
                        stage,
                        new_status,
                        exit_code,
                        ts,
                        finished,
                        initial_log,
                    ),
                )
            else:
                cur_len = int(existing["log_len"] or 0)
                chunk_to_append = ""
                if append_text and cur_len < max_log_chars:
                    remaining = max_log_chars - cur_len
                    if len(append_text) <= remaining:
                        chunk_to_append = append_text
                    else:
                        chunk_to_append = (
                            append_text[:remaining] + STEP_LOG_TRUNCATION_MARKER
                        )

                new_status = status or existing["status"]
                new_exit = exit_code if exit_code is not None else existing["exit_code"]
                finished = existing["finished_at"]
                if new_status in ("passed", "failed", "skipped", "cancelled") and not finished:
                    finished = ts
                if chunk_to_append:
                    conn.execute(
                        """
                        UPDATE run_steps
                        SET job_name = ?,
                            step_name = ?,
                            status = ?,
                            exit_code = ?,
                            finished_at = ?,
                            log_text = log_text || ?
                        WHERE id = ?
                        """,
                        (
                            job_name or job_id,
                            step_name or step_id,
                            new_status,
                            new_exit,
                            finished,
                            chunk_to_append,
                            existing["id"],
                        ),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE run_steps
                        SET job_name = ?,
                            step_name = ?,
                            status = ?,
                            exit_code = ?,
                            finished_at = ?
                        WHERE id = ?
                        """,
                        (
                            job_name or job_id,
                            step_name or step_id,
                            new_status,
                            new_exit,
                            finished,
                            existing["id"],
                        ),
                    )

    def list_run_steps(self, run_id: str) -> list[dict[str, Any]]:
        with self.connection(write=False) as conn:
            rows = conn.execute(
                """
                SELECT id, run_id, seq, job_id, job_name, step_id, step_name, stage,
                       status, exit_code, started_at, finished_at, log_text
                FROM run_steps
                WHERE run_id = ?
                ORDER BY seq ASC
                """,
                (run_id,),
            ).fetchall()
            return [dict(r) for r in rows]
