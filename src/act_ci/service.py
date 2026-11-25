"""Core business logic, RBAC enforcement, audit logging, and sanitization."""

from __future__ import annotations

import json
import posixpath
import re
from datetime import datetime
from typing import Any, Callable
from urllib.parse import urlparse

from act_ci.config import DEFAULT_RUNNER_IMAGE, DEFAULT_TIMEOUT_SECONDS, Settings
from act_ci.db import VALID_CREDENTIAL_TYPES, VALID_ROLES, VALID_RUN_STATUSES, Database
from act_ci.models import (
    ApiError,
    ForbiddenError,
    JobLogGroupView,
    NotFoundError,
    Principal,
    RepoPublicView,
    RunLogsResponse,
    RunPublicView,
    StepLogView,
    TriggerRunRequest,
    UnauthorizedError,
    ValidationApiError,
)
from act_ci.security import (
    SecretBox,
    SecretMasker,
    generate_api_token,
    hash_api_token,
)

REPO_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
EVENT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$")
SECRET_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def compute_duration_seconds(started_at: str | None, finished_at: str | None) -> float | None:
    start_dt = _parse_iso(started_at)
    if not start_dt:
        return None
    end_dt = _parse_iso(finished_at)
    if not end_dt:
        return None
    return max(0.0, round((end_dt - start_dt).total_seconds(), 2))


def validate_relative_workspace_path(rel_path: str, *, allow_git_dir: bool = False) -> str:
    """Ensure an overlay or workflow path stays strictly inside the workspace."""
    if not rel_path or "\x00" in rel_path:
        raise ValidationApiError("Invalid empty or null-byte file path")
    cleaned = rel_path.replace("\\", "/").strip()
    if cleaned.startswith("/") or cleaned.startswith("~"):
        raise ValidationApiError(f"Absolute paths are not allowed: {rel_path}")
    norm = posixpath.normpath(cleaned)
    if norm in ("", ".", "..") or norm.startswith("../") or "/../" in f"/{norm}/":
        raise ValidationApiError(f"Path traversal is not allowed: {rel_path}")
    parts = norm.split("/")
    if not allow_git_dir and parts[0] == ".git":
        raise ValidationApiError("Overlay paths may not modify .git/")
    return norm


def validate_callback_url(url: str | None) -> str | None:
    if not url:
        return None
    cleaned = url.strip()
    if not cleaned:
        return None
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValidationApiError("callback_url must be a valid http:// or https:// URL")
    return cleaned


class CiService:
    """Single source of truth for RBAC, audit logging, repos, tokens, and runs."""

    def __init__(
        self,
        db: Database,
        secret_box: SecretBox,
        settings: Settings,
        on_run_enqueued: Callable[[], None] | None = None,
        on_run_cancel_requested: Callable[[str], None] | None = None,
    ) -> None:
        self.db = db
        self.secret_box = secret_box
        self.settings = settings
        self.on_run_enqueued = on_run_enqueued
        self.on_run_cancel_requested = on_run_cancel_requested

    # ---- Authentication & Audit ----

    def authenticate_bearer(
        self,
        authorization_header: str | None,
        *,
        source: str,
        attempted_action: str,
        repo_name: str | None = None,
        run_id: str | None = None,
    ) -> Principal:
        """Validate a bearer token. Records an audit row immediately on auth failure."""
        if not authorization_header:
            self.db.append_audit(
                source=source,
                token_id=None,
                token_name="<anonymous>",
                role=None,
                action=attempted_action,
                repo_name=repo_name,
                run_id=run_id,
                result="unauthorized:missing_token",
            )
            raise UnauthorizedError("Missing Authorization bearer token")

        parts = authorization_header.strip().split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            self.db.append_audit(
                source=source,
                token_id=None,
                token_name="<malformed>",
                role=None,
                action=attempted_action,
                repo_name=repo_name,
                run_id=run_id,
                result="unauthorized:malformed_header",
            )
            raise UnauthorizedError("Authorization header must be 'Bearer <token>'")

        raw_token = parts[1].strip()
        token_hash = hash_api_token(raw_token)
        token_row = self.db.get_token_by_hash(token_hash)
        if not token_row:
            self.db.append_audit(
                source=source,
                token_id=None,
                token_name="<invalid>",
                role=None,
                action=attempted_action,
                repo_name=repo_name,
                run_id=run_id,
                result="unauthorized:unknown_token",
            )
            raise UnauthorizedError("Invalid bearer token")

        if token_row["revoked_at"] is not None:
            self.db.append_audit(
                source=source,
                token_id=token_row["id"],
                token_name=token_row["name"],
                role=token_row["role"],
                action=attempted_action,
                repo_name=repo_name,
                run_id=run_id,
                result="unauthorized:revoked_token",
            )
            raise UnauthorizedError("Bearer token has been revoked")

        self.db.touch_token_last_used(token_row["id"])
        return Principal(
            role=token_row["role"],
            token_id=token_row["id"],
            token_name=token_row["name"],
            source=source,  # type: ignore[arg-type]
        )

    def _audit(
        self,
        principal: Principal,
        action: str,
        result: str,
        *,
        repo_name: str | None = None,
        run_id: str | None = None,
    ) -> None:
        if principal.source in ("api", "mcp"):
            self.db.append_audit(
                source=principal.source,
                token_id=principal.token_id,
                token_name=principal.token_name,
                role=principal.role,
                action=action,
                repo_name=repo_name,
                run_id=run_id,
                result=result,
            )

    def record_protocol_call(
        self,
        principal: Principal,
        action: str,
        result: str = "ok",
    ) -> None:
        """Audit non-CRUD MCP protocol actions (initialize, tools/list, ping, etc.)."""
        self._audit(principal, action, result)

    def _require_role(
        self,
        principal: Principal,
        allowed_roles: tuple[str, ...],
        *,
        action: str,
        repo_name: str | None = None,
        run_id: str | None = None,
    ) -> None:
        if principal.role not in allowed_roles:
            self._audit(
                principal,
                action,
                "denied:insufficient_role",
                repo_name=repo_name,
                run_id=run_id,
            )
            raise ForbiddenError(
                f"Role '{principal.role}' is not permitted to perform '{action}'"
            )

    # ---- Masker Construction ----

    def build_masker_for_repo(self, repo_row: dict[str, Any] | None) -> SecretMasker:
        values: list[str] = []
        if repo_row:
            cred = self.secret_box.decrypt_str(repo_row.get("encrypted_credential") or "")
            if cred:
                values.append(cred)
            sec_dict = self.secret_box.decrypt_dict(repo_row.get("encrypted_secrets") or "")
            values.extend(sec_dict.values())
        return SecretMasker(values)

    def build_global_masker(self) -> SecretMasker:
        values: list[str] = []
        for repo_row in self.db.list_repos():
            cred = self.secret_box.decrypt_str(repo_row.get("encrypted_credential") or "")
            if cred:
                values.append(cred)
            sec_dict = self.secret_box.decrypt_dict(repo_row.get("encrypted_secrets") or "")
            values.extend(sec_dict.values())
        return SecretMasker(values)

    # ---- Admin: Tokens Management ----

    def create_token(self, *, name: str, role: str) -> tuple[dict[str, Any], str]:
        clean_name = name.strip()
        if not clean_name or len(clean_name) > 128:
            raise ValidationApiError("Token name must be 1–128 characters")
        if role not in VALID_ROLES:
            raise ValidationApiError(f"Role must be one of {VALID_ROLES}")
        raw_token, token_hash, token_prefix = generate_api_token()
        row = self.db.insert_token(
            name=clean_name,
            role=role,
            token_hash=token_hash,
            token_prefix=token_prefix,
        )
        return row, raw_token

    def list_tokens(self) -> list[dict[str, Any]]:
        return self.db.list_tokens()

    def revoke_token(self, token_id: int) -> bool:
        return self.db.revoke_token(token_id)

    # ---- Admin: Repos Management ----

    def _validate_git_url(self, git_url: str) -> str:
        clean = git_url.strip()
        if not clean or len(clean) > 2048:
            raise ValidationApiError("git_url is required")
        if clean.startswith("-"):
            raise ValidationApiError("git_url cannot start with '-'")
        if clean.startswith(("https://", "http://", "ssh://", "git@")):
            return clean
        if self.settings.allow_local_repos and (
            clean.startswith("file://") or clean.startswith("/")
        ):
            return clean
        raise ValidationApiError(
            "git_url must be an https://, ssh://, or git@ repository URL"
        )

    def create_repo_admin(
        self,
        *,
        name: str,
        git_url: str,
        credential_type: str = "none",
        credential_value: str = "",
        default_image: str = DEFAULT_RUNNER_IMAGE,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        secrets_dict: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        clean_name = name.strip()
        if not REPO_NAME_RE.match(clean_name):
            raise ValidationApiError(
                "Repo name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
            )
        if self.db.get_repo_by_name(clean_name):
            raise ValidationApiError(f"Repository '{clean_name}' already exists")
        clean_url = self._validate_git_url(git_url)
        if credential_type not in VALID_CREDENTIAL_TYPES:
            raise ValidationApiError(f"Invalid credential_type: {credential_type}")
        clean_image = default_image.strip() or DEFAULT_RUNNER_IMAGE
        if timeout_seconds < 1 or timeout_seconds > 86400:
            raise ValidationApiError("timeout_seconds must be between 1 and 86400")

        enc_cred = ""
        if credential_type != "none" and credential_value.strip():
            enc_cred = self.secret_box.encrypt_str(credential_value.strip())
        elif credential_type != "none" and not credential_value.strip():
            raise ValidationApiError("Credential value is required when credential_type is set")

        cleaned_secrets = self._validate_secrets_dict(secrets_dict or {})
        enc_secrets = self.secret_box.encrypt_dict(cleaned_secrets)
        secret_keys_json = json.dumps(sorted(cleaned_secrets.keys()))

        return self.db.create_repo(
            name=clean_name,
            git_url=clean_url,
            credential_type=credential_type,
            encrypted_credential=enc_cred,
            default_image=clean_image,
            timeout_seconds=timeout_seconds,
            encrypted_secrets=enc_secrets,
            secret_keys_json=secret_keys_json,
        )

    def update_repo_admin(
        self,
        repo_id: int,
        *,
        name: str,
        git_url: str,
        credential_type: str,
        credential_value: str | None = None,
        keep_existing_credential: bool = True,
        default_image: str = DEFAULT_RUNNER_IMAGE,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        secrets_updates: dict[str, str] | None = None,
        replace_secrets: bool = False,
        remove_secret_keys: list[str] | None = None,
    ) -> dict[str, Any]:
        existing = self.db.get_repo_by_id(repo_id)
        if not existing:
            raise NotFoundError(f"Repository id={repo_id} not found")

        clean_name = name.strip()
        if not REPO_NAME_RE.match(clean_name):
            raise ValidationApiError(
                "Repo name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
            )
        by_name = self.db.get_repo_by_name(clean_name)
        if by_name and by_name["id"] != repo_id:
            raise ValidationApiError(f"Repository '{clean_name}' already exists")

        clean_url = self._validate_git_url(git_url)
        if credential_type not in VALID_CREDENTIAL_TYPES:
            raise ValidationApiError(f"Invalid credential_type: {credential_type}")
        clean_image = default_image.strip() or DEFAULT_RUNNER_IMAGE
        if timeout_seconds < 1 or timeout_seconds > 86400:
            raise ValidationApiError("timeout_seconds must be between 1 and 86400")

        if credential_type == "none":
            enc_cred = ""
        elif credential_value and credential_value.strip():
            enc_cred = self.secret_box.encrypt_str(credential_value.strip())
        elif keep_existing_credential and existing["encrypted_credential"]:
            enc_cred = existing["encrypted_credential"]
        else:
            raise ValidationApiError("Credential value is required when credential_type is set")

        if replace_secrets:
            merged_secrets: dict[str, str] = {}
        else:
            merged_secrets = self.secret_box.decrypt_dict(existing["encrypted_secrets"])

        for k in remove_secret_keys or []:
            merged_secrets.pop(k, None)

        if secrets_updates:
            validated_updates = self._validate_secrets_dict(secrets_updates)
            merged_secrets.update(validated_updates)

        enc_secrets = self.secret_box.encrypt_dict(merged_secrets)
        secret_keys_json = json.dumps(sorted(merged_secrets.keys()))

        updated = self.db.update_repo(
            repo_id,
            name=clean_name,
            git_url=clean_url,
            credential_type=credential_type,
            encrypted_credential=enc_cred,
            default_image=clean_image,
            timeout_seconds=timeout_seconds,
            encrypted_secrets=enc_secrets,
            secret_keys_json=secret_keys_json,
        )
        if not updated:
            raise NotFoundError(f"Repository id={repo_id} not found")
        return updated

    def delete_repo_admin(self, repo_id: int) -> bool:
        return self.db.delete_repo(repo_id)

    @staticmethod
    def _validate_secrets_dict(secrets_dict: dict[str, str]) -> dict[str, str]:
        cleaned: dict[str, str] = {}
        for k, v in secrets_dict.items():
            key = k.strip()
            if not key:
                continue
            if not SECRET_KEY_RE.match(key):
                raise ValidationApiError(
                    f"Invalid secret name '{key}': must match ^[A-Za-z_][A-Za-z0-9_]*$"
                )
            cleaned[key] = v
        return cleaned

    @staticmethod
    def _serialize_repo_public(row: dict[str, Any]) -> RepoPublicView:
        # Never return encrypted_credential, encrypted_secrets, or secret values!
        return RepoPublicView(
            name=row["name"],
            git_url=row["git_url"],
            credential_type=row["credential_type"],
            has_credential=bool(row["encrypted_credential"]),
            default_image=row["default_image"],
            timeout_seconds=row["timeout_seconds"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # ---- Shared API / MCP Operations (Role-Enforced + Audited) ----

    def list_repos(self, principal: Principal) -> list[RepoPublicView]:
        self._require_role(
            principal, ("admin", "operator", "viewer"), action="repos.list"
        )
        rows = self.db.list_repos()
        self._audit(principal, "repos.list", "ok")
        return [self._serialize_repo_public(r) for r in rows]

    def trigger_run(
        self,
        principal: Principal,
        req: TriggerRunRequest,
    ) -> RunPublicView:
        repo_name = req.repo.strip()
        self._require_role(
            principal,
            ("admin", "operator"),
            action="runs.trigger",
            repo_name=repo_name,
        )

        repo_row = self.db.get_repo_by_name(repo_name)
        if not repo_row:
            self._audit(
                principal, "runs.trigger", "not_found:repo", repo_name=repo_name
            )
            raise NotFoundError(f"Repository '{repo_name}' not found")

        ref = req.ref.strip()
        if not ref or ref.startswith("-") or "\x00" in ref:
            self._audit(
                principal, "runs.trigger", "invalid_request:ref", repo_name=repo_name
            )
            raise ValidationApiError("Invalid git ref or commit SHA")

        try:
            workflow_path = (
                validate_relative_workspace_path(req.workflow)
                if req.workflow and req.workflow.strip()
                else None
            )
            event_name: str | None = None
            if req.event and req.event.strip():
                ev = req.event.strip()
                if not EVENT_NAME_RE.match(ev):
                    raise ValidationApiError(f"Invalid event name: {ev}")
                event_name = ev

            normalized_overlay: dict[str, str] = {}
            if req.overlay:
                if len(req.overlay) > 100:
                    raise ValidationApiError("Overlay cannot exceed 100 files")
                for raw_path, content in req.overlay.items():
                    norm_path = validate_relative_workspace_path(raw_path)
                    normalized_overlay[norm_path] = content

            replacement_wf = (
                req.replacement_workflow
                if req.replacement_workflow and req.replacement_workflow.strip()
                else None
            )
            callback_url = validate_callback_url(req.callback_url)
        except ValidationApiError as exc:
            self._audit(
                principal,
                "runs.trigger",
                f"invalid_request:{exc.detail}",
                repo_name=repo_name,
            )
            raise

        payload_obj: dict[str, Any] = {}
        if normalized_overlay:
            payload_obj["overlay"] = normalized_overlay
        if replacement_wf:
            payload_obj["replacement_workflow"] = replacement_wf

        encrypted_payload = (
            self.secret_box.encrypt_str(json.dumps(payload_obj))
            if payload_obj
            else ""
        )

        run_row = self.db.create_run(
            repo_id=repo_row["id"],
            repo_name=repo_row["name"],
            requested_ref=ref,
            workflow_path=workflow_path,
            event_name=event_name,
            is_private=bool(req.private),
            has_overlay=bool(normalized_overlay),
            has_replacement_workflow=bool(replacement_wf),
            encrypted_payload=encrypted_payload,
            callback_url=callback_url,
            triggered_by=principal.token_name,
        )

        self._audit(
            principal,
            "runs.trigger",
            "ok",
            repo_name=repo_row["name"],
            run_id=run_row["id"],
        )

        if self.on_run_enqueued:
            self.on_run_enqueued()

        masker = self.build_masker_for_repo(repo_row)
        return self._serialize_run(run_row, principal, masker)

    def _serialize_run(
        self,
        row: dict[str, Any],
        principal: Principal,
        masker: SecretMasker,
    ) -> RunPublicView:
        is_private = bool(row["is_private"])
        can_inspect_private = principal.role in ("admin", "operator")

        overlay_files: list[str] | None = None
        has_overlay: bool | None = bool(row["has_overlay"])
        has_replacement_wf: bool | None = bool(row["has_replacement_workflow"])
        error_msg: str | None = masker.mask(row["error_message"]) if row["error_message"] else None
        workflow_shown: str | None = row["workflow_path"]
        triggered_by_shown: str | None = row["triggered_by"]

        if is_private and not can_inspect_private:
            # Viewers get status & basic run coordinates ONLY; no private overlay/error details
            has_overlay = None
            has_replacement_wf = None
            overlay_files = None
            error_msg = None
            workflow_shown = None
            triggered_by_shown = None
        elif can_inspect_private and row["encrypted_payload"]:
            try:
                payload = json.loads(self.secret_box.decrypt_str(row["encrypted_payload"]))
                if isinstance(payload.get("overlay"), dict):
                    overlay_files = sorted(
                        masker.mask(k) for k in payload["overlay"].keys()
                    )
            except Exception:
                overlay_files = []

        return RunPublicView(
            id=row["id"],
            repo=row["repo_name"],
            ref=masker.mask(row["requested_ref"]),
            commit_sha=row["commit_sha"],
            workflow=masker.mask(workflow_shown) if workflow_shown else None,
            event=row["event_name"],
            private=is_private,
            has_overlay=has_overlay,
            has_replacement_workflow=has_replacement_wf,
            overlay_files=overlay_files,
            status=row["status"],
            exit_code=row["exit_code"],
            error_message=error_msg,
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            duration_seconds=compute_duration_seconds(
                row["started_at"], row["finished_at"]
            ),
            triggered_by=triggered_by_shown,
        )

    def list_runs(
        self,
        principal: Principal,
        *,
        repo: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[RunPublicView]:
        clean_repo = repo.strip() if repo and repo.strip() else None
        clean_status = status.strip() if status and status.strip() else None
        self._require_role(
            principal,
            ("admin", "operator", "viewer"),
            action="runs.list",
            repo_name=clean_repo,
        )
        if clean_status and clean_status not in VALID_RUN_STATUSES:
            self._audit(
                principal,
                "runs.list",
                f"invalid_request:status={clean_status}",
                repo_name=clean_repo,
            )
            raise ValidationApiError(f"Invalid status filter: {clean_status}")

        rows = self.db.list_runs(
            repo_name=clean_repo,
            status=clean_status,
            limit=limit,
        )
        masker = self.build_global_masker()
        self._audit(principal, "runs.list", "ok", repo_name=clean_repo)
        return [self._serialize_run(r, principal, masker) for r in rows]

    def get_run_status(self, principal: Principal, run_id: str) -> RunPublicView:
        self._require_role(
            principal,
            ("admin", "operator", "viewer"),
            action="runs.get",
            run_id=run_id,
        )
        row = self.db.get_run(run_id)
        if not row:
            self._audit(principal, "runs.get", "not_found", run_id=run_id)
            raise NotFoundError(f"Run '{run_id}' not found")

        repo_row = self.db.get_repo_by_id(row["repo_id"])
        masker = self.build_masker_for_repo(repo_row)
        self._audit(
            principal,
            "runs.get",
            "ok",
            repo_name=row["repo_name"],
            run_id=row["id"],
        )
        return self._serialize_run(row, principal, masker)

    def get_run_logs(self, principal: Principal, run_id: str) -> RunLogsResponse:
        self._require_role(
            principal,
            ("admin", "operator", "viewer"),
            action="runs.logs",
            run_id=run_id,
        )
        row = self.db.get_run(run_id)
        if not row:
            self._audit(principal, "runs.logs", "not_found", run_id=run_id)
            raise NotFoundError(f"Run '{run_id}' not found")

        if row["is_private"] and principal.role == "viewer":
            self._audit(
                principal,
                "runs.logs",
                "denied:private_run",
                repo_name=row["repo_name"],
                run_id=row["id"],
            )
            raise ForbiddenError("Viewer tokens cannot read logs of private runs")

        repo_row = self.db.get_repo_by_id(row["repo_id"])
        masker = self.build_masker_for_repo(repo_row)
        steps = self.db.list_run_steps(run_id)

        jobs_map: dict[str, JobLogGroupView] = {}
        jobs_order: list[JobLogGroupView] = []
        raw_chunks: list[str] = []

        for s in steps:
            jid = s["job_id"]
            jname = masker.mask(s["job_name"])
            if jid not in jobs_map:
                grp = JobLogGroupView(
                    job_id=jid,
                    job_name=jname,
                    status="passed",
                    steps=[],
                )
                jobs_map[jid] = grp
                jobs_order.append(grp)

            masked_log = masker.mask(s["log_text"])
            step_view = StepLogView(
                job_id=jid,
                job_name=jname,
                step_id=s["step_id"],
                step_name=masker.mask(s["step_name"]),
                stage=s["stage"],
                status=s["status"],
                exit_code=s["exit_code"],
                started_at=s["started_at"],
                finished_at=s["finished_at"],
                log=masked_log,
            )
            jobs_map[jid].steps.append(step_view)
            if masked_log:
                raw_chunks.append(f"=== [{jname} / {step_view.step_name}] ===\n{masked_log}")

        for grp in jobs_order:
            statuses = [st.status for st in grp.steps]
            if "running" in statuses:
                grp.status = "running"
            elif "failed" in statuses:
                grp.status = "failed"
            elif "cancelled" in statuses:
                grp.status = "cancelled"
            elif all(st == "skipped" for st in statuses) and statuses:
                grp.status = "skipped"
            else:
                grp.status = "passed"

        self._audit(
            principal,
            "runs.logs",
            "ok",
            repo_name=row["repo_name"],
            run_id=row["id"],
        )
        return RunLogsResponse(
            run_id=row["id"],
            repo=row["repo_name"],
            status=row["status"],
            private=bool(row["is_private"]),
            jobs=jobs_order,
            raw_log="\n".join(raw_chunks),
        )

    def cancel_run(self, principal: Principal, run_id: str) -> RunPublicView:
        self._require_role(
            principal,
            ("admin", "operator"),
            action="runs.cancel",
            run_id=run_id,
        )
        existing = self.db.get_run(run_id)
        if not existing:
            self._audit(principal, "runs.cancel", "not_found", run_id=run_id)
            raise NotFoundError(f"Run '{run_id}' not found")

        updated, changed = self.db.request_cancel_run(run_id)
        assert updated is not None
        if changed and self.on_run_cancel_requested:
            self.on_run_cancel_requested(run_id)

        repo_row = self.db.get_repo_by_id(updated["repo_id"])
        masker = self.build_masker_for_repo(repo_row)
        self._audit(
            principal,
            "runs.cancel",
            "ok" if changed else "noop:already_terminal",
            repo_name=updated["repo_name"],
            run_id=updated["id"],
        )
        return self._serialize_run(updated, principal, masker)

    def get_run_private_overlay_admin_or_operator(
        self, principal: Principal, run_id: str
    ) -> dict[str, Any]:
        """Allow admin UI (or operator) to inspect overlay filenames & replacement flag safely."""
        if principal.role not in ("admin", "operator"):
            raise ForbiddenError("Insufficient permissions")
        row = self.db.get_run(run_id)
        if not row or not row["encrypted_payload"]:
            return {}
        repo_row = self.db.get_repo_by_id(row["repo_id"])
        masker = self.build_masker_for_repo(repo_row)
        payload = json.loads(self.secret_box.decrypt_str(row["encrypted_payload"]))
        result: dict[str, Any] = {}
        if isinstance(payload.get("overlay"), dict):
            result["overlay"] = {
                masker.mask(k): masker.mask(v)
                for k, v in payload["overlay"].items()
            }
        if payload.get("replacement_workflow"):
            result["replacement_workflow"] = masker.mask(
                str(payload["replacement_workflow"])
            )
        return result
