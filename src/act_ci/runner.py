"""Single-slot nektos/act execution engine against an isolated Docker-in-Docker sidecar."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import re
import shlex
import shutil
import signal
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from act_ci.config import Settings
from act_ci.db import Database, utc_now_iso
from act_ci.service import (
    is_disallowed_callback_ip,
    validate_callback_url,
    validate_relative_workspace_path,
)
from act_ci.security import SecretBox, SecretMasker

logger = logging.getLogger("act_ci.runner")

ACT_PLATFORM_LABELS = (
    "ubuntu-latest",
    "ubuntu-24.04",
    "ubuntu-22.04",
    "ubuntu-20.04",
)


@dataclass
class Slot:
    slot_id: str
    docker_host: str
    cache_dir: Path
    workspace_root: Path
    temp_root: Path

    def ensure_dirs(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.cache_dir / "actions").mkdir(parents=True, exist_ok=True)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.temp_root.mkdir(parents=True, exist_ok=True)


def parse_act_json_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped or not stripped.startswith("{"):
        return None
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def map_act_json_event(event: dict[str, Any]) -> dict[str, Any]:
    """Extract normalized (job_id, job_name, step_id, step_name, stage, status, exit_code, text)."""
    job_id = str(event.get("jobID") or event.get("job") or "__workflow__")
    job_name = str(event.get("job") or event.get("jobID") or "Workflow")
    stage = str(event.get("stage") or "Main")
    step_name = str(event.get("step") or "")
    raw_stepid = event.get("stepID") or event.get("stepid")
    if isinstance(raw_stepid, list):
        step_id_raw = "/".join(str(x) for x in raw_stepid) or step_name or "__job__"
    else:
        step_id_raw = str(raw_stepid or step_name or "__job__")
    if stage and stage != "Main" and step_id_raw != "__job__":
        step_id = f"{stage}:{step_id_raw}"
    else:
        step_id = step_id_raw
    if not step_name:
        step_name = "Job Setup / Summary"

    execution_result = str(
        event.get("executionResult")
        or event.get("stepResult")
        or event.get("jobResult")
        or ""
    ).lower()
    raw_output = event.get("rawOutput") is True
    msg = str(event.get("msg") or "")

    status: str | None = None
    exit_code: int | None = None
    if execution_result in ("success", "passed"):
        status = "passed"
        exit_code = 0
    elif execution_result in ("failure", "failed"):
        status = "failed"
        exit_code = 1
    elif execution_result == "skipped":
        status = "skipped"
        exit_code = 0
    elif execution_result in ("cancelled", "canceled"):
        status = "cancelled"

    append_text = ""
    if raw_output:
        append_text = msg if msg.endswith("\n") else f"{msg}\n"
    elif msg:
        # Useful lifecycle line from act (pulling image, starting step, result, error)
        level = str(event.get("level") or "info")
        if level in ("error", "warning") or not msg.startswith("  "):
            append_text = msg if msg.endswith("\n") else f"{msg}\n"

    return {
        "job_id": job_id,
        "job_name": job_name,
        "step_id": step_id,
        "step_name": step_name,
        "stage": stage,
        "status": status,
        "exit_code": exit_code,
        "append_text": append_text,
        "timestamp": event.get("time") if isinstance(event.get("time"), str) else None,
    }


def _escape_secret_file_value(val: str) -> str:
    """Format a dotenv/act secret-file value, supporting multiline values safely."""
    if "\n" in val or '"' in val or "'" in val or " " in val or "#" in val:
        escaped = (
            val.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )
        return f'"{escaped}"'
    return val


class RunnerWorker:
    """Manages one dedicated DinD slot, FIFO run queue, cancellation, and scheduled pruning."""

    def __init__(
        self,
        db: Database,
        secret_box: SecretBox,
        settings: Settings,
    ) -> None:
        self.db = db
        self.secret_box = secret_box
        self.settings = settings
        self.slot = Slot(
            slot_id="slot-0",
            docker_host=settings.docker_host,
            cache_dir=settings.slot_cache_dir,
            workspace_root=settings.slot_workspace_root,
            temp_root=settings.slot_temp_root,
        )
        self._wake_event = asyncio.Event()
        self._stop_event = asyncio.Event()
        self._active_run_id: str | None = None
        self._cancel_active_event = asyncio.Event()
        self._worker_task: asyncio.Task[None] | None = None
        self._prune_task: asyncio.Task[None] | None = None

    def notify_enqueued(self) -> None:
        self._wake_event.set()

    def notify_cancel(self, run_id: str) -> None:
        if self._active_run_id == run_id:
            self._cancel_active_event.set()
        self._wake_event.set()

    async def start(self) -> None:
        self.slot.ensure_dirs()
        recovered = self.db.recover_interrupted_runs()
        if recovered:
            logger.warning("Recovered interrupted runs on startup: %s", recovered)
        # Best-effort cleanup of any leftover workspace dirs or DinD containers from prior crash
        self._clear_directory_children(self.slot.workspace_root)
        self._clear_directory_children(self.slot.temp_root)
        await self._cleanup_slot_daemon_containers(ignore_errors=True)

        self._stop_event.clear()
        self._wake_event.set()
        self._worker_task = asyncio.create_task(self._worker_loop(), name="act-ci-slot-0")
        if self.settings.prune_interval_seconds > 0:
            self._prune_task = asyncio.create_task(
                self._prune_loop(), name="act-ci-image-pruner"
            )

    async def stop(self) -> None:
        self._stop_event.set()
        self._cancel_active_event.set()
        self._wake_event.set()
        for task in (self._worker_task, self._prune_task):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        self._worker_task = None
        self._prune_task = None

    async def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            run_row = self.db.claim_next_queued_run()
            if run_row is None:
                self._wake_event.clear()
                # Double-check in case an enqueue raced right before clear()
                if self.db.list_runs(status="queued", limit=1):
                    continue
                try:
                    await asyncio.wait_for(self._wake_event.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
                continue

            run_id = run_row["id"]
            self._active_run_id = run_id
            self._cancel_active_event.clear()
            if run_row.get("cancel_requested"):
                self._cancel_active_event.set()

            try:
                await self.execute_claimed_run(run_row)
            except Exception as exc:
                logger.exception("Unhandled error in runner for %s: %s", run_id, exc)
                self.db.finish_run(
                    run_id,
                    status="failed",
                    exit_code=-1,
                    error_message="Internal runner error",
                )
            finally:
                self._active_run_id = None
                self._cancel_active_event.clear()

    async def _prune_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self.settings.prune_interval_seconds)
            except asyncio.CancelledError:
                break
            if self._active_run_id is None:
                await self.prune_old_images()

    async def prune_old_images(self) -> tuple[int, str]:
        """Prune old unused images on the slot's Docker daemon."""
        if not shutil.which(self.settings.docker_binary):
            return 0, "docker binary not installed; skipping prune"
        rc, out = await self._run_short_cmd(
            [
                self.settings.docker_binary,
                "-H",
                self.slot.docker_host,
                "image",
                "prune",
                "-af",
                "--filter",
                f"until={self.settings.prune_until}",
            ],
            timeout=120.0,
        )
        return rc, out

    async def execute_claimed_run(self, run_row: dict[str, Any]) -> None:
        run_id = run_row["id"]
        repo_row = self.db.get_repo_by_id(run_row["repo_id"])
        if not repo_row:
            self.db.finish_run(
                run_id,
                status="failed",
                exit_code=1,
                error_message="Repository no longer exists",
            )
            await self._deliver_callback(run_row.get("callback_url"), run_id, "failed")
            return

        credential = self.secret_box.decrypt_str(repo_row.get("encrypted_credential") or "")
        credential_type = str(repo_row.get("credential_type") or "none")
        if credential_type == "global":
            # Use the account-wide Git credential configured once in Repos settings.
            global_row = self.db.get_global_git_credential()
            global_type = str(global_row.get("git_credential_type") or "none")
            global_value = self.secret_box.decrypt_str(
                global_row.get("encrypted_git_credential") or ""
            )
            credential = global_value
            credential_type = global_type if (global_value and global_type != "none") else "none"
        secrets_dict = self.secret_box.decrypt_dict(repo_row.get("encrypted_secrets") or "")
        masker = SecretMasker([credential, *secrets_dict.values()])

        workspace_dir = self.slot.workspace_root / f"ws-{run_id}"
        run_tmp_dir = self.slot.temp_root / f"tmp-{run_id}"
        timeout_seconds = max(1, int(repo_row.get("timeout_seconds") or 1800))
        deadline = asyncio.get_running_loop().time() + timeout_seconds

        final_status = "failed"
        final_exit_code: int | None = 1
        final_error: str | None = None

        try:
            self.slot.ensure_dirs()
            if workspace_dir.exists():
                shutil.rmtree(workspace_dir, ignore_errors=True)
            if run_tmp_dir.exists():
                shutil.rmtree(run_tmp_dir, ignore_errors=True)
            workspace_dir.mkdir(parents=True, mode=0o700)
            run_tmp_dir.mkdir(parents=True, mode=0o700)

            # Ensure clean daemon before starting
            await self._cleanup_slot_daemon_containers(ignore_errors=True)

            # Step 1: Clone & checkout exact commit
            self._append_system_step(
                run_id,
                step_id="checkout",
                step_name="Clone repository",
                status="running",
                text=f"Cloning {masker.mask(repo_row['git_url'])} at ref '{masker.mask(run_row['requested_ref'])}'...\n",
            )
            commit_sha = await self._clone_and_checkout(
                run_id=run_id,
                git_url=repo_row["git_url"],
                requested_ref=run_row["requested_ref"],
                credential_type=credential_type,
                credential=credential,
                workspace_dir=workspace_dir,
                run_tmp_dir=run_tmp_dir,
                masker=masker,
                deadline=deadline,
            )
            self.db.set_run_commit_sha(run_id, commit_sha)
            self._append_system_step(
                run_id,
                step_id="checkout",
                step_name="Clone repository",
                status="passed",
                exit_code=0,
                text=f"Checked out commit {commit_sha}\n",
            )

            if self._is_cancelled(run_id):
                raise _RunCancelled()

            # Step 2: Apply overlay and/or replacement workflow
            workflow_arg = self._apply_overlay_and_workflow(
                run_row=run_row,
                workspace_dir=workspace_dir,
                run_tmp_dir=run_tmp_dir,
            )

            # Step 3: Run nektos/act against the slot's Docker daemon
            act_rc = await self._invoke_act(
                run_id=run_id,
                repo_row=repo_row,
                run_row=run_row,
                secrets_dict=secrets_dict,
                workspace_dir=workspace_dir,
                run_tmp_dir=run_tmp_dir,
                workflow_arg=workflow_arg,
                masker=masker,
                deadline=deadline,
            )

            if self._is_cancelled(run_id):
                raise _RunCancelled()

            if act_rc == 0:
                final_status = "passed"
                final_exit_code = 0
            else:
                final_status = "failed"
                final_exit_code = act_rc
                final_error = f"act exited with code {act_rc}"

        except _RunCancelled:
            final_status = "cancelled"
            final_exit_code = -1
            final_error = "Run cancelled"
            self._append_system_step(
                run_id,
                step_id="lifecycle",
                step_name="Run cancelled",
                status="cancelled",
                text="Cancellation requested; stopping containers.\n",
            )
        except _RunTimedOut:
            final_status = "timed_out"
            final_exit_code = -1
            final_error = f"Run exceeded timeout of {timeout_seconds}s"
            self._append_system_step(
                run_id,
                step_id="lifecycle",
                step_name="Run timed out",
                status="cancelled",
                text=f"Run killed after exceeding timeout ({timeout_seconds}s).\n",
            )
        except _CloneFailed as exc:
            final_status = "failed"
            final_exit_code = exc.exit_code
            final_error = masker.mask(str(exc))
            self._append_system_step(
                run_id,
                step_id="checkout",
                step_name="Clone repository",
                status="failed",
                exit_code=exc.exit_code,
                text=masker.mask(f"{exc}\n"),
            )
        except Exception as exc:
            final_status = "failed"
            final_exit_code = 1
            final_error = masker.mask(str(exc))
            self._append_system_step(
                run_id,
                step_id="lifecycle",
                step_name="Runner error",
                status="failed",
                exit_code=1,
                text=masker.mask(f"Runner error: {exc}\n"),
            )
        finally:
            # Always clean temporary credentials/secrets, workspace, and slot containers!
            shutil.rmtree(run_tmp_dir, ignore_errors=True)
            shutil.rmtree(workspace_dir, ignore_errors=True)
            await self._cleanup_slot_daemon_containers(ignore_errors=True)

        self.db.finish_run(
            run_id,
            status=final_status,
            exit_code=final_exit_code,
            error_message=masker.mask(final_error) if final_error else None,
        )
        await self._deliver_callback(
            run_row.get("callback_url"), run_id, final_status
        )

    def _is_cancelled(self, run_id: str) -> bool:
        if self._cancel_active_event.is_set():
            return True
        fresh = self.db.get_run(run_id)
        return bool(fresh and fresh.get("cancel_requested"))

    def _append_system_step(
        self,
        run_id: str,
        *,
        step_id: str,
        step_name: str,
        status: str,
        exit_code: int | None = None,
        text: str = "",
    ) -> None:
        self.db.upsert_step_log(
            run_id,
            job_id="__system__",
            job_name="System",
            step_id=step_id,
            step_name=step_name,
            stage="Pre",
            status=status,
            exit_code=exit_code,
            append_text=text,
            timestamp=utc_now_iso(),
        )

    async def _clone_and_checkout(
        self,
        *,
        run_id: str,
        git_url: str,
        requested_ref: str,
        credential_type: str,
        credential: str,
        workspace_dir: Path,
        run_tmp_dir: Path,
        masker: SecretMasker,
        deadline: float,
    ) -> str:
        git_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(run_tmp_dir),
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C.UTF-8",
        }

        if credential_type == "token" and credential:
            cred_file = run_tmp_dir / "git-token"
            cred_file.write_text(credential, encoding="utf-8")
            cred_file.chmod(0o600)
            askpass_script = run_tmp_dir / "git-askpass.sh"
            askpass_script.write_text(
                "#!/bin/sh\n"
                'case "$1" in\n'
                '  *Username*|*username*) printf "%s\\n" "x-access-token" ;;\n'
                f'  *) cat {shlex.quote(str(cred_file))} ;;\n'
                "esac\n",
                encoding="utf-8",
            )
            askpass_script.chmod(0o700)
            git_env["GIT_ASKPASS"] = str(askpass_script)
        elif credential_type == "deploy_key" and credential:
            key_file = run_tmp_dir / "deploy_key"
            key_text = credential if credential.endswith("\n") else credential + "\n"
            key_file.write_text(key_text, encoding="utf-8")
            key_file.chmod(0o600)
            git_env["GIT_SSH_COMMAND"] = (
                f"ssh -i {shlex.quote(str(key_file))} "
                "-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
            )

        git = self.settings.git_binary

        await self._exec_git([git, "init", "--quiet"], workspace_dir, git_env, masker, deadline, run_id)
        await self._exec_git(
            [git, "remote", "add", "origin", git_url],
            workspace_dir,
            git_env,
            masker,
            deadline,
            run_id,
        )

        if requested_ref == "HEAD":
            await self._exec_git(
                [git, "fetch", "--depth=1", "origin", "HEAD"],
                workspace_dir,
                git_env,
                masker,
                deadline,
                run_id,
            )
            await self._exec_git(
                [git, "checkout", "--detach", "FETCH_HEAD"],
                workspace_dir,
                git_env,
                masker,
                deadline,
                run_id,
            )
        else:
            # For local directory paths (e.g. fixture repos), full fetch ensures non-tip
            # commit SHAs work across all git uploadpack.allowReachableSHA1InWant defaults.
            is_local_repo = git_url.startswith("/") or git_url.startswith("file://")
            rc = 1
            out = ""
            if not is_local_repo:
                rc, out = await self._exec_git_allow_fail(
                    [git, "fetch", "--depth=1", "origin", requested_ref],
                    workspace_dir,
                    git_env,
                    deadline,
                    run_id,
                )
            if rc == 0:
                await self._exec_git(
                    [git, "checkout", "--detach", "FETCH_HEAD"],
                    workspace_dir,
                    git_env,
                    masker,
                    deadline,
                    run_id,
                )
            else:
                await self._exec_git(
                    [git, "fetch", "--tags", "origin"],
                    workspace_dir,
                    git_env,
                    masker,
                    deadline,
                    run_id,
                )
                # Try requested_ref directly (commit SHA or tag) or origin/<branch>
                rc_co, out_co = await self._exec_git_allow_fail(
                    [git, "checkout", "--detach", requested_ref],
                    workspace_dir,
                    git_env,
                    deadline,
                    run_id,
                )
                if rc_co != 0:
                    rc_br, out_br = await self._exec_git_allow_fail(
                        [git, "checkout", "--detach", f"origin/{requested_ref}"],
                        workspace_dir,
                        git_env,
                        deadline,
                        run_id,
                    )
                    if rc_br != 0:
                        # Last resort: direct fetch of exact SHA with allowanysha1
                        rc_sha, out_sha = await self._exec_git_allow_fail(
                            [git, "fetch", "origin", requested_ref],
                            workspace_dir,
                            git_env,
                            deadline,
                            run_id,
                        )
                        if rc_sha == 0:
                            await self._exec_git(
                                [git, "checkout", "--detach", "FETCH_HEAD"],
                                workspace_dir,
                                git_env,
                                masker,
                                deadline,
                                run_id,
                            )
                        else:
                            raise _CloneFailed(
                                rc_co,
                                masker.mask(
                                    f"Failed to checkout ref '{requested_ref}': {out_co.strip() or out.strip()}"
                                ),
                            )

        sha_out = await self._exec_git(
            [git, "rev-parse", "HEAD"],
            workspace_dir,
            git_env,
            masker,
            deadline,
            run_id,
        )
        commit_sha = sha_out.strip()
        # Attach a local branch so nektos/act can always resolve GITHUB_REF (even when
        # requested_ref was a raw commit SHA rather than a branch/tag name).
        branch_name = (
            requested_ref
            if re.match(r"^[A-Za-z0-9._-]+$", requested_ref)
            and requested_ref != commit_sha
            else "act-ci"
        )
        await self._exec_git(
            [git, "checkout", "-B", branch_name, commit_sha],
            workspace_dir,
            git_env,
            masker,
            deadline,
            run_id,
        )
        # Wipe credentials from run_tmp_dir immediately after git clone completes!
        for p in run_tmp_dir.iterdir():
            if p.is_file():
                p.unlink(missing_ok=True)
        return commit_sha

    async def _exec_git_allow_fail(
        self,
        cmd: list[str],
        cwd: Path,
        env: dict[str, str],
        deadline: float,
        run_id: str,
    ) -> tuple[int, str]:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise _RunTimedOut()
        if self._is_cancelled(run_id):
            raise _RunCancelled()

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=remaining
            )
            return int(proc.returncode or 0), stdout_bytes.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            await self._terminate_process_group(proc)
            raise _RunTimedOut()

    async def _exec_git(
        self,
        cmd: list[str],
        cwd: Path,
        env: dict[str, str],
        masker: SecretMasker,
        deadline: float,
        run_id: str,
    ) -> str:
        rc, out = await self._exec_git_allow_fail(cmd, cwd, env, deadline, run_id)
        if rc != 0:
            raise _CloneFailed(rc, masker.mask(out.strip() or f"git exited with {rc}"))
        return out

    def _apply_overlay_and_workflow(
        self,
        *,
        run_row: dict[str, Any],
        workspace_dir: Path,
        run_tmp_dir: Path,
    ) -> str | None:
        """Apply overlay files onto workspace and prepare -W workflow argument if needed."""
        ws_real = workspace_dir.resolve()
        payload: dict[str, Any] = {}
        if run_row.get("encrypted_payload"):
            payload = json.loads(
                self.secret_box.decrypt_str(run_row["encrypted_payload"])
            )

        overlay = payload.get("overlay")
        if isinstance(overlay, dict):
            for rel_path, content in overlay.items():
                norm_rel = validate_relative_workspace_path(str(rel_path))
                # Reject symlinks anywhere along parent chain inside the cloned repo
                current = workspace_dir
                for part in norm_rel.split("/")[:-1]:
                    current = current / part
                    if current.is_symlink():
                        raise RuntimeError(
                            f"Refusing to write overlay through symlink: {norm_rel}"
                        )
                target = workspace_dir / norm_rel
                if target.is_symlink():
                    target.unlink()
                target.parent.mkdir(parents=True, exist_ok=True)
                resolved_parent = target.parent.resolve()
                if resolved_parent != ws_real and ws_real not in resolved_parent.parents:
                    raise RuntimeError(f"Overlay path escaped workspace: {norm_rel}")
                target.write_text(str(content), encoding="utf-8")

        replacement_wf = payload.get("replacement_workflow")
        if replacement_wf:
            # Write replacement workflow into .github/workflows override and mark git-ignored
            dot_github = workspace_dir / ".github"
            wf_dir = dot_github / "workflows"
            if dot_github.is_symlink() or wf_dir.is_symlink():
                raise RuntimeError("Refusing to write workflow into symlinked .github/workflows")
            wf_dir.mkdir(parents=True, exist_ok=True)
            override_rel = ".github/workflows/__act_ci_replacement__.yml"
            override_path = workspace_dir / override_rel
            if override_path.is_symlink():
                override_path.unlink()
            override_path.write_text(str(replacement_wf), encoding="utf-8")

            git_exclude = workspace_dir / ".git" / "info" / "exclude"
            if git_exclude.parent.is_dir() and not git_exclude.is_symlink():
                existing_excl = (
                    git_exclude.read_text(encoding="utf-8")
                    if git_exclude.exists()
                    else ""
                )
                marker_line = f"/{override_rel}"
                if marker_line not in existing_excl.splitlines():
                    prefix = (
                        ""
                        if (not existing_excl or existing_excl.endswith("\n"))
                        else "\n"
                    )
                    git_exclude.write_text(
                        f"{existing_excl}{prefix}{marker_line}\n",
                        encoding="utf-8",
                    )
            return override_rel

        if run_row.get("workflow_path"):
            norm_wf = validate_relative_workspace_path(str(run_row["workflow_path"]))
            wf_target = (workspace_dir / norm_wf).resolve()
            if wf_target != ws_real and ws_real not in wf_target.parents:
                raise RuntimeError(f"Workflow path escaped workspace: {norm_wf}")
            return norm_wf

        return None

    def build_act_command(
        self,
        *,
        default_image: str,
        event_name: str | None,
        workflow_arg: str | None,
        workspace_dir: Path,
        secret_file: Path,
    ) -> list[str]:
        """Build nektos/act v0.2.98 invocation using verified flags only (copy mode, JSON output)."""
        cmd: list[str] = [self.settings.act_binary]
        if event_name:
            cmd.append(event_name)
        cmd.extend(
            [
                "-C",
                str(workspace_dir),
                "--json",
                "--rm",
                "--no-cache-server",
                "--action-cache-path",
                str(self.slot.cache_dir / "actions"),
                "--container-daemon-socket",
                "-",
                "--secret-file",
                str(secret_file),
            ]
        )
        for label in ACT_PLATFORM_LABELS:
            cmd.extend(["-P", f"{label}={default_image}"])
        if workflow_arg:
            cmd.extend(["-W", workflow_arg])
        return cmd

    async def _invoke_act(
        self,
        *,
        run_id: str,
        repo_row: dict[str, Any],
        run_row: dict[str, Any],
        secrets_dict: dict[str, str],
        workspace_dir: Path,
        run_tmp_dir: Path,
        workflow_arg: str | None,
        masker: SecretMasker,
        deadline: float,
    ) -> int:
        secret_file = run_tmp_dir / "act.secrets"
        lines = [
            f"{k}={_escape_secret_file_value(v)}"
            for k, v in sorted(secrets_dict.items())
        ]
        fd = os.open(str(secret_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"))
        finally:
            os.close(fd)

        cmd = self.build_act_command(
            default_image=repo_row["default_image"],
            event_name=run_row.get("event_name"),
            workflow_arg=workflow_arg,
            workspace_dir=workspace_dir,
            secret_file=secret_file,
        )

        act_home = run_tmp_dir / "act-home"
        act_home.mkdir(parents=True, exist_ok=True)
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(act_home),
            "XDG_CACHE_HOME": str(self.slot.cache_dir),
            "XDG_CONFIG_HOME": str(act_home / ".config"),
            "DOCKER_HOST": self.slot.docker_host,
            "ACT_CONTAINER_DAEMON_SOCKET": "-",
            "LC_ALL": "C.UTF-8",
        }

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(workspace_dir),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )

        async def _stream_stdout() -> None:
            assert proc.stdout is not None
            loop = asyncio.get_running_loop()
            pending_key: tuple[str, str, str] | None = None
            pending_meta: dict[str, Any] = {}
            pending_chunks: list[str] = []
            last_flush = loop.time()

            flush_timer: asyncio.TimerHandle | None = None

            def _cancel_flush_timer() -> None:
                nonlocal flush_timer
                if flush_timer is not None:
                    flush_timer.cancel()
                    flush_timer = None

            def _flush_pending() -> None:
                nonlocal pending_key, pending_meta, pending_chunks, last_flush
                _cancel_flush_timer()
                if pending_key is None or not pending_chunks:
                    pending_key = None
                    pending_chunks = []
                    return
                self.db.upsert_step_log(
                    run_id,
                    job_id=pending_meta["job_id"],
                    job_name=pending_meta["job_name"],
                    step_id=pending_meta["step_id"],
                    step_name=pending_meta["step_name"],
                    stage=pending_meta["stage"],
                    status=None,
                    exit_code=None,
                    append_text="".join(pending_chunks),
                    timestamp=pending_meta.get("timestamp"),
                )
                pending_key = None
                pending_chunks = []
                last_flush = loop.time()

            def _schedule_flush() -> None:
                nonlocal flush_timer
                if flush_timer is None:
                    flush_timer = loop.call_later(0.1, _flush_pending)

            try:
                while True:
                    raw_line = await proc.stdout.readline()
                    if not raw_line:
                        break
                    decoded = raw_line.decode("utf-8", errors="replace")
                    parsed = parse_act_json_line(decoded)
                    if parsed is not None:
                        mapped = map_act_json_event(parsed)
                        if mapped["append_text"] or mapped["status"]:
                            job_name_m = masker.mask(mapped["job_name"])
                            step_name_m = masker.mask(mapped["step_name"])
                            text_m = masker.mask(mapped["append_text"])
                            key = (mapped["job_id"], mapped["step_id"], mapped["stage"])
                            if mapped["status"] is not None:
                                if pending_key == key and pending_chunks:
                                    _cancel_flush_timer()
                                    text_m = "".join(pending_chunks) + text_m
                                    pending_key = None
                                    pending_chunks = []
                                else:
                                    _flush_pending()
                                self.db.upsert_step_log(
                                    run_id,
                                    job_id=mapped["job_id"],
                                    job_name=job_name_m,
                                    step_id=mapped["step_id"],
                                    step_name=step_name_m,
                                    stage=mapped["stage"],
                                    status=mapped["status"],
                                    exit_code=mapped["exit_code"],
                                    append_text=text_m,
                                    timestamp=mapped["timestamp"],
                                )
                                last_flush = loop.time()
                            elif text_m:
                                if pending_key is not None and pending_key != key:
                                    _flush_pending()
                                if pending_key is None:
                                    pending_key = key
                                    pending_meta = {
                                        "job_id": mapped["job_id"],
                                        "job_name": job_name_m,
                                        "step_id": mapped["step_id"],
                                        "step_name": step_name_m,
                                        "stage": mapped["stage"],
                                        "timestamp": mapped["timestamp"],
                                    }
                                else:
                                    pending_meta["job_name"] = job_name_m
                                    pending_meta["step_name"] = step_name_m
                                pending_chunks.append(text_m)
                                if (
                                    len(pending_chunks) >= 64
                                    or (loop.time() - last_flush) >= 0.1
                                ):
                                    _flush_pending()
                                else:
                                    _schedule_flush()
                    else:
                        clean_line = masker.mask(decoded)
                        if clean_line.strip():
                            key = ("__act__", "output", "Main")
                            if pending_key is not None and pending_key != key:
                                _flush_pending()
                            if pending_key is None:
                                pending_key = key
                                pending_meta = {
                                    "job_id": "__act__",
                                    "job_name": "Runner",
                                    "step_id": "output",
                                    "step_name": "act output",
                                    "stage": "Main",
                                    "timestamp": None,
                                }
                            pending_chunks.append(
                                clean_line
                                if clean_line.endswith("\n")
                                else f"{clean_line}\n"
                            )
                            if (
                                len(pending_chunks) >= 64
                                or (loop.time() - last_flush) >= 0.1
                            ):
                                _flush_pending()
                            else:
                                _schedule_flush()
            finally:
                _cancel_flush_timer()
                _flush_pending()

        reader_task = asyncio.create_task(_stream_stdout())
        timed_out = False
        cancelled = False

        try:
            while proc.returncode is None:
                if self._is_cancelled(run_id):
                    cancelled = True
                    break
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    timed_out = True
                    break
                wait_slice = min(0.25, remaining)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=wait_slice)
                except asyncio.TimeoutError:
                    continue

            if cancelled or timed_out:
                await self._terminate_process_group(proc)
                await self._cleanup_slot_daemon_containers(ignore_errors=True)
        finally:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(reader_task, timeout=3.0)
            if not reader_task.done():
                reader_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reader_task

        if cancelled:
            raise _RunCancelled()
        if timed_out:
            raise _RunTimedOut()
        return int(proc.returncode or 0)

    async def _terminate_process_group(
        self, proc: asyncio.subprocess.Process
    ) -> None:
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()

        try:
            await asyncio.wait_for(proc.wait(), timeout=3.0)
            return
        except asyncio.TimeoutError:
            pass

        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except OSError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=2.0)

    async def _cleanup_slot_daemon_containers(self, *, ignore_errors: bool = True) -> None:
        """Stop & remove ALL containers, custom networks, and anonymous volumes on the dedicated slot daemon."""
        docker = self.settings.docker_binary
        if not shutil.which(docker):
            return
        rc, out = await self._run_short_cmd(
            [docker, "-H", self.slot.docker_host, "ps", "-aq"],
            timeout=15.0,
        )
        if rc == 0 and out.strip():
            container_ids = [cid.strip() for cid in out.splitlines() if cid.strip()]
            if container_ids:
                await self._run_short_cmd(
                    [docker, "-H", self.slot.docker_host, "rm", "-f", "-v", *container_ids],
                    timeout=30.0,
                )
        await self._run_short_cmd(
            [docker, "-H", self.slot.docker_host, "network", "prune", "-f"],
            timeout=15.0,
        )
        await self._run_short_cmd(
            [docker, "-H", self.slot.docker_host, "volume", "prune", "-f"],
            timeout=15.0,
        )

    async def _run_short_cmd(
        self, cmd: list[str], *, timeout: float = 15.0
    ) -> tuple[int, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return int(proc.returncode or 0), stdout_bytes.decode("utf-8", errors="replace")
        except Exception as exc:
            return 1, str(exc)

    @staticmethod
    def _clear_directory_children(root: Path) -> None:
        if not root.exists():
            return
        for child in root.iterdir():
            if child.is_dir() and not child.is_symlink():
                # Ensure read-only git packfiles can be deleted
                for dirpath, _, filenames in os.walk(child):
                    with contextlib.suppress(OSError):
                        os.chmod(dirpath, stat.S_IRWXU)
                    for fn in filenames:
                        with contextlib.suppress(OSError):
                            os.chmod(os.path.join(dirpath, fn), stat.S_IRWXU)
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)

    async def _deliver_callback(
        self, callback_url: str | None, run_id: str, status: str
    ) -> None:
        if not callback_url:
            return
        payload = {"run_id": run_id, "status": status}
        allow_loopback = self.settings.allow_loopback_callbacks
        try:
            validate_callback_url(callback_url, allow_loopback=allow_loopback)
            parsed = urlparse(callback_url)
            hostname = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            addr_infos = await asyncio.get_running_loop().getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            )
            if not addr_infos:
                raise ValueError(f"Could not resolve callback host '{hostname}'")
            for info in addr_infos:
                raw_ip = info[4][0]
                ip_obj = ipaddress.ip_address(raw_ip.split("%", 1)[0])
                if is_disallowed_callback_ip(ip_obj, allow_loopback=allow_loopback):
                    raise ValueError(
                        f"Refusing callback to disallowed address {ip_obj}"
                    )
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                resp = await client.post(callback_url, json=payload)
                self.db.set_callback_status(run_id, f"http_{resp.status_code}")
        except Exception as exc:
            logger.warning("Callback delivery failed for %s: %s", run_id, exc)
            self.db.set_callback_status(run_id, "delivery_failed")


class _RunCancelled(Exception):
    pass


class _RunTimedOut(Exception):
    pass


class _CloneFailed(Exception):
    def __init__(self, exit_code: int, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
