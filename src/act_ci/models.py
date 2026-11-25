"""Pydantic models and exceptions for Act-CI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, Field

RoleType = Literal["operator", "viewer"]
ActorRole = Literal["admin", "operator", "viewer"]


class ApiError(Exception):
    def __init__(self, status_code: int, detail: str, audit_result: str | None = None) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.audit_result = audit_result or f"error:{status_code}"


class UnauthorizedError(ApiError):
    def __init__(self, detail: str = "Missing, invalid, or revoked bearer token") -> None:
        super().__init__(401, detail, "unauthorized")


class ForbiddenError(ApiError):
    def __init__(self, detail: str = "Insufficient permissions for this action") -> None:
        super().__init__(403, detail, "denied")


class NotFoundError(ApiError):
    def __init__(self, detail: str = "Resource not found") -> None:
        super().__init__(404, detail, "not_found")


class ValidationApiError(ApiError):
    def __init__(self, detail: str) -> None:
        super().__init__(422, detail, "invalid_request")


@dataclass(frozen=True)
class Principal:
    role: ActorRole
    token_id: int | None
    token_name: str
    source: Literal["admin", "api", "mcp"]


class TriggerRunRequest(BaseModel):
    repo: str = Field(..., min_length=1, max_length=128)
    ref: str = Field(default="HEAD", min_length=1, max_length=256)
    workflow: str | None = Field(default=None, max_length=512)
    event: str | None = Field(default=None, max_length=64)
    overlay: dict[str, str] | None = Field(
        default=None,
        description="Map of workspace-relative file paths to UTF-8 text contents.",
    )
    replacement_workflow: str | None = Field(
        default=None,
        description="Complete YAML content replacing the repository's workflows for this run.",
    )
    private: bool = Field(default=False)
    callback_url: str | None = Field(default=None, max_length=2048)


class RepoPublicView(BaseModel):
    name: str
    git_url: str
    credential_type: str
    has_credential: bool
    default_image: str
    timeout_seconds: int
    created_at: str
    updated_at: str


class RunPublicView(BaseModel):
    id: str
    repo: str
    ref: str
    commit_sha: str | None
    workflow: str | None
    event: str | None
    private: bool
    has_overlay: bool | None = None
    has_replacement_workflow: bool | None = None
    overlay_files: list[str] | None = None
    status: str
    exit_code: int | None
    error_message: str | None = None
    created_at: str
    started_at: str | None
    finished_at: str | None
    duration_seconds: float | None
    triggered_by: str | None = None


class StepLogView(BaseModel):
    job_id: str
    job_name: str
    step_id: str
    step_name: str
    stage: str
    status: str
    exit_code: int | None
    started_at: str | None
    finished_at: str | None
    log: str


class JobLogGroupView(BaseModel):
    job_id: str
    job_name: str
    status: str
    steps: list[StepLogView]


class RunLogsResponse(BaseModel):
    run_id: str
    repo: str
    status: str
    private: bool
    jobs: list[JobLogGroupView]
    raw_log: str
