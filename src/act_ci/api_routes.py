"""Bearer-authenticated REST API routes (/api/v1/*)."""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from act_ci.models import (
    RepoPublicView,
    RunLogsResponse,
    RunPublicView,
    TriggerRunRequest,
)
from act_ci.service import CiService

api_router = APIRouter(prefix="/api/v1", tags=["api"])


def _svc(request: Request) -> CiService:
    return request.app.state.service


@api_router.get("/repos", response_model=list[RepoPublicView])
async def api_list_repos(request: Request) -> list[RepoPublicView]:
    svc = _svc(request)
    principal = svc.authenticate_bearer(
        request.headers.get("authorization"),
        source="api",
        attempted_action="repos.list",
    )
    return svc.list_repos(principal)


@api_router.post("/runs", response_model=RunPublicView, status_code=201)
async def api_trigger_run(
    payload: TriggerRunRequest,
    request: Request,
) -> RunPublicView:
    svc = _svc(request)
    principal = svc.authenticate_bearer(
        request.headers.get("authorization"),
        source="api",
        attempted_action="runs.trigger",
        repo_name=payload.repo,
    )
    return svc.trigger_run(principal, payload)


@api_router.get("/runs", response_model=list[RunPublicView])
async def api_list_runs(
    request: Request,
    repo: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[RunPublicView]:
    svc = _svc(request)
    principal = svc.authenticate_bearer(
        request.headers.get("authorization"),
        source="api",
        attempted_action="runs.list",
        repo_name=repo,
    )
    return svc.list_runs(principal, repo=repo, status=status, limit=limit)


@api_router.get("/runs/{run_id}", response_model=RunPublicView)
async def api_get_run(run_id: str, request: Request) -> RunPublicView:
    svc = _svc(request)
    principal = svc.authenticate_bearer(
        request.headers.get("authorization"),
        source="api",
        attempted_action="runs.get",
        run_id=run_id,
    )
    return svc.get_run_status(principal, run_id)


@api_router.get("/runs/{run_id}/logs", response_model=RunLogsResponse)
async def api_get_run_logs(run_id: str, request: Request) -> RunLogsResponse:
    svc = _svc(request)
    principal = svc.authenticate_bearer(
        request.headers.get("authorization"),
        source="api",
        attempted_action="runs.logs",
        run_id=run_id,
    )
    return svc.get_run_logs(principal, run_id)


@api_router.post("/runs/{run_id}/cancel", response_model=RunPublicView)
async def api_cancel_run(run_id: str, request: Request) -> RunPublicView:
    svc = _svc(request)
    principal = svc.authenticate_bearer(
        request.headers.get("authorization"),
        source="api",
        attempted_action="runs.cancel",
        run_id=run_id,
    )
    return svc.cancel_run(principal, run_id)
