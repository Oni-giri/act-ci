"""Server-rendered Admin Web UI routes (protected by Umbrel's app_proxy login)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from act_ci.config import DEFAULT_RUNNER_IMAGE, DEFAULT_TIMEOUT_SECONDS
from act_ci.db import VALID_RUN_STATUSES
from act_ci.models import (
    ApiError,
    ForbiddenError,
    Principal,
    TriggerRunRequest,
)
from act_ci.security import CSRF_COOKIE_NAME, CsrfSigner
from act_ci.service import CiService

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

PROJECT_PALETTE = (
    "var(--project-sky)",
    "var(--project-pink)",
    "var(--project-amber)",
)

def _require_admin_ui(request: Request) -> None:
    """Reject any request carrying an Authorization bearer header on admin/UI routes."""
    auth = request.headers.get("authorization")
    if auth:
        # Also record attempted bearer access against admin UI in audit log if token is parseable
        svc: CiService = request.app.state.service
        try:
            p = svc.authenticate_bearer(
                auth,
                source="api",
                attempted_action=f"admin.rejected:{request.method}:{request.url.path}",
            )
            svc.db.append_audit(
                source="api",
                token_id=p.token_id,
                token_name=p.token_name,
                role=p.role,
                action=f"admin.rejected:{request.method}:{request.url.path}",
                result="denied:admin_route_forbids_bearer",
            )
        except ApiError:
            pass
        raise ForbiddenError("Bearer tokens cannot access admin UI routes")


ui_router = APIRouter(tags=["ui"], dependencies=[Depends(_require_admin_ui)])

ADMIN_PRINCIPAL = Principal(
    role="admin",
    token_id=None,
    token_name="admin-ui",
    source="admin",
)


def _effective_request_host(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-host")
    if forwarded:
        return forwarded.split(",", 1)[0].strip().lower()
    host = request.headers.get("host")
    if host:
        return host.strip().lower()
    return request.url.netloc.lower()


def _verify_same_origin_headers(request: Request) -> None:
    """Enforce Origin / Referer host match on state-changing requests when present."""
    expected_host = _effective_request_host(request)
    if not expected_host:
        return

    origin = request.headers.get("origin")
    if origin:
        if origin.strip().lower() == "null":
            raise ForbiddenError("Cross-origin request rejected (null Origin)")
        parsed = urlparse(origin.strip())
        if not parsed.netloc or parsed.netloc.lower() != expected_host:
            raise ForbiddenError("Cross-origin request rejected (Origin mismatch)")
        return

    referer = request.headers.get("referer")
    if referer:
        parsed = urlparse(referer.strip())
        if not parsed.netloc or parsed.netloc.lower() != expected_host:
            raise ForbiddenError("Cross-origin request rejected (Referer mismatch)")


def _require_csrf(request: Request, csrf_token: str | None) -> None:
    _verify_same_origin_headers(request)
    signer: CsrfSigner = request.app.state.csrf
    session_id = request.cookies.get(CSRF_COOKIE_NAME) or ""
    if not CsrfSigner.is_valid_session_id(session_id):
        raise ForbiddenError("Invalid or missing CSRF session cookie")
    if not signer.verify(csrf_token, session_id=session_id):
        raise ForbiddenError("Invalid or missing CSRF token")


def _shell_counts_and_repos(svc: CiService) -> dict[str, Any]:
    raw_repos = svc.db.list_repos()
    all_runs = svc.db.list_runs(limit=500)
    run_counts_by_repo: dict[str, int] = {}
    status_counts: dict[str, int] = {s: 0 for s in VALID_RUN_STATUSES}
    for r in all_runs:
        rname = r["repo_name"]
        run_counts_by_repo[rname] = run_counts_by_repo.get(rname, 0) + 1
        st = r["status"]
        if st in status_counts:
            status_counts[st] += 1

    sidebar_repos = []
    for idx, repo in enumerate(raw_repos):
        sidebar_repos.append(
            {
                "id": repo["id"],
                "name": repo["name"],
                "color": PROJECT_PALETTE[idx % len(PROJECT_PALETTE)],
                "run_count": run_counts_by_repo.get(repo["name"], 0),
            }
        )

    tokens = svc.db.list_tokens()
    active_token_count = sum(1 for t in tokens if not t["revoked_at"])
    recent_audits = svc.db.list_audit_logs(limit=200)
    denied_audit_count = sum(
        1
        for a in recent_audits
        if a["result"].startswith(("denied", "unauthorized"))
    )

    return {
        "sidebar_repos": sidebar_repos,
        "nav_runs_count": len(all_runs),
        "nav_repos_count": len(raw_repos),
        "nav_tokens_count": active_token_count,
        "nav_denied_count": denied_audit_count,
        "all_status_counts": status_counts,
        "all_runs_total": len(all_runs),
    }


def _render_template(
    request: Request,
    template_name: str,
    active_nav: str,
    *,
    status_code: int = 200,
    **extra: Any,
) -> HTMLResponse:
    svc: CiService = request.app.state.service
    signer: CsrfSigner = request.app.state.csrf
    existing_sid = request.cookies.get(CSRF_COOKIE_NAME)
    if CsrfSigner.is_valid_session_id(existing_sid):
        session_id = existing_sid  # type: ignore[assignment]
        needs_cookie = False
    else:
        session_id = signer.generate_session_id()
        needs_cookie = True

    ctx: dict[str, Any] = {
        "request": request,
        "active_nav": active_nav,
        "csrf_token": signer.issue(session_id=session_id),
    }
    ctx.update(_shell_counts_and_repos(svc))
    ctx.update(extra)
    resp = templates.TemplateResponse(request, template_name, ctx, status_code=status_code)
    if needs_cookie:
        is_https = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
            == "https"
        )
        resp.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=session_id,
            max_age=signer.ttl_seconds,
            httponly=True,
            samesite="lax",
            secure=is_https,
            path="/",
        )
    return resp


def _unquote_dotenv_value(raw_val: str) -> str:
    val = raw_val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        quote = val[0]
        inner = val[1:-1]
        if quote == "'":
            return inner
        # Unescape standard double-quoted dotenv sequences
        out_chars: list[str] = []
        i = 0
        while i < len(inner):
            ch = inner[i]
            if ch == "\\" and i + 1 < len(inner):
                nxt = inner[i + 1]
                if nxt == "n":
                    out_chars.append("\n")
                elif nxt == "r":
                    out_chars.append("\r")
                elif nxt == "t":
                    out_chars.append("\t")
                elif nxt in ('"', "\\", "$"):
                    out_chars.append(nxt)
                else:
                    out_chars.append(ch)
                    out_chars.append(nxt)
                i += 2
            else:
                out_chars.append(ch)
                i += 1
        return "".join(out_chars)
    return val


def _parse_dotenv_secrets(raw_text: str) -> dict[str, str]:
    """Parse KEY=VALUE lines submitted from the repo secrets textarea."""
    out: dict[str, str] = {}
    for idx, line in enumerate(raw_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            line = stripped[len("export ") :]
        if "=" not in line:
            raise ApiError(
                422,
                f"Invalid secret entry on line {idx}: expected KEY=VALUE",
                "invalid_request",
            )
        key, val = line.split("=", 1)
        out[key.strip()] = _unquote_dotenv_value(val)
    return out


# ---- Static Assets & Health Check (Admin/Internal, behind Umbrel login) ----


@ui_router.get("/ui-assets/{asset_path:path}")
async def ui_static_asset(asset_path: str, request: Request) -> Response:
    _require_admin_ui(request)
    static_root = STATIC_DIR.resolve()
    candidate = (static_root / asset_path).resolve()
    if (
        candidate == static_root
        or static_root not in candidate.parents
        or not candidate.is_file()
    ):
        return Response(status_code=404)
    return FileResponse(candidate)


@ui_router.get("/healthz")
async def healthz(request: Request) -> JSONResponse:
    _require_admin_ui(request)
    return JSONResponse({"status": "ok"})


# ---- Runs List & Trigger ----


@ui_router.get("/", response_class=HTMLResponse)
@ui_router.get("/runs", response_class=HTMLResponse)
async def ui_runs_list(
    request: Request,
    repo: str | None = Query(default=None),
    status: str | None = Query(default=None),
    flash: str | None = Query(default=None),
) -> HTMLResponse:
    _require_admin_ui(request)
    svc: CiService = request.app.state.service
    repos = svc.list_repos(ADMIN_PRINCIPAL)
    clean_repo = repo.strip() if repo and repo.strip() else None
    clean_status = (
        status.strip()
        if status and status.strip() in VALID_RUN_STATUSES
        else None
    )
    runs = svc.list_runs(
        ADMIN_PRINCIPAL, repo=clean_repo, status=clean_status, limit=100
    )
    repo_scoped_runs = svc.list_runs(
        ADMIN_PRINCIPAL, repo=clean_repo, status=None, limit=200
    )
    tab_counts: dict[str, int] = {s: 0 for s in VALID_RUN_STATUSES}
    for r in repo_scoped_runs:
        if r.status in tab_counts:
            tab_counts[r.status] += 1
    attention_runs = (
        []
        if clean_status
        else [
            r
            for r in repo_scoped_runs
            if r.status in ("running", "queued", "failed", "timed_out")
        ][:4]
    )

    step_summaries: dict[str, dict[str, int]] = {}
    for r in runs:
        steps = svc.db.list_run_steps(r.id)
        passed_n = sum(1 for s in steps if s["status"] == "passed")
        failed_n = sum(1 for s in steps if s["status"] == "failed")
        total_n = len(steps)
        step_summaries[r.id] = {
            "passed": passed_n,
            "failed": failed_n,
            "total": total_n,
        }

    return _render_template(
        request,
        "runs.html",
        "runs",
        runs=runs,
        repos=repos,
        selected_repo=clean_repo or "",
        selected_status=clean_status or "",
        statuses=VALID_RUN_STATUSES,
        tab_counts=tab_counts,
        tab_total=len(repo_scoped_runs),
        attention_runs=attention_runs,
        step_summaries=step_summaries,
        flash=flash,
    )


@ui_router.post("/runs/trigger")
async def ui_trigger_run(
    request: Request,
    csrf_token: str = Form(default=""),
    repo: str = Form(...),
    ref: str = Form(default="HEAD"),
    workflow: str = Form(default=""),
    event: str = Form(default=""),
    private: str | None = Form(default=None),
) -> Response:
    _require_admin_ui(request)
    _require_csrf(request, csrf_token)
    svc: CiService = request.app.state.service
    req = TriggerRunRequest(
        repo=repo.strip(),
        ref=ref.strip() or "HEAD",
        workflow=workflow.strip() or None,
        event=event.strip() or None,
        private=bool(private),
    )
    run = svc.trigger_run(ADMIN_PRINCIPAL, req)
    return RedirectResponse(url=f"/runs/{run.id}", status_code=303)


@ui_router.get("/runs/{run_id}", response_class=HTMLResponse)
async def ui_run_detail(run_id: str, request: Request) -> HTMLResponse:
    _require_admin_ui(request)
    svc: CiService = request.app.state.service
    run = svc.get_run_status(ADMIN_PRINCIPAL, run_id)
    logs = svc.get_run_logs(ADMIN_PRINCIPAL, run_id)
    overlay_info = svc.get_run_private_overlay_admin_or_operator(ADMIN_PRINCIPAL, run_id)
    return _render_template(
        request,
        "run_detail.html",
        "runs",
        run=run,
        logs=logs,
        overlay_info=overlay_info,
    )


@ui_router.get("/runs/{run_id}/live")
async def ui_run_live_fragment(run_id: str, request: Request) -> JSONResponse:
    """Admin-only JSON endpoint polled by the Run Detail page while a run is queued or running."""
    _require_admin_ui(request)
    svc: CiService = request.app.state.service
    run = svc.get_run_status(ADMIN_PRINCIPAL, run_id)
    logs = svc.get_run_logs(ADMIN_PRINCIPAL, run_id)
    return JSONResponse(
        {
            "run": run.model_dump(),
            "jobs": [j.model_dump() for j in logs.jobs],
        }
    )


@ui_router.post("/runs/{run_id}/cancel")
async def ui_cancel_run(
    run_id: str,
    request: Request,
    csrf_token: str = Form(default=""),
) -> Response:
    _require_admin_ui(request)
    _require_csrf(request, csrf_token)
    svc: CiService = request.app.state.service
    svc.cancel_run(ADMIN_PRINCIPAL, run_id)
    return RedirectResponse(url=f"/runs/{run_id}", status_code=303)


# ---- Repos Page ----


@ui_router.get("/repos", response_class=HTMLResponse)
async def ui_repos_page(
    request: Request,
    edit: int | None = Query(default=None),
    flash: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> HTMLResponse:
    _require_admin_ui(request)
    svc: CiService = request.app.state.service
    raw_repos = svc.db.list_repos()
    repo_items = []
    edit_repo: dict[str, Any] | None = None
    for r in raw_repos:
        sec_keys = json.loads(r.get("secret_keys_json") or "[]")
        item = {
            "id": r["id"],
            "name": r["name"],
            "git_url": r["git_url"],
            "credential_type": r["credential_type"],
            "has_credential": bool(r["encrypted_credential"]),
            "default_image": r["default_image"],
            "timeout_seconds": r["timeout_seconds"],
            "secret_keys": sec_keys,
            "updated_at": r["updated_at"],
        }
        repo_items.append(item)
        if edit is not None and r["id"] == edit:
            edit_repo = item

    return _render_template(
        request,
        "repos.html",
        "repos",
        repos=repo_items,
        edit_repo=edit_repo,
        default_image=DEFAULT_RUNNER_IMAGE,
        default_timeout=DEFAULT_TIMEOUT_SECONDS,
        global_credential=svc.get_global_git_credential_status(),
        flash=flash,
        error=error,
    )


@ui_router.post("/repos/git-credential")
async def ui_set_global_git_credential(
    request: Request,
    csrf_token: str = Form(default=""),
    git_credential_type: str = Form(default="token"),
    git_credential_value: str = Form(default=""),
) -> Response:
    _require_admin_ui(request)
    _require_csrf(request, csrf_token)
    svc: CiService = request.app.state.service
    from urllib.parse import quote_plus

    try:
        svc.set_global_git_credential_admin(
            credential_type=git_credential_type,
            credential_value=git_credential_value,
        )
        return RedirectResponse(
            url="/repos?flash=Global+Git+connection+saved", status_code=303
        )
    except ApiError as exc:
        return RedirectResponse(
            url=f"/repos?error={quote_plus(exc.detail)}", status_code=303
        )


@ui_router.post("/repos")
async def ui_create_repo(
    request: Request,
    csrf_token: str = Form(default=""),
    name: str = Form(...),
    git_url: str = Form(...),
    credential_type: str = Form(default="global"),
    credential_value: str = Form(default=""),
    default_image: str = Form(default=DEFAULT_RUNNER_IMAGE),
    timeout_seconds: int = Form(default=DEFAULT_TIMEOUT_SECONDS),
    secrets_text: str = Form(default=""),
) -> Response:
    _require_admin_ui(request)
    _require_csrf(request, csrf_token)
    svc: CiService = request.app.state.service
    try:
        secrets_dict = _parse_dotenv_secrets(secrets_text)
        svc.create_repo_admin(
            name=name,
            git_url=git_url,
            credential_type=credential_type,
            credential_value=credential_value,
            default_image=default_image,
            timeout_seconds=timeout_seconds,
            secrets_dict=secrets_dict,
        )
        return RedirectResponse(url="/repos?flash=Repository+saved", status_code=303)
    except ApiError as exc:
        from urllib.parse import quote_plus

        return RedirectResponse(
            url=f"/repos?error={quote_plus(exc.detail)}", status_code=303
        )


@ui_router.post("/repos/{repo_id}/edit")
async def ui_update_repo(
    repo_id: int,
    request: Request,
    csrf_token: str = Form(default=""),
    name: str = Form(...),
    git_url: str = Form(...),
    credential_type: str = Form(default="global"),
    credential_value: str = Form(default=""),
    default_image: str = Form(default=DEFAULT_RUNNER_IMAGE),
    timeout_seconds: int = Form(default=DEFAULT_TIMEOUT_SECONDS),
    secrets_text: str = Form(default=""),
    clear_secrets: str | None = Form(default=None),
) -> Response:
    _require_admin_ui(request)
    _require_csrf(request, csrf_token)
    svc: CiService = request.app.state.service
    try:
        secrets_updates = _parse_dotenv_secrets(secrets_text)
        svc.update_repo_admin(
            repo_id,
            name=name,
            git_url=git_url,
            credential_type=credential_type,
            credential_value=credential_value,
            keep_existing_credential=True,
            default_image=default_image,
            timeout_seconds=timeout_seconds,
            secrets_updates=secrets_updates,
            replace_secrets=bool(clear_secrets),
        )
        return RedirectResponse(url="/repos?flash=Repository+updated", status_code=303)
    except ApiError as exc:
        from urllib.parse import quote_plus

        return RedirectResponse(
            url=f"/repos?edit={repo_id}&error={quote_plus(exc.detail)}",
            status_code=303,
        )


@ui_router.post("/repos/{repo_id}/delete")
async def ui_delete_repo(
    repo_id: int,
    request: Request,
    csrf_token: str = Form(default=""),
) -> Response:
    _require_admin_ui(request)
    _require_csrf(request, csrf_token)
    svc: CiService = request.app.state.service
    svc.delete_repo_admin(repo_id)
    return RedirectResponse(url="/repos?flash=Repository+removed", status_code=303)


# ---- Tokens Page ----


@ui_router.get("/tokens", response_class=HTMLResponse)
async def ui_tokens_page(
    request: Request,
    flash: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> HTMLResponse:
    _require_admin_ui(request)
    svc: CiService = request.app.state.service
    tokens = svc.list_tokens()
    return _render_template(
        request,
        "tokens.html",
        "tokens",
        tokens=tokens,
        created_token=None,
        created_token_meta=None,
        flash=flash,
        error=error,
    )


@ui_router.post("/tokens", response_class=HTMLResponse)
async def ui_create_token(
    request: Request,
    csrf_token: str = Form(default=""),
    name: str = Form(...),
    role: str = Form(...),
) -> Response:
    _require_admin_ui(request)
    _require_csrf(request, csrf_token)
    svc: CiService = request.app.state.service
    try:
        meta, raw_token = svc.create_token(name=name, role=role)
    except ApiError as exc:
        from urllib.parse import quote_plus

        return RedirectResponse(
            url=f"/tokens?error={quote_plus(exc.detail)}", status_code=303
        )

    # Render directly in response to POST (never put raw token in URL query string or DB!)
    tokens = svc.list_tokens()
    return _render_template(
        request,
        "tokens.html",
        "tokens",
        status_code=201,
        tokens=tokens,
        created_token=raw_token,
        created_token_meta=meta,
        flash=None,
        error=None,
    )


@ui_router.post("/tokens/{token_id}/revoke")
async def ui_revoke_token(
    token_id: int,
    request: Request,
    csrf_token: str = Form(default=""),
) -> Response:
    _require_admin_ui(request)
    _require_csrf(request, csrf_token)
    svc: CiService = request.app.state.service
    svc.revoke_token(token_id)
    return RedirectResponse(url="/tokens?flash=Token+revoked", status_code=303)


# ---- Audit Activity Page ----


@ui_router.get("/activity", response_class=HTMLResponse)
async def ui_activity_page(
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> HTMLResponse:
    _require_admin_ui(request)
    svc: CiService = request.app.state.service
    entries = svc.db.list_audit_logs(limit=limit, offset=offset)
    total = svc.db.count_audit_logs()
    ok_count = sum(1 for e in entries if e["result"] == "ok" or e["result"].startswith("noop"))
    blocked_count = sum(
        1 for e in entries if e["result"].startswith(("denied", "unauthorized"))
    )
    api_count = sum(1 for e in entries if e["source"] == "api")
    mcp_count = sum(1 for e in entries if e["source"] == "mcp")
    return _render_template(
        request,
        "activity.html",
        "activity",
        entries=entries,
        total=total,
        ok_count=ok_count,
        blocked_count=blocked_count,
        api_count=api_count,
        mcp_count=mcp_count,
        limit=limit,
        offset=offset,
    )
