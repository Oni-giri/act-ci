"""FastAPI application factory for Act-CI."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from act_ci import __version__
from act_ci.api_routes import api_router
from act_ci.config import Settings, load_settings
from act_ci.db import Database
from act_ci.mcp_server import mcp_router
from act_ci.models import ApiError
from act_ci.runner import RunnerWorker
from act_ci.security import CsrfSigner, SecretBox
from act_ci.service import CiService
from act_ci.ui_routes import ui_router


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or load_settings()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)

    db = Database(cfg.db_path)
    secret_box = SecretBox.from_data_dir(cfg.data_dir, env_key=cfg.master_key_env)
    csrf_signer = CsrfSigner(secret_box.derive_csrf_secret(cfg.csrf_secret_env))
    worker = RunnerWorker(db=db, secret_box=secret_box, settings=cfg)
    service = CiService(
        db=db,
        secret_box=secret_box,
        settings=cfg,
        on_run_enqueued=worker.notify_enqueued,
        on_run_cancel_requested=worker.notify_cancel,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if cfg.enable_worker:
            await worker.start()
        try:
            yield
        finally:
            if cfg.enable_worker:
                await worker.stop()

    app = FastAPI(
        title="Act-CI",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = cfg
    app.state.db = db
    app.state.secret_box = secret_box
    app.state.csrf = csrf_signer
    app.state.worker = worker
    app.state.service = service

    @app.exception_handler(ApiError)
    async def handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Ensure malformed JSON/body on /api/* still records an audit entry!
        path = request.url.path
        if path.startswith("/api/"):
            auth = request.headers.get("authorization")
            try:
                p = service.authenticate_bearer(
                    auth,
                    source="api",
                    attempted_action=f"api.validation:{request.method}:{path}",
                )
                service.db.append_audit(
                    source="api",
                    token_id=p.token_id,
                    token_name=p.token_name,
                    role=p.role,
                    action=f"api.validation:{request.method}:{path}",
                    result="invalid_request:schema",
                )
            except ApiError as auth_exc:
                headers = (
                    {"WWW-Authenticate": "Bearer"}
                    if auth_exc.status_code == 401
                    else None
                )
                return JSONResponse(
                    status_code=auth_exc.status_code,
                    content={"detail": auth_exc.detail},
                    headers=headers,
                )
        return JSONResponse(
            status_code=422,
            content={"detail": exc.errors()},
        )

    app.include_router(api_router)
    app.include_router(mcp_router)
    app.include_router(ui_router)
    return app
