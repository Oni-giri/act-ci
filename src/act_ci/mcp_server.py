"""Streamable HTTP Model Context Protocol (MCP) server endpoint (/mcp)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from act_ci import __version__
from act_ci.models import (
    ApiError,
    Principal,
    RegisterRepoRequest,
    TriggerRunRequest,
)
from act_ci.service import CiService

mcp_router = APIRouter(tags=["mcp"])

SUPPORTED_PROTOCOL_VERSIONS = ("2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = "2025-03-26"

# Complete MCP tool catalog.
# Notice: tools/list filters this list by the caller's role, while actual authorization
# is strictly enforced inside CiService (the API/service layer), never merely in MCP.
MCP_TOOLS_SPEC: tuple[dict[str, Any], ...] = (
    {
        "name": "list_repos",
        "min_roles": ("operator", "viewer"),
        "definition": {
            "name": "list_repos",
            "description": "List configured repositories (metadata only; never includes credentials or secrets).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    },
    {
        "name": "register_repo",
        "min_roles": ("operator",),
        "definition": {
            "name": "register_repo",
            "description": (
                "Register a Git repository so its workflows can be run with trigger_run. "
                "By default the repository inherits the account-wide Git credential "
                "(configure it once in Act-CI settings), so no token is needed here. "
                "Never pass API keys or workflow secrets through this tool: ask the operator "
                "to add them in the Act-CI UI. Idempotent: re-registering the same name and "
                "git_url returns the existing repository."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Short slug used by trigger_run (e.g. my-service).",
                    },
                    "git_url": {
                        "type": "string",
                        "description": "Clone URL, e.g. https://github.com/owner/repo.git or git@github.com:owner/repo.git.",
                    },
                    "credential_type": {
                        "type": "string",
                        "enum": ["global", "none", "token", "deploy_key"],
                        "default": "global",
                        "description": "Use 'global' to reuse the account-wide Git credential.",
                    },
                    "credential_value": {
                        "type": "string",
                        "description": "Only for credential_type token/deploy_key. Prefer 'global'.",
                    },
                    "default_image": {
                        "type": "string",
                        "default": "catthehacker/ubuntu:act-22.04",
                        "description": "Container image mapped to ubuntu-* runner labels.",
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 86400,
                        "default": 1800,
                    },
                },
                "required": ["name", "git_url"],
                "additionalProperties": False,
            },
        },
    },
    {
        "name": "list_recent_runs",
        "min_roles": ("operator", "viewer"),
        "definition": {
            "name": "list_recent_runs",
            "description": "List recent CI runs, optionally filtered by repository name or status.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Filter by repository name.",
                    },
                    "status": {
                        "type": "string",
                        "enum": [
                            "queued",
                            "running",
                            "passed",
                            "failed",
                            "cancelled",
                            "timed_out",
                        ],
                        "description": "Filter by run status.",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "default": 25,
                    },
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "name": "get_run_status",
        "min_roles": ("operator", "viewer"),
        "definition": {
            "name": "get_run_status",
            "description": "Get the current status, commit SHA, exit code, and timestamps of a CI run.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run_id": {
                        "type": "string",
                        "description": "The run identifier (e.g. run_...).",
                    }
                },
                "required": ["run_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "name": "get_run_log",
        "min_roles": ("operator", "viewer"),
        "definition": {
            "name": "get_run_log",
            "description": "Get structured job and step logs for a CI run. Viewers can read logs of non-private runs only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run_id": {
                        "type": "string",
                        "description": "The run identifier (e.g. run_...).",
                    }
                },
                "required": ["run_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "name": "trigger_run",
        "min_roles": ("operator",),
        "definition": {
            "name": "trigger_run",
            "description": "Queue a new CI run for a repository at a branch, tag, or commit SHA, with optional overlay files or replacement workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Configured repository name.",
                    },
                    "ref": {
                        "type": "string",
                        "default": "HEAD",
                        "description": "Branch, tag, or commit SHA to check out.",
                    },
                    "workflow": {
                        "type": "string",
                        "description": "Optional relative path to workflow file (e.g. .github/workflows/ci.yml).",
                    },
                    "event": {
                        "type": "string",
                        "description": "Optional GitHub Actions event name (e.g. push, workflow_dispatch).",
                    },
                    "overlay": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Optional map of workspace-relative file paths to UTF-8 text contents overlaid onto checkout.",
                    },
                    "replacement_workflow": {
                        "type": "string",
                        "description": "Optional full YAML workflow text to run instead of the repo's .github/workflows.",
                    },
                    "private": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, run logs and overlay contents are hidden from viewer tokens.",
                    },
                    "callback_url": {
                        "type": "string",
                        "description": "Optional HTTP(S) URL to POST {run_id, status} when the run finishes.",
                    },
                },
                "required": ["repo"],
                "additionalProperties": False,
            },
        },
    },
    {
        "name": "cancel_run",
        "min_roles": ("operator",),
        "definition": {
            "name": "cancel_run",
            "description": "Cancel a queued or running CI run and stop its containers.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run_id": {
                        "type": "string",
                        "description": "The run identifier to cancel.",
                    }
                },
                "required": ["run_id"],
                "additionalProperties": False,
            },
        },
    },
)

ALL_MCP_TOOL_NAMES: tuple[str, ...] = tuple(t["name"] for t in MCP_TOOLS_SPEC)


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(
    req_id: Any, code: int, message: str, data: Any | None = None
) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _dispatch_tool_call(
    svc: CiService,
    principal: Principal,
    tool_name: str,
    arguments: dict[str, Any],
) -> Any:
    """Thin wrapper over CiService methods — all RBAC is enforced in CiService."""
    if tool_name == "list_repos":
        repos = svc.list_repos(principal)
        return [r.model_dump() for r in repos]

    if tool_name == "register_repo":
        try:
            req = RegisterRepoRequest(**arguments)
        except Exception as exc:
            svc.record_protocol_call(principal, "repos.register", "invalid_request:schema")
            raise ApiError(422, f"Invalid register_repo arguments: {exc}", "invalid_request") from exc
        repo = svc.register_repo(principal, req)
        return repo.model_dump()

    if tool_name == "list_recent_runs":
        runs = svc.list_runs(
            principal,
            repo=arguments.get("repo"),
            status=arguments.get("status"),
            limit=int(arguments.get("limit", 25)),
        )
        return [r.model_dump(exclude_none=True) for r in runs]

    if tool_name == "get_run_status":
        run_id = str(arguments.get("run_id") or "").strip()
        if not run_id:
            svc.record_protocol_call(principal, "runs.get", "invalid_request:missing_run_id")
            raise ApiError(422, "run_id is required", "invalid_request")
        run = svc.get_run_status(principal, run_id)
        return run.model_dump(exclude_none=True)

    if tool_name == "get_run_log":
        run_id = str(arguments.get("run_id") or "").strip()
        if not run_id:
            svc.record_protocol_call(principal, "runs.logs", "invalid_request:missing_run_id")
            raise ApiError(422, "run_id is required", "invalid_request")
        logs = svc.get_run_logs(principal, run_id)
        return logs.model_dump()

    if tool_name == "trigger_run":
        try:
            req = TriggerRunRequest(**arguments)
        except Exception as exc:
            svc.record_protocol_call(principal, "runs.trigger", "invalid_request:schema")
            raise ApiError(422, f"Invalid trigger_run arguments: {exc}", "invalid_request") from exc
        run = svc.trigger_run(principal, req)
        return run.model_dump(exclude_none=True)

    if tool_name == "cancel_run":
        run_id = str(arguments.get("run_id") or "").strip()
        if not run_id:
            svc.record_protocol_call(principal, "runs.cancel", "invalid_request:missing_run_id")
            raise ApiError(422, "run_id is required", "invalid_request")
        run = svc.cancel_run(principal, run_id)
        return run.model_dump(exclude_none=True)

    svc.record_protocol_call(principal, f"mcp.tools.unknown:{tool_name}", "not_found")
    raise ApiError(404, f"Unknown MCP tool '{tool_name}'", "not_found")


def _handle_single_rpc(
    svc: CiService,
    principal: Principal,
    msg: Any,
) -> dict[str, Any] | None:
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        svc.record_protocol_call(principal, "mcp.invalid_request", "invalid_request")
        return _jsonrpc_error(None, -32600, "Invalid JSON-RPC 2.0 request")

    method = msg.get("method")
    req_id = msg.get("id")
    is_notification = "id" not in msg
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    if not isinstance(method, str) or not method:
        svc.record_protocol_call(principal, "mcp.invalid_method", "invalid_request")
        return _jsonrpc_error(req_id, -32600, "Missing method")

    if method == "initialize":
        requested_ver = str(params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION)
        negotiated = (
            requested_ver
            if requested_ver in SUPPORTED_PROTOCOL_VERSIONS
            else DEFAULT_PROTOCOL_VERSION
        )
        svc.record_protocol_call(principal, "mcp.initialize", "ok")
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "act-ci", "version": __version__},
            },
        )

    if method in ("notifications/initialized", "notifications/cancelled"):
        svc.record_protocol_call(principal, f"mcp.{method}", "ok")
        return None

    if method == "ping":
        svc.record_protocol_call(principal, "mcp.ping", "ok")
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        visible_tools = [
            item["definition"]
            for item in MCP_TOOLS_SPEC
            if principal.role in item["min_roles"]
        ]
        svc.record_protocol_call(principal, "mcp.tools.list", "ok")
        return _jsonrpc_result(req_id, {"tools": visible_tools})

    if method == "tools/call":
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            svc.record_protocol_call(
                principal, f"mcp.tools.call:{tool_name}", "invalid_request:arguments"
            )
            return _jsonrpc_error(req_id, -32602, "Tool arguments must be an object")

        try:
            payload = _dispatch_tool_call(svc, principal, tool_name, arguments)
            serialized = json.dumps(payload, indent=2)
            return _jsonrpc_result(
                req_id,
                {
                    "content": [{"type": "text", "text": serialized}],
                    "structuredContent": {"result": payload}
                    if isinstance(payload, list)
                    else payload,
                    "isError": False,
                },
            )
        except ApiError as exc:
            # Map domain/RBAC errors into clean JSON-RPC or MCP tool errors
            rpc_code = {
                401: -32001,
                403: -32003,
                404: -32004,
                422: -32602,
            }.get(exc.status_code, -32000)
            return _jsonrpc_error(
                req_id,
                rpc_code,
                exc.detail,
                {"http_status": exc.status_code},
            )

    svc.record_protocol_call(principal, f"mcp.unknown:{method}", "method_not_found")
    if is_notification:
        return None
    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


@mcp_router.post("/mcp")
async def mcp_post_endpoint(request: Request) -> Response:
    svc: CiService = request.app.state.service

    # Peek action label for unauthenticated audit visibility if JSON is readable
    raw_body = await request.body()
    attempted_action = "mcp.request"
    parsed_body: Any = None
    parse_error = False
    try:
        parsed_body = json.loads(raw_body.decode("utf-8"))
        if isinstance(parsed_body, dict) and isinstance(parsed_body.get("method"), str):
            m = parsed_body["method"]
            if m == "tools/call" and isinstance(parsed_body.get("params"), dict):
                tname = parsed_body["params"].get("name")
                attempted_action = f"mcp.tools.call:{tname}" if tname else "mcp.tools.call"
            else:
                attempted_action = f"mcp.{m}"
    except Exception:
        parse_error = True

    principal = svc.authenticate_bearer(
        request.headers.get("authorization"),
        source="mcp",
        attempted_action=attempted_action,
    )

    if parse_error:
        svc.record_protocol_call(principal, "mcp.parse_error", "parse_error")
        return JSONResponse(
            status_code=400,
            content=_jsonrpc_error(None, -32700, "Parse error: invalid JSON"),
        )

    if isinstance(parsed_body, list):
        if not parsed_body:
            svc.record_protocol_call(principal, "mcp.empty_batch", "invalid_request")
            return JSONResponse(
                status_code=400,
                content=_jsonrpc_error(None, -32600, "Empty JSON-RPC batch"),
            )
        responses = []
        for item in parsed_body:
            resp = _handle_single_rpc(svc, principal, item)
            if resp is not None:
                responses.append(resp)
        if not responses:
            return Response(status_code=202)
        return JSONResponse(content=responses)

    resp = _handle_single_rpc(svc, principal, parsed_body)
    if resp is None:
        return Response(status_code=202)
    return JSONResponse(content=resp)


@mcp_router.get("/mcp")
async def mcp_get_endpoint(request: Request) -> Response:
    """Per Streamable HTTP MCP spec, GET /mcp authenticates the token and returns 405 if standalone SSE stream is not offered."""
    svc: CiService = request.app.state.service
    principal = svc.authenticate_bearer(
        request.headers.get("authorization"),
        source="mcp",
        attempted_action="mcp.sse_probe",
    )
    svc.record_protocol_call(principal, "mcp.sse_probe", "method_not_allowed")
    return JSONResponse(
        status_code=405,
        headers={"Allow": "POST"},
        content={"detail": "Use HTTP POST /mcp with JSON-RPC 2.0 messages"},
    )
