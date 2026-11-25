# PLAN.md — Act-CI

## 1. Product Identity & Naming

- **App Name:** **Act-CI** (`act-ci`)
- **App Repo / Image Namespace:** `github.com/Oni-giri/act-ci` → `ghcr.io/oni-giri/act-ci` (multi-arch `linux/amd64`, `linux/arm64`)
- **Store Repo & Package ID:**
  - Store repository: `Oni-giri/yakitoris-app-store` (`/data/home/Yakitori-App-Store/yakitoris-app-store`) on a dedicated branch (`feat/yakitori-act-ci`), touching **only** `yakitori-act-ci/`.
  - Umbrel App ID: `yakitori-act-ci` (following the `yakitori-*` store convention; `manifestVersion: 2`, `storage.dataRoot: data`, unique host port `8755`, internal web port `8080`).

## 2. Technology Stack & Architecture

- **Language & Web Framework:** Python 3.11+ with **FastAPI**, **Uvicorn**, **Jinja2** server-rendered HTML templates, and lightweight progressive enhancement (vanilla JS fetch polling for live run logs, zero external CDN dependencies so it works completely offline on LAN/Tailscale).
- **Database:** **SQLite** (`${ACT_CI_DATA_DIR}/act_ci.db`) in WAL mode (`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`), with automatic, idempotent schema migrations at startup.
- **Cryptography:**
  - **Tokens:** Prefix `actci_` + 32 bytes of `secrets.token_urlsafe`. Only `SHA-256(raw_token)` is stored in SQLite (`token_hash`), along with a non-secret display prefix (`actci_xxxx...`). Shown once on creation; never recoverable.
  - **Secrets & Clone Credentials at Rest:** Encrypted using `cryptography.fernet.Fernet` (AES-128-CBC + HMAC-SHA256). Key derived via HKDF-SHA256 from `ACT_CI_MASTER_KEY` environment variable (supplied by Umbrel `exports.sh` via `derive_entropy "${app_entropy_identifier}-encryption-key"`); when running standalone outside Umbrel without `ACT_CI_MASTER_KEY`, auto-generates and persists `${ACT_CI_DATA_DIR}/master.key` (`0600`) on first boot.
- **Pinned Upstream Binaries / Sidecars:**
  - `nektos/act`: **v0.2.98** (verified SHA256 checksums per architecture: `d3344bd0810c04b000d2444030b08c90ab9fbf905bbe2c3e26298be00c620d65` for `Linux_x86_64`, `a30ba1a1582cb93810c77f743415cac33c16f60fc288116a8e0943144b6a6a4f` for `Linux_arm64`).
  - Docker CLI inside web container (pinned static Docker CLI matching daemon API) + **Docker-in-Docker sidecar** `docker:27.2.0-dind@sha256:f9f72ad901a78f27be922b2d320bbc263174f12919c1b37e6a01f828fa904565` (multi-arch, modeled on `getumbrel/umbrel-apps` `onedev`).

## 3. Access Model, Route Layout & Proxy Boundary

### Boundary Design
Umbrel's `app_proxy` protects everything by default with Umbrel's login session. Only `/api/*` and `/mcp` (plus `/mcp/*`) are listed in `PROXY_AUTH_WHITELIST`:

```yaml
PROXY_AUTH_WHITELIST: "/api/*,/mcp,/mcp/*"
```

- **Admin Surface (`/` and `/ui/*` or `/admin/*` — NOT under `/api/*` or `/mcp*`):**
  - Reached only after passing Umbrel's login proxy.
  - **Defense in depth:** Every non-whitelisted route ALSO rejects any request carrying an `Authorization` header (`403 Forbidden`), ensuring bearer tokens can never access admin routes even if someone reaches the container directly without `app_proxy`.
  - CSRF protection on all state-changing HTML form POSTs (`Origin`/`Referer` check + per-install HMAC CSRF token).
- **Bearer API Surface (`/api/v1/...`):**
  - Requires `Authorization: Bearer <token>`. Missing, malformed, unknown, or revoked tokens return `401 Unauthorized` (and still record an audit entry for the attempted call).
  - **Enforced in the core API/service layer**, shared identically by HTTP `/api/v1/*` handlers and MCP tool handlers:
    - `operator`:
      - `GET /api/v1/repos` — list repos (metadata only; never credentials or secret values, only secret keys/count if needed—better: not even secret values, ever).
      - `POST /api/v1/runs` — trigger run (supports `repo`, `ref`, `workflow`, `event`, `overlay`, `replacement_workflow`, `private`, `callback_url`).
      - `GET /api/v1/runs` — list runs (with optional `repo`, `status`, `limit` filters).
      - `GET /api/v1/runs/{run_id}` — get run status & metadata (includes overlay file path list for operators, never raw secrets).
      - `GET /api/v1/runs/{run_id}/logs` — get full structured job/step logs (with secrets masked) for all runs including `private=true`.
      - `POST /api/v1/runs/{run_id}/cancel` — cancel a queued or running run.
    - `viewer`:
      - `GET /api/v1/repos` — list repos (safe summary).
      - `GET /api/v1/runs` — list runs (safe status/timing summary; for private runs, `overlay` / `replacement_workflow` metadata is redacted).
      - `GET /api/v1/runs/{run_id}` — get run status & timing (no overlay contents/paths or workflow replacement details on private runs).
      - `GET /api/v1/runs/{run_id}/logs` — allowed ONLY when `run.is_private == False`; returns `403 Forbidden` when `run.is_private == True`.
      - `POST /api/v1/runs` & `POST /api/v1/runs/{run_id}/cancel` — returns `403 Forbidden`.

### Append-Only Audit Log
- Every API call (`/api/*`) and every MCP request (`/mcp`), **including reads and auth/permission denials**, writes an audit row:
  - `id`, `created_at`, `source` (`api` | `mcp`), `token_id` (nullable), `token_name` (nullable / `"<anonymous>"` / `"<invalid>"`), `role` (nullable), `action` (e.g. `runs.list`, `runs.get`, `runs.logs`, `runs.trigger`, `runs.cancel`, `repos.list`, `mcp.tools.list`, `mcp.initialize`), `repo_name`, `run_id`, `result` (`allowed` / `denied` / `unauthorized` / `not_found` / `error` + HTTP/RPC status).
- SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers on `audit_logs` raise `ABORT('audit_logs is append-only')` so rows cannot be modified or deleted even by accidental SQL in the application, and no update/delete methods or routes exist.

## 4. Data Schema & Secret Hygiene

1. **`repos`**
   - `id`, `name` (unique slug), `git_url`, `credential_type` (`none` | `token` | `deploy_key`), `encrypted_credential`, `default_image` (default `catthehacker/ubuntu:act-22.04`), `timeout_seconds` (default `1800`), `encrypted_secrets_json` (Fernet-encrypted JSON dict `{KEY: VALUE}`), `created_at`, `updated_at`.
2. **`tokens`**
   - `id`, `name`, `role` (`operator` | `viewer`), `token_hash` (unique SHA-256 hex), `token_prefix`, `created_at`, `last_used_at`, `revoked_at`.
3. **`runs`**
   - `id` (UUID/ULID string), `repo_id`, `repo_name`, `requested_ref`, `commit_sha`, `workflow_path`, `event_name`, `is_private` (bool), `encrypted_overlay_json` (encrypted at rest while queued/running, or cleared/kept encrypted for operator inspection—stored encrypted and never exposed to viewers), `has_overlay` (bool), `has_replacement_workflow` (bool), `callback_url`, `callback_status`, `status` (`queued` | `running` | `passed` | `failed` | `cancelled` | `timed_out`), `exit_code`, `error_message`, `created_at`, `started_at`, `finished_at`, `triggered_by` (`admin-ui` or token name).
4. **`run_steps`** / **`run_logs`**
   - Structured per-job and per-step records parsed from `act --json` output:
     - `job_id`, `job_name`, `step_id`, `step_name`, `stage`, `status`, `exit_code`, `started_at`, `finished_at`, `log_text`.
   - Raw fallback / system lifecycle lines (clone, checkout, timeout, cancel) stored under a synthetic `__setup__` / `__system__` job so clone failures and timeouts are transparently visible in logs (and masked!).
5. **Secret Masking:**
   - Before any log line or error string is persisted to SQLite or returned, a `SecretMasker` strips every repo secret value and clone credential (sorted longest-first, plus URL-encoded and base64-encoded variants for tokens ≥ 4 chars), replacing matches with `***`.
   - Clone credentials are passed via transient `GIT_ASKPASS` script (for HTTPS tokens) or `GIT_SSH_COMMAND` with a `0600` temp key file outside the workspace (deleted immediately after `git fetch`/`checkout`), never embedded in `git remote` URLs where `.git/config` inside the copied workspace could leak them into job containers!

## 5. Runner Engine & `nektos/act` Integration (Milestone 2)

### Slot & Queue Model
- Data model encapsulates a `Slot(slot_id, docker_host, act_cache_dir, workspace_root)`. v1 instantiates **1 slot** (`slot-0`) backed by an `asyncio.Condition` / worker loop that claims `queued` runs in FIFO order (`ORDER BY created_at ASC, id ASC`).
- On startup, any orphaned `running` runs from an abrupt container crash are cleanly marked `failed` (with reason `"interrupted by service restart"`) and leftover containers on the slot daemon are cleaned up before accepting new runs.

### Exact Execution Lifecycle
1. **Workspace creation:** Create fresh temp directory `${SLOT_WORKSPACE_ROOT}/run-${run_id}`.
2. **Git clone & checkout at exact commit:**
   - Support HTTPS URLs (with optional read-only token via `GIT_ASKPASS`), SSH URLs (with optional deploy key via `GIT_SSH_COMMAND`), and local filesystem paths (`file://` or local path in test/fixture mode when `ACT_CI_ALLOW_LOCAL_REPOS=1` or valid git URL).
   - Resolve `requested_ref` (branch, tag, or full/short commit SHA) cleanly: `git init`, `git remote add origin <clean_url>`, `git fetch --depth=1 origin <ref>` (with fallback fetch if short SHA), `git checkout --detach FETCH_HEAD`, record exact `git rev-parse HEAD` into `runs.commit_sha`.
3. **Apply overlay & replacement workflow:**
   - Validate all overlay relative paths against path traversal (`..`, leading `/`, symlink escape outside workspace root, or `.git/` tampering).
   - Write each `overlay` file (`{path: content_or_base64}`) into workspace.
   - If `replacement_workflow` is provided: write it to `.act-ci-replacement-workflow.yml` (or `.github/workflows/__act_ci_override.yml` while removing/pointing `-W` strictly at that file) and pass `-W <workflow_file>` to `act`. Otherwise if `workflow` path is specified, validate it stays inside workspace and pass `-W <workflow>`. Otherwise `act` runs `./.github/workflows/` unchanged.
4. **Verified `act` v0.2.98 CLI Invocation:**
   Every flag verified against `act --help` (v0.2.98):
   - Positional `[event_name]` (if provided; otherwise omit or `--detect-event`? Note: in `act --help`: *"If no event name passed, will default to 'on: push'. If actions handles only one event it will be used as default instead of 'on: push'"* — so only pass `event_name` when explicitly specified by caller/repo, or pass it positionally).
   - `-C <workspace_dir>` (working directory; **no `-b` / `--bind`**, using `act`'s default copy mode!).
   - `--json` (structured JSON log lines on stdout/stderr).
   - `--rm` (automatically remove containers/volumes after failure; default already removes on success since `-r/--reuse` is not set).
   - `--action-cache-path <slot_act_cache_dir>/actions`
   - `--no-cache-server` (avoids host-IP cache server binding mismatches against remote DinD sidecar; roadmap leaves caching open).
   - `--container-daemon-socket -` (prevents `act` from bind-mounting `/var/run/docker.sock` inside untrusted workflow job containers by default, keeping jobs isolated from the DinD socket).
   - `-P ubuntu-latest=<repo.default_image>` `-P ubuntu-24.04=<repo.default_image>` `-P ubuntu-22.04=<repo.default_image>` `-P ubuntu-20.04=<repo.default_image>`
   - `--secret-file <temp_secrets_file>` (temp file outside workspace `0600`, deleted in `finally`, never inside workspace).
   - `-W <workflow_path>` (when specified or replacement workflow given).
   - Environment passed to `act` subprocess: `DOCKER_HOST=<slot.docker_host>` (e.g., `unix:///var/run/act-docker/docker.sock` or `tcp://...`), isolated `HOME` & `XDG_CACHE_HOME`.
5. **Streaming JSON Parser:**
   - Reads `act --json` line-by-line in real time, masks secrets, groups lines by `(jobID/job, stepID/step/stage)`, and flushes incrementally to SQLite so the UI updates live while running.
6. **Timeout & Cancellation Enforcement:**
   - Watchdog enforces `repo.timeout_seconds` using `asyncio.wait_for` / monotonic deadline.
   - On timeout (`timed_out`) or `cancel` request (`cancelled`): terminate the `act` process group (`SIGTERM` → grace → `SIGKILL`) AND query the slot's Docker daemon (`docker -H <docker_host> ps -aq`) to `docker rm -f` all containers on that dedicated slot daemon (safe because 1 slot = 1 dedicated DinD daemon, so every container on that daemon belongs to the current run!).
7. **Post-Run Cleanup & Pruning:**
   - Always (`try ... finally`):
     1. Remove temp credential/secret files.
     2. Delete the workspace directory (`shutil.rmtree`).
     3. Force-remove any remaining containers (`docker ps -aq | xargs -r docker rm -f`) and dangling job networks/volumes (`docker network prune -f`, `docker volume prune -f`) on the slot's Docker daemon so `docker ps -a` is guaranteed empty.
   - Background scheduled task runs `docker image prune -af --filter "until=168h"` (configurable interval & retention, e.g. every 6 hours) on the slot daemon.
8. **Callback Delivery:**
   - If `callback_url` was provided, validate scheme (`http://` or `https://`), POST JSON `{"run_id": run.id, "status": run.status}` with a short timeout (10s), record delivery status without failing the run itself if the receiver is unreachable.

## 6. MCP Server Design (Milestone 4)

- Mounted at `/mcp` on the same FastAPI app using the Streamable HTTP MCP transport (JSON-RPC 2.0 over HTTP `POST /mcp`, supporting `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`, with proper MCP protocol version negotiation `2025-03-26` / `2024-11-05`).
- Uses the exact same `Authorization: Bearer <token>` authenticator and writes to the same append-only `audit_logs` table on every request (`tools/list`, `tools/call`, etc.).
- **Role-Filtered Tool Catalog:**
  - **Viewer sees 4 tools:** `list_repos`, `list_recent_runs`, `get_run_status`, `get_run_log`.
  - **Operator sees all 6 tools:** `list_repos`, `list_recent_runs`, `get_run_status`, `get_run_log`, `trigger_run`, `cancel_run`.
- **Defense in Depth:** Even if a `viewer` token manually invokes `tools/call` with `name="trigger_run"` or `name="cancel_run"` (bypassing `tools/list`), the underlying API/service layer still enforces RBAC and rejects it with permission denied, logging the denied call in `audit_logs`!

## 7. Umbrel Package Design (Milestone 5)

Following `getumbrel/umbrel-apps` `AGENTS.md`, `umbrel-package-app`, `umbrel-develop-app`, `umbrel-test-app`, and `onedev`:
- Directory in `yakitoris-app-store` (on branch `feat/yakitori-act-ci`): `yakitori-act-ci/`
  - `umbrel-app.yml`:
    - `manifestVersion: 2`, `storage: { dataRoot: data }`, `id: yakitori-act-ci`, `name: Act-CI`, `port: 8755`, `path: ""`, `defaultUsername: ""`, `defaultPassword: ""`.
    - Prominent disclosure at top of `description` that Act-CI runs a privileged Docker-in-Docker sidecar container and executes repository workflow code.
    - No personal hostnames, IPs, usernames, or tokens anywhere.
  - `exports.sh`:
    - Derives per-install secrets with `derive_entropy`, one unique label per secret:
      - `APP_ACT_CI_ENCRYPTION_KEY="$(derive_entropy "${app_entropy_identifier}-encryption-key")"`
      - `APP_ACT_CI_CSRF_SECRET="$(derive_entropy "${app_entropy_identifier}-csrf-secret")"`
  - `docker-compose.yml`:
    - `app_proxy`: `APP_HOST: yakitori-act-ci_web_1`, `APP_PORT: 8080`, `PROXY_AUTH_WHITELIST: "/api/*,/mcp,/mcp/*"`.
    - `docker` (DinD sidecar): `docker:27.2.0-dind@sha256:...`, `privileged: true`, isolated daemon storing state in `${APP_DATA_DIR}/data/docker` and exposing socket on shared volume `${APP_DATA_DIR}/data/docker-run/docker.sock` (or TLS/unix socket over shared `${APP_DATA_DIR}/data/docker-sock` directory—never `/var/run/docker.sock` from the host!). Note: Unlike `onedev` which used `network_mode: host`, standard bridge networking on `docker:27.2.0-dind` (`DOCKER_TLS_CERTDIR=""` + unix socket on a shared bind-mounted directory `${APP_DATA_DIR}/data/dind-run`) avoids `network_mode: host` entirely, keeping host network namespace untouched while still supporting DinD job & service containers!
    - `web`: `ghcr.io/oni-giri/act-ci:0.1.0@sha256:<multi-arch-digest>`, `restart: on-failure`, `init: true`, mounts `${APP_DATA_DIR}/data/app:/data` and `${APP_DATA_DIR}/data/dind-run:/var/run/dind`.
  - `data/app/.gitkeep`, `data/docker/.gitkeep`, `data/dind-run/.gitkeep` so all bind-mount directories exist cleanly.

## 8. Environment Findings & Open Questions

1. **Local Execution Environment Observation:**
   - Current workspace container (`x86_64`, Python 3.11) does **not** have a local `docker` daemon/CLI installed (`docker: command not found`, running inside an unprivileged container).
   - GitHub CLI (`gh`) is authenticated as `Oni-giri` with `repo` and `workflow` scopes, so we can push `Oni-giri/act-ci`, run GitHub Actions (`ubuntu-latest` with real Docker + QEMU/Buildx) to execute Level 2 & Level 3 tests against a real Docker daemon AND build/publish the multi-arch (`linux/amd64`, `linux/arm64`) image to `ghcr.io/oni-giri/act-ci`!
2. **Open Questions for User (Non-blocking for Milestones 1–4; needed for Level 4 live Umbrel device check if available):**
   - **Q1 (Umbrel / Docker Host Access):** Do you have SSH or MCP access details for an Umbrel device (or a Docker-capable host for containerized umbrelOS / local Level 2–4 runs) that you want me to use? (Per instructions, I will ask rather than guess, while immediately proceeding with Milestone 1–4 implementation.)
   - **Q2 (App Naming):** Confirming **Act-CI** (`Oni-giri/act-ci`, store package `yakitori-act-ci` in `Oni-giri/yakitoris-app-store`) — let me know if you prefer a different name or target store repo (`Oni-giri/umbrel-apps` vs `Oni-giri/yakitoris-app-store`).
