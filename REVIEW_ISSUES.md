# Code & Security Review Findings — Act-CI

Recorded from the full repository review of **Act-CI** (`v0.1.0`). Each item below lists its severity, affected files, root cause & impact, and resolution plan/status.

---

## Summary Matrix

| ID | Severity | Area | Locations | Status |
| --- | --- | --- | --- | --- |
| **ISSUE-01** | Medium | SSRF / Internal Network Surface | `src/act_ci/service.py`, `src/act_ci/runner.py`, `src/act_ci/config.py` | **Fixed & Tested** |
| **ISSUE-02** | Medium | CSRF Session Binding, TTL & Origin Check | `src/act_ci/security.py`, `src/act_ci/ui_routes.py`, `scripts/level3_smoke_test.py` | **Fixed & Tested** |
| **ISSUE-03** | Low | Standalone Compose & Local-Repo Defaults | `docker-compose.yml`, `src/act_ci/config.py`, `scripts/level3_smoke_test.py` | **Fixed & Tested** |
| **ISSUE-04** | Low | Unbounded Overlay Payloads & Step Log Growth | `src/act_ci/service.py`, `src/act_ci/db.py`, `src/act_ci/runner.py` | **Fixed & Tested** |
| **ISSUE-05** | Low | Dotenv Secret Quoting & Docker CLI SHA-256 Pin | `src/act_ci/ui_routes.py`, `Dockerfile` | **Fixed & Tested** |
| **ISSUE-06** | Low | Dirty Git Working Tree on `replacement_workflow` | `src/act_ci/runner.py` | **Fixed & Tested** |
| **ISSUE-07** | Low | Test Deprecation Warning & Doc Digest Drift | `pyproject.toml`, `PLAN.md`, `.dockerignore` | **Fixed & Tested** |

---

## Detailed Findings

### ISSUE-01 — Blind SSRF Surface on `callback_url` (Medium)

- **Locations:** `src/act_ci/service.py` (`validate_callback_url`), `src/act_ci/runner.py` (`_deliver_callback`)
- **Problem:** `validate_callback_url` checks only `scheme in ("http", "https")` and non-empty `netloc`. An `operator` token can specify loopback (`127.0.0.1`, `::1`, `localhost`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), multicast/unspecified addresses, or container-internal Docker daemon endpoints (`http://docker:2375/...`), causing the `web` container to issue blind `POST` requests to internal services (including via DNS rebinding if checked only syntactically).
- **Fix:**
  1. Reject literal loopback, unspecified (`0.0.0.0`, `::`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, and `localhost` targets during validation unless `allow_loopback_callbacks` is explicitly enabled for local test suites (`ACT_CI_ALLOW_LOOPBACK_CALLBACKS=1`).
  2. Resolve target hostnames immediately before connecting in `_deliver_callback` (pinning/verifying all resolved `getaddrinfo` IPs against the same disallowed ranges) while preserving RFC1918 LAN and Tailscale (`100.64.0.0/10`) addresses needed by self-hosted home/LAN agent callbacks.

---

### ISSUE-02 — Stateless Unbound CSRF Tokens & Missing `Origin`/`Referer` Check (Medium)

- **Locations:** `src/act_ci/security.py` (`CsrfSigner`), `src/act_ci/ui_routes.py` (`_require_csrf`, `_base_ctx`)
- **Problem:** `CsrfSigner` signs a bare random nonce (`nonce.sig`) with the per-install secret without binding to a browser cookie, without an expiration timestamp, and without checking `Origin` / `Referer` headers (which `PLAN.md` §3 specified). Any single leaked token remains valid indefinitely across all sessions.
- **Fix:**
  1. Bind CSRF tokens to a per-browser `SameSite=Lax`, `HttpOnly` session cookie (`act_ci_csrf_sid`) and embed an issuance timestamp with a bounded TTL (12 hours).
  2. Enforce same-origin verification in `_require_csrf` whenever `Origin` or `Referer` headers are present on state-changing `POST` requests.
  3. Update `scripts/level3_smoke_test.py` (`HTTPCookieProcessor`) so automated UI smoke tests preserve the CSRF session cookie cleanly.

---

### ISSUE-03 — Standalone `docker-compose.yml` & `ACT_CI_ALLOW_LOCAL_REPOS` Defaults (Low)

- **Locations:** `docker-compose.yml`, `src/act_ci/config.py`, `scripts/level3_smoke_test.py`
- **Problem:**
  1. `load_settings()` in `src/act_ci/config.py` defaults `ACT_CI_ALLOW_LOCAL_REPOS` to `"1"`, allowing local filesystem path clones (`/` or `file://`) unless explicitly disabled.
  2. Standalone `docker-compose.yml` exposes the DinD daemon over unauthenticated `tcp://0.0.0.0:2375` on the Compose bridge network (instead of a shared Unix socket) and binds the unauthenticated standalone Web UI on all interfaces (`0.0.0.0:8755`) rather than `127.0.0.1:8755`.
- **Fix:**
  1. Change the default of `ACT_CI_ALLOW_LOCAL_REPOS` in `src/act_ci/config.py` to `"0"` (safe by default; test fixtures explicitly enable it where needed).
  2. Switch standalone `docker-compose.yml` to share a dedicated Unix socket volume (`dind-run:/var/run/dind`, matching `Dockerfile` and the Umbrel compose configuration), set `ACT_CI_ALLOW_LOCAL_REPOS: "${ACT_CI_ALLOW_LOCAL_REPOS:-0}"`, and default host port binding to `${ACT_CI_LISTEN_HOST:-127.0.0.1}:${ACT_CI_LISTEN_PORT:-8755}:8080`.
  3. Update `scripts/level3_smoke_test.py` to pass `ACT_CI_ALLOW_LOCAL_REPOS=1` for its local fixture smoke test and query `unix:///var/run/dind/docker.sock`.

---

### ISSUE-04 — Unbounded Overlay Payload Sizes & $O(N^2)$ Step Log Rewrites (Low)

- **Locations:** `src/act_ci/service.py`, `src/act_ci/db.py`, `src/act_ci/runner.py`
- **Problem:**
  1. `TriggerRunRequest` caps overlay file count at 100, but does not cap individual file size, total overlay bytes, or `replacement_workflow` size—allowing multi-hundred-MB SQLite rows.
  2. `Database.upsert_step_log` rewrites the full `log_text` string on every single output line emitted by `act --json` without any maximum per-step size cap or stream batching.
- **Fix:**
  1. Enforce explicit byte-size limits in `CiService.trigger_run`: max 512 KiB per `replacement_workflow`, max 1 MiB per overlay file, and max 4 MiB total overlay payload.
  2. Enforce a per-step `MAX_STEP_LOG_BYTES` cap (2 MiB) in `Database.upsert_step_log` with a clean `\n...[log truncated at 2097152 bytes]...\n` marker, using SQLite concatenation / bounded updates, and batch contiguous stdout log chunks over short ~100ms windows in `RunnerWorker._invoke_act` to avoid per-line write-lock churn.

---

### ISSUE-05 — Quoted Dotenv Secret Parsing & Docker CLI Tarball Checksum (Low)

- **Locations:** `src/act_ci/ui_routes.py` (`_parse_dotenv_secrets`), `Dockerfile`
- **Problem:**
  1. `_parse_dotenv_secrets` calls `val.strip()`, leaving literal surrounding quotes if a user enters `API_KEY="secret"` or `API_KEY='secret'`.
  2. `Dockerfile` verifies SHA-256 digests for `nektos/act`, but downloads static `docker-27.5.1.tgz` without verifying SHA-256 checksums.
- **Fix:**
  1. Unquote matching single/double-quoted values (supporting standard escaped characters in double quotes) in `_parse_dotenv_secrets`.
  2. Pin and verify official SHA-256 digests (`DOCKER_CLI_SHA256_AMD64` and `DOCKER_CLI_SHA256_ARM64`) with `sha256sum -c -` in `Dockerfile`.

---

### ISSUE-06 — Dirty Git Working Tree When Using `replacement_workflow` (Low)

- **Locations:** `src/act_ci/runner.py` (`_apply_overlay_and_workflow`)
- **Problem:** Writing `.github/workflows/__act_ci_replacement__.yml` inside `workspace_dir` leaves an untracked file in the git checkout, which can fail workflows running `git status --porcelain` cleanliness assertions.
- **Fix:** Append `.github/workflows/__act_ci_replacement__.yml` to `.git/info/exclude` inside `workspace_dir` whenever a replacement workflow is materialized (and verify `override_path` is not a symlink).

---

### ISSUE-07 — Test Suite Deprecation Warning & Documentation Digest Drift (Low)

- **Locations:** `pyproject.toml`, `PLAN.md`, `.dockerignore`
- **Problem:**
  1. Starlette 1.10+ (`fastapi>=0.165`) emits `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead` unless `httpx2` is included in `dev` dependencies.
  2. `PLAN.md` still references an earlier DinD digest (`sha256:f9f72ad...`) instead of the multi-arch digest (`sha256:d1d6d52...`) used in `docker-compose.yml`, `REVIEWER_NOTES.md`, `EVIDENCE.md`, and `.github/workflows/ci-publish.yml`.
- **Fix:** Add `httpx2` to `[project.optional-dependencies].dev` (and install if available in the test environment or filter if offline), align `PLAN.md` image digests, and exclude `REVIEW_ISSUES.md` in `.dockerignore`.
