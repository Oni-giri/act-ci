# Reviewer Notes — Act-CI (`yakitori-act-ci` v0.1.0)

## 1. Package & Repository Overview

- **Umbrel App ID:** `yakitori-act-ci` (`manifestVersion: 2`, `storage.dataRoot: data`, host port `8755`, internal web port `8080`)
- **Upstream Source Repo:** [`https://github.com/Oni-giri/act-ci`](https://github.com/Oni-giri/act-ci)
- **Store Branch:** [`feat/yakitori-act-ci`](https://github.com/Oni-giri/yakitoris-app-store/tree/feat/yakitori-act-ci) in `Oni-giri/yakitoris-app-store` (diff touches **only** `yakitori-act-ci/`, zero personal values/IPs/tokens)
- **Pinned Multi-Arch Images (`linux/amd64` + `linux/arm64`):**
  - `web`: `ghcr.io/oni-giri/act-ci:0.1.0@sha256:1ea8f527fdcf38d003adf4f22b15e00a312a23bca97cafb2eb2d5cb7125df5f9` (bundles Python 3.12, FastAPI, SQLite, static Docker CLI `27.5.1`, and `nektos/act` `v0.2.98` verified by SHA-256)
  - `docker` (DinD sidecar): `docker:27.2.0-dind@sha256:d1d6d5265119696d8fa9b883f813953c560c5d87ea128a57681239b576f62997`

---

## 2. Host Access & Intentional Linter Warning Justification

Running `npm run lint:apps -- yakitori-act-ci --check-images` from `getumbrel/umbrel-apps` reports **0 errors** and **1 intentional warning**:

```text
WARNING access.privileged yakitori-act-ci/docker-compose.yml:14
  Service `docker` uses `privileged: true`; justify this in the PR.
```

### Why `privileged: true` is required and how blast radius is minimized
1. **No Host Docker Socket:** Act-CI **never** mounts `/var/run/docker.sock` from the Umbrel host. Instead, following the `onedev` pattern in `getumbrel/umbrel-apps`, it runs a dedicated `docker:27.2.0-dind` sidecar so workflow job and service containers (e.g. Postgres) run inside an isolated daemon and cannot see or control other Umbrel containers.
2. **No `network_mode: host`:** Unlike `onedev`, `yakitori-act-ci` keeps the DinD sidecar on standard bridge networking and shares only an app-private Unix socket directory (`${APP_DATA_DIR}/data/dind-run:/var/run/dind`) with `web`.
3. **Socket Withheld from Workflow Containers:** Act-CI invokes `act` in default **copy mode** (never `--bind`) and passes `--container-daemon-socket -`, so untrusted workflow steps do not receive the DinD socket either.
4. **Prominent User Disclosure:** The top of `description` in `umbrel-app.yml` explicitly discloses that Act-CI runs a privileged Docker-in-Docker sidecar container and executes repository workflow code.

---

## 3. Authentication, Proxy Whitelist & Persistence Contract

- **Umbrel Login & `PROXY_AUTH_WHITELIST`:**
  - Umbrel's `app_proxy` login remains enabled by default (`defaultUsername: ""`, `defaultPassword: ""`).
  - `PROXY_AUTH_WHITELIST` is scoped strictly to `"/api/*,/mcp,/mcp/*"`.
  - All Admin UI routes (`/`, `/runs*`, `/repos*`, `/tokens*`, `/activity`, `/healthz`) sit outside the whitelist AND explicitly reject any request carrying an `Authorization` header (`403 Forbidden`) as defense in depth.
- **Role Enforcement & Audit Trail:**
  - Bearer tokens (`actci_...`) are shown once on creation and stored only as SHA-256 hashes.
  - Role checks (`operator` vs `viewer`, including private-run log/overlay isolation) are enforced in a single core service layer (`src/act_ci/service.py`) shared by `/api/v1/*` and `/mcp`.
  - Every API and MCP request—including reads and `401`/`403` denials—is recorded in an append-only `audit_logs` SQLite table protected by `BEFORE UPDATE` and `BEFORE DELETE` `RAISE(ABORT, ...)` triggers.
- **Persistence & Secrets:**
  - All mutable state lives under `${APP_DATA_DIR}/data` (`data/app`, `data/docker`, `data/dind-run`), compatible with umbrelOS 2.0 external storage relocation (`storage.dataRoot: data`).
  - `exports.sh` derives independent per-install secrets via `derive_entropy` (`${app_entropy_identifier}-master-key` and `${app_entropy_identifier}-csrf-secret`). Clone credentials, workflow secrets, and run overlays are encrypted at rest with Fernet (`AES-128-CBC` + `HMAC-SHA256`) and masked (`***`) in logs.

---

## 4. Context Note on GitHub Actions CI & Testing Performed

- **Why CI triggers are tag/manual-only:** The repository owner's private-repo GitHub Actions minutes were exhausted (which is the exact motivation for building Act-CI!). Accordingly, `.github/workflows/ci-publish.yml` in `Oni-giri/act-ci` is configured to run only on `v*` release tags or explicit `workflow_dispatch` rather than every branch push.
- **What was executed and proved** (full command-by-command matrix in [`EVIDENCE.md`](EVIDENCE.md)):
  1. **Level 1 (Local container & Ubuntu 26.04 `amd64`):** `.venv/bin/pytest -m "not docker" -v` — **74/74 passed** (exhaustive API + MCP permission matrix with route/tool completeness guard, private-run canary non-leak test, token hashing/revocation, Fernet encryption at rest + log masking, append-only audit trigger checks, `act` v0.2.98 flag check, UI + CSRF).
  2. **Level 2 (Real `docker:27.2.0-dind` daemon, `amd64`, GitHub Actions run `45719436439`):** `pytest -m "docker" -v` — **all passed** (passing/failing commits, overlay + replacement workflow, 8s timeout kill, live container cancel, Postgres 16 service container workflow, two-run FIFO single-slot queue, callback POST delivery, zero leftover workspaces or containers in `docker ps -a`).
  3. **Level 3 (Plain Docker Compose stack smoke test, `amd64`, run `45719436439`):** `python3 scripts/level3_smoke_test.py` — **passed** (UI token & repo creation → REST trigger → UI live log polling → MCP status & log read; explicitly **not** counted as Umbrel verification).
  4. **Level 4 (Static + Containerized `ghcr.io/getumbrel/umbrelos:2.0.2`, `amd64`, run `45723290377`):**
     - Static checks: official `getumbrel/umbrel-apps` linter (`0 errors, 1 expected privileged warning`), `docker compose config`, `git diff --check`, and `docker buildx imagetools inspect` confirming `linux/amd64` + `linux/arm64` manifests on all pinned digests.
     - Containerized `umbrelOS 2.0.2` runtime (`scripts/level4_umbrelos_verify.py`): registered community store via `umbreld client appStore.addRepository.mutate`, synced `yakitori-act-ci`, installed via `apps.install.mutate`, verified `:8755/` and `:8755/tokens` redirect (`302`) to Umbrel `:2000/app-auth` (internal `:8080` unexposed), verified `/api/v1/repos` and `/mcp` return `401` without a token and `200` with a valid bearer token, executed a full nested-DinD workflow run (`run_df84620628c84b0d` → `passed`) inside the installed Umbrel app, and verified tokens, repos, and run history survived both `apps.restart.mutate` and an `apps.update.mutate` (`0.1.0` → `0.1.1`) upgrade with clean settled logs.

---

## 5. Caveats / Untested Hardware Paths for Reviewer

1. **Physical Umbrel Hardware & Native `arm64` Runtime:** While multi-arch `linux/amd64` + `linux/arm64` images are built and inspected and containerized `umbrelOS 2.0.2` (`amd64`) ran end to end (including nested DinD), installation on a physical Umbrel device (especially `arm64` Raspberry Pi 4/5 hardware) and interactive browser sign-in through `:2000/app-auth` have not yet been run on physical hardware because no SSH/device connection was attached to the build environment.
2. **Live Private GitHub SSH Deploy Key Clone:** HTTPS cloning from GitHub ran live in Level 4 and `GIT_SSH_COMMAND` deploy-key handling + secret masking are covered in Level 1 tests, but cloning a private GitHub repository with a live SSH deploy key requires a private test repository + key pair.
3. **`act` Copy-Mode Checkout Convention:** Because `act` runs in copy mode (`-C`, no `--bind`) against a separate DinD container, workflows that read repository files inside job steps should include `- uses: actions/checkout@v4` (matching normal GitHub Actions workflows).
