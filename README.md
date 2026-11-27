<p align="center">
  <img src="assets/icon.svg" width="120" height="120" alt="Act-CI Logo">
</p>

# Act-CI

Self-hosted GitHub Actions CI service powered by [`nektos/act`](https://github.com/nektos/act), packaged as a one-click [umbrelOS](https://umbrel.com/) app.

Act-CI runs `.github/workflows` locally against an isolated Docker-in-Docker sidecar. It has **no inbound GitHub integration** (no OAuth app, no webhooks, no public endpoints): it clones repositories using optional read-only credentials, and runs are triggered from its browser UI, REST API, or built-in Model Context Protocol (MCP) server over your LAN or Tailscale network.

> **Security notice:** Act-CI runs a privileged Docker-in-Docker sidecar container and executes workflow code from the repositories and overlays you run. Never mount the host Docker socket; install Act-CI only on an Umbrel or server you trust and keep it behind Umbrel's login and a private network (LAN / Tailscale).

---

## Install

### On Umbrel

1. Open the **App Store** on your Umbrel.
2. Add the community app store containing `yakitori-act-ci` (or open it directly once synced).
3. Install **Act-CI** and click **Open**.
   - Umbrel's own login protects the browser UI and all admin routes automatically.
   - Only `/api/*` and `/mcp` are exempted from Umbrel's cookie proxy (`PROXY_AUTH_WHITELIST`), where Act-CI enforces named bearer-token authentication and role-based access control.
   - All mutable data lives under `${APP_DATA_DIR}/data`, and encryption/CSRF secrets are deterministically derived per install in `exports.sh` via `derive_entropy`. No `.env` editing or SSH is needed.

### Standalone with Docker Compose

```bash
docker compose up -d --build
```

Then open `http://localhost:8755`.

---

## Adding a Repository

1. Open the Act-CI web UI and navigate to **Repos**.
2. Fill in:
   - **Name:** Short slug used in API and MCP calls (for example, `my-service`).
   - **Git URL:** HTTPS (`https://github.com/owner/repo.git`) or SSH (`git@github.com:owner/repo.git`) clone URL.
   - **Read-Only Clone Credential:**
     - *None* for public repositories.
     - *HTTPS Read-Only Token / PAT* (for example, a fine-grained GitHub Personal Access Token with read-only `Contents` access).
     - *SSH Read-Only Deploy Key* (private key for a repository deploy key without write access).
   - **Default Runner Image:** Container image mapped to `ubuntu-latest` / `ubuntu-24.04` / `ubuntu-22.04` / `ubuntu-20.04` (defaults to `catthehacker/ubuntu:act-22.04`).
   - **Per-Run Timeout:** Maximum run wall-clock duration in seconds before overdue containers are terminated (`timed_out`).
   - **Workflow Secrets:** Optional `KEY=VALUE` lines passed to `act`.
3. Click **Add Repository**.
   - Clone credentials and workflow secrets are encrypted at rest with Fernet (`AES-128-CBC` + `HMAC-SHA256`), never returned by any API or UI response, and automatically masked (`***`) in run logs.
4. Click **Run** next to any repository to queue an immediate run from `HEAD`, or use the **Runs** page to specify a branch, tag, commit SHA, or workflow file.

---

## Creating Bearer Tokens & Access Roles

1. Open **Tokens** in the web UI.
2. Enter a **Token Name** (for example, `coding-agent`) and choose a **Role**:

| Role | Capabilities |
| --- | --- |
| `operator` | Trigger runs (including overlays, replacement workflows, and `private` runs), cancel runs, list repos, and read all run statuses and logs. |
| `viewer` | List repos, list runs, read run status for all runs, and read logs of **non-private** runs only (`private: true` logs and overlays are forbidden). |

3. Click **Create Token** and copy the `actci_...` token immediately.
   - The plaintext token is shown **once**; only its `SHA-256` hash is stored in SQLite.
   - Every API and MCP request (reads and denials included) is recorded in the append-only **Activity** audit log.
   - Click **Revoke** at any time to immediately invalidate a token.

---

## Triggering & Reading Runs over the REST API

Set your base URL (for example `http://umbrel.local:8755`) and bearer token:

```bash
export ACT_CI_URL="http://umbrel.local:8755"
export ACT_CI_TOKEN="actci_..."
```

### List configured repositories

```bash
curl -sS -H "Authorization: Bearer $ACT_CI_TOKEN" \
  "$ACT_CI_URL/api/v1/repos"
```

### Connect your Git account once, then let agents register repos

On the **Repos** page, save a single **Git account connection** (a fine-grained GitHub token
with read-only *Contents*, or an SSH deploy key). It is encrypted at rest and used by every
repository whose credential is `global` (the default) — so you never paste a token per repo,
and agents never need to see it.

An `operator` token can then register a repository over the API or MCP with no secret at all:

```bash
curl -sS -X POST "$ACT_CI_URL/api/v1/repos" \
  -H "Authorization: Bearer $ACT_CI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-service", "git_url": "https://github.com/me/my-service.git"}'
```

Registration is idempotent (same name + URL returns the existing repo) and is audited as
`repos.register`. It is limited to known forges (`github.com`, `gitlab.com`, `bitbucket.org`,
`codeberg.org`, `gitea.com`); anything else must be added in the UI. `viewer` tokens are
rejected. Workflow secrets and API keys are intentionally **not** accepted here — add those on
the Repos page yourself.

### Trigger a standard run

```bash
curl -sS -X POST "$ACT_CI_URL/api/v1/runs" \
  -H "Authorization: Bearer $ACT_CI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "my-service",
    "ref": "main"
  }'
```

### Trigger a private run with overlay files, replacement workflow, and callback URL

Overlay files and a replacement workflow let coding agents run extra verification suites without committing them to the target repository. Setting `"private": true` hides logs and overlay contents from `viewer` tokens:

```bash
curl -sS -X POST "$ACT_CI_URL/api/v1/runs" \
  -H "Authorization: Bearer $ACT_CI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "my-service",
    "ref": "a1b2c3d4",
    "private": true,
    "overlay": {
      "tests/test_agent_holdout.py": "def test_edge_case():\n    assert 2 + 2 == 4\n"
    },
    "replacement_workflow": "name: Holdout\non: [push]\njobs:\n  verify:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest tests/test_agent_holdout.py\n",
    "callback_url": "http://agent-box.tailnet.ts.net:9000/ci-done"
  }'
```

When the run finishes, Act-CI `POST`s `{"run_id": "run_...", "status": "passed"}` to `callback_url`.

### Poll status, fetch logs, or cancel

```bash
# Run status
curl -sS -H "Authorization: Bearer $ACT_CI_TOKEN" \
  "$ACT_CI_URL/api/v1/runs/run_0123456789abcdef"

# Structured job/step logs
curl -sS -H "Authorization: Bearer $ACT_CI_TOKEN" \
  "$ACT_CI_URL/api/v1/runs/run_0123456789abcdef/logs"

# Cancel a queued or running job
curl -sS -X POST -H "Authorization: Bearer $ACT_CI_TOKEN" \
  "$ACT_CI_URL/api/v1/runs/run_0123456789abcdef/cancel"
```

---

## Connecting Coding Agents via MCP

Act-CI exposes a Streamable HTTP MCP server at `/mcp` using the same bearer tokens. The `tools/list` response automatically filters tools to match the token's role (`viewer` vs `operator`), and all RBAC rules are enforced in the core service layer:

- `list_repos` *(viewer, operator)*
- `register_repo` *(operator: name + URL only, inherits the Git account connection)*
- `list_recent_runs` *(viewer, operator)*
- `get_run_status` *(viewer, operator)*
- `get_run_log` *(viewer: non-private runs only; operator: all runs)*
- `trigger_run` *(operator)*
- `cancel_run` *(operator)*

### Example MCP Client Configuration

```json
{
  "mcpServers": {
    "act-ci": {
      "type": "http",
      "url": "http://umbrel.local:8755/mcp",
      "headers": {
        "Authorization": "Bearer actci_..."
      }
    }
  }
}
```

### Example Direct JSON-RPC Call

```bash
curl -sS -X POST "$ACT_CI_URL/mcp" \
  -H "Authorization: Bearer $ACT_CI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "trigger_run",
      "arguments": {
        "repo": "my-service",
        "ref": "main"
      }
    }
  }'
```

---

## Known Differences from GitHub-Hosted Runners

1. **Runner Container Images vs Full GitHub VMs:** GitHub's `ubuntu-latest` VMs bundle ~70 GB of SDKs and browsers. By default Act-CI maps `ubuntu-*` labels to `catthehacker/ubuntu:act-22.04` (configurable per repository). Workflows needing specialized toolchains should install them via `setup-*` actions or set a richer runner image on the repository.
2. **Copy Mode (No Host Bind Mounts):** Because jobs execute inside an isolated Docker-in-Docker sidecar container, Act-CI invokes `act` in its default **copy mode** (never `--bind`), and passes `--container-daemon-socket -` so untrusted workflow steps do not receive the DinD socket by default.
3. **Single Execution Slot & Queue:** v1 ships with one isolated Docker daemon slot and a FIFO queue. Concurrent submissions queue cleanly and run one after another so `act` container names never collide.
4. **No GitHub Forge Tokens or Artifacts Server:** `GITHUB_TOKEN` is not automatically minted because Act-CI has no GitHub App/OAuth integration (pass read-only PATs as repo secrets if a workflow fetches private dependencies). `actions/cache` and `actions/upload-artifact` storage across runs are out of scope for v1 (`--no-cache-server` is enabled).
5. **Host Architecture (`amd64` vs `arm64`):** Job containers run natively on your Umbrel's CPU architecture (`x86_64` on PC/home servers, `arm64` on Raspberry Pi 4/5). Workflows that download x86-only binaries without multi-arch support may need architecture-aware steps on ARM devices.
6. **Systemd / Kernel Modules:** Runner containers execute inside Docker-in-Docker rather than full VMs, so workflows requiring `systemctl`, custom kernel modules, or nested KVM are not supported.

---

## Running Automated Tests

### Level 1 (No Docker required — runs in seconds)

```bash
pytest -m "not docker" -v
```

### Level 2 (Real isolated Docker-in-Docker daemon + `act` v0.2.98)

```bash
ACT_CI_TEST_DOCKER_HOST=tcp://127.0.0.1:23750 pytest -m "docker" -v
```

### Level 3 (Plain Docker Compose stack smoke test)

```bash
python3 scripts/level3_smoke_test.py
```
