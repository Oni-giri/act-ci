# ideas.md — Act-CI

Loose notes and "would be nice" items that are **not** committed work. Nothing here is a
promise; the roadmap in `PLAN.md` and the shipped code stay the source of truth. Each idea
lists why it showed up, whether it already works today, and what it would cost.

---

## CI → GitHub: posting commit statuses

**The ask.** After a run passes or fails, show the result where people already look: the
commit / PR checks panel on GitHub.

**Today: no.** Posting a commit status is a GitHub *write* operation and needs a write-scoped
credential (or a GitHub App). v1 keeps Act-CI strictly read-only against GitHub: `git fetch`
only — never push, never `api.github.com`. This is the roadmap item *"Posting results back to
GitHub as commit statuses."*

**Why an agent usually doesn't need Act-CI to do it.** After `trigger_run` the agent already
holds the run ID, the final status, and the per-step logs. It can set the status itself with
its own `gh` auth, and Act-CI never has to store a write credential:

```bash
# Look up the run's verdict over MCP, then post it (agent-side; uses the agent's own gh auth)
SHA="$(git rev-parse HEAD)"
STATE="success"   # or "failure" / "pending" / "error"
gh api -X POST "repos/OWNER/REPO/statuses/$SHA" \
  -f state="$STATE" \
  -f context="act-ci" \
  -f description="Act-CI run run_abc123" \
  -f target_url="http://umbrel.local:8755/runs/run_abc123"
```

**Or let the workflow post its own status.** No Act-CI change at all: put a GitHub token in
that repo's **Workflow secrets**, and have a final step call the same API with
`${{ secrets.GH_TOKEN }}`. The secret is already Fernet-encrypted at rest and masked in logs.

**If we build it natively (option 3).** Optional per-repo "status token" + a post-run publisher
sending `pending → success | failure`. Open decisions before any code:

- Which token scope (classic `repo:status` vs fine-grained *Commit statuses: write*), and
  whether to support a GitHub App instead so the credential is short-lived.
- Post `pending` at queue time, or only the terminal status?
- Map `timed_out` / `cancelled` to `error` — or leave them silent?
- `target_url` points at the Act-CI run page, which is only reachable on LAN/Tailscale. A dead
  link in GitHub's UI is worse than no link; consider a static description instead.
- Statuses are per commit, not per PR: two runs for the same SHA (e.g. a PR run and a `main`
  run) need distinct `context` strings (`act-ci / pr`, `act-ci / main`).

**Effort guess:** half a day for the native publisher (token field, post-run hook, tests), plus
the decisions above. The agent-side and workflow-side routes work today and cost nothing.

---

## Smaller things worth keeping in mind

- **Repo registration over MCP** — discussed at length; the plan is name + URL only, global
  git credential, optional host allowlist (`github.com` / `github.com/<org>`), `delete_repo`
  stays UI-only. Shipped as part of the pending `v0.1.3` work rather than an idea.
- **One global Git credential per account** — so a new repo doesn't mean pasting a token again.
  Also part of the pending `v0.1.3` work; listed here because it is the reason repo
  registration can stay secret-free.
- **Triggering on `pull_request` events** — needs the same write credential as statuses, plus
  an inbound path (webhook or polling). Roadmap.
- **Polling repos for new commits** — the "no webhook" way to get auto-runs. Roadmap; cheap in
  code, but it makes the runner do work nobody asked for, so it needs per-repo opt-in and
  branch filters.
- **A short public-ish run summary** — one signed, read-only URL per run (status + last failing
  step) that could be pasted into a PR comment. Would make `target_url` in statuses meaningful.
- **Log search inside a run** — the step view is grouped and collapsible; a find-in-logs box
  would help on 10k-line k6/playwright failures.
- **Artifacts** — even just "download this workspace path before cleanup" would cover screenshots
  and coverage reports. Out of scope for v1; would need a retention policy and a size cap.
- **Dependency caching between runs** — `act` runs with `--no-cache-server` today; a per-repo
  cache volume would cut npm/pip time a lot. Needs cache poisoning rules before it is safe.
- **More slots** — the queue is one slot by design (one DinD daemon = no container-name
  collisions). A second slot is really a second sidecar with its own daemon and socket.
