"""Configuration and runtime paths for Act-CI."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_RUNNER_IMAGE = "catthehacker/ubuntu:act-22.04"
DEFAULT_TIMEOUT_SECONDS = 1800


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    host: str
    port: int
    docker_host: str
    act_binary: str
    git_binary: str
    docker_binary: str
    master_key_env: str | None
    csrf_secret_env: str | None
    allow_local_repos: bool
    prune_interval_seconds: int
    prune_until: str
    enable_worker: bool
    allow_loopback_callbacks: bool = False

    @property
    def db_path(self) -> Path:
        return self.data_dir / "act_ci.db"

    @property
    def slot_cache_dir(self) -> Path:
        return self.data_dir / "slots" / "slot-0" / "act-cache"

    @property
    def slot_workspace_root(self) -> Path:
        return self.data_dir / "slots" / "slot-0" / "workspaces"

    @property
    def slot_temp_root(self) -> Path:
        return self.data_dir / "slots" / "slot-0" / "tmp"


def load_settings() -> Settings:
    data_dir = Path(os.environ.get("ACT_CI_DATA_DIR", "./data")).resolve()
    host = os.environ.get("ACT_CI_HOST", "0.0.0.0")
    port = int(os.environ.get("ACT_CI_PORT", "8080"))
    docker_host = os.environ.get(
        "ACT_CI_DOCKER_HOST",
        os.environ.get("DOCKER_HOST", "unix:///var/run/dind/docker.sock"),
    )
    act_binary = os.environ.get("ACT_CI_ACT_BINARY", "act")
    git_binary = os.environ.get("ACT_CI_GIT_BINARY", "git")
    docker_binary = os.environ.get("ACT_CI_DOCKER_BINARY", "docker")
    master_key_env = os.environ.get("ACT_CI_MASTER_KEY") or None
    csrf_secret_env = os.environ.get("ACT_CI_CSRF_SECRET") or None
    allow_local_repos = os.environ.get("ACT_CI_ALLOW_LOCAL_REPOS", "0").lower() in (
        "1",
        "true",
        "yes",
    )
    allow_loopback_callbacks = os.environ.get(
        "ACT_CI_ALLOW_LOOPBACK_CALLBACKS", "0"
    ).lower() in (
        "1",
        "true",
        "yes",
    )
    prune_interval_seconds = int(
        os.environ.get("ACT_CI_PRUNE_INTERVAL_SECONDS", str(6 * 3600))
    )
    prune_until = os.environ.get("ACT_CI_PRUNE_UNTIL", "168h")
    enable_worker = os.environ.get("ACT_CI_ENABLE_WORKER", "1").lower() in (
        "1",
        "true",
        "yes",
    )
    return Settings(
        data_dir=data_dir,
        host=host,
        port=port,
        docker_host=docker_host,
        act_binary=act_binary,
        git_binary=git_binary,
        docker_binary=docker_binary,
        master_key_env=master_key_env,
        csrf_secret_env=csrf_secret_env,
        allow_local_repos=allow_local_repos,
        prune_interval_seconds=prune_interval_seconds,
        prune_until=prune_until,
        enable_worker=enable_worker,
        allow_loopback_callbacks=allow_loopback_callbacks,
    )
