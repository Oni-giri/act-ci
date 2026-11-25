"""Shared test fixtures for Level 1 (no Docker) and Level 2/3 (Docker + act) tests."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from act_ci.app import create_app
from act_ci.config import Settings


def init_local_git_fixture(repo_dir: Path, files: dict[str, str] | None = None) -> str:
    """Create a real local git repository with an initial commit and return its commit SHA."""
    repo_dir.mkdir(parents=True, exist_ok=True)
    default_files = {
        "README.md": "# Fixture Repo\n",
        ".github/workflows/ci.yml": (
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: Greeting\n"
            "        run: echo 'Hello from fixture CI'\n"
        ),
    }
    if files:
        default_files.update(files)
    for rel, content in default_files.items():
        target = repo_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Fixture Bot"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "fixture@example.invalid"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial fixture commit"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        host="127.0.0.1",
        port=8080,
        docker_host="unix:///nonexistent/docker.sock",
        act_binary="/tmp/act-bin/act" if Path("/tmp/act-bin/act").exists() else "act",
        git_binary="git",
        docker_binary="docker",
        master_key_env="unit-test-master-key-32-chars-minimum-012345",
        csrf_secret_env="unit-test-csrf-secret-32-chars-minimum-012345",
        allow_local_repos=True,
        prune_interval_seconds=0,
        prune_until="168h",
        enable_worker=False,
    )


@pytest.fixture
def app_instance(test_settings: Settings):
    return create_app(test_settings)


@pytest.fixture
def client(app_instance) -> TestClient:
    with TestClient(app_instance) as c:
        yield c
