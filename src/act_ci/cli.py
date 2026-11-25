"""CLI entrypoint for running Act-CI."""

from __future__ import annotations

import logging

import uvicorn

from act_ci.config import load_settings


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    settings = load_settings()
    uvicorn.run(
        "act_ci.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    main()
