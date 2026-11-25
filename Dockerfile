# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

ARG TARGETARCH

# Pinned nektos/act v0.2.98 and static Docker CLI v27.5.1 with verified SHA-256 digests
ENV ACT_VERSION=0.2.98 \
    ACT_SHA256_AMD64=d3344bd0810c04b000d2444030b08c90ab9fbf905bbe2c3e26298be00c620d65 \
    ACT_SHA256_ARM64=a30ba1a1582cb93810c77f743415cac33c16f60fc288116a8e0943144b6a6a4f \
    DOCKER_CLI_VERSION=27.5.1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      openssh-client \
      tini \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) \
        ACT_ARCH="Linux_x86_64"; \
        ACT_SHA="${ACT_SHA256_AMD64}"; \
        DOCKER_ARCH="x86_64"; \
        ;; \
      arm64) \
        ACT_ARCH="Linux_arm64"; \
        ACT_SHA="${ACT_SHA256_ARM64}"; \
        DOCKER_ARCH="aarch64"; \
        ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/nektos/act/releases/download/v${ACT_VERSION}/act_${ACT_ARCH}.tar.gz" -o /tmp/act.tar.gz; \
    echo "${ACT_SHA}  /tmp/act.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/act.tar.gz -C /usr/local/bin act; \
    chmod +x /usr/local/bin/act; \
    rm -f /tmp/act.tar.gz; \
    curl -fsSL "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz; \
    tar -xzf /tmp/docker.tgz --strip-components=1 -C /usr/local/bin docker/docker; \
    chmod +x /usr/local/bin/docker; \
    rm -f /tmp/docker.tgz; \
    act --version; \
    docker --version

RUN groupadd -g 1000 actci && useradd -m -u 1000 -g 1000 -s /bin/sh actci

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir . && \
    mkdir -p /data /var/run/dind && \
    chown -R actci:actci /app /data /var/run/dind

ENV ACT_CI_DATA_DIR=/data \
    ACT_CI_HOST=0.0.0.0 \
    ACT_CI_PORT=8080 \
    ACT_CI_DOCKER_HOST=unix:///var/run/dind/docker.sock

EXPOSE 8080
USER 1000:1000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["act-ci"]
