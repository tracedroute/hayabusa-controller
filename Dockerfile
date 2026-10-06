# Hayabusa Controller — complete from-scratch image (no base-image layering).
#
# Published on Docker Hub: tracedroute/hayabusa-controller
# Simplest run (no env files, no setup script):
#   docker run -d --name hayabusa-controller --restart unless-stopped --network host \
#     -v hayabusa-controller-data:/var/lib/hayabusa-controller \
#     tracedroute/hayabusa-controller:latest
#
# First boot prints admin password to logs: docker logs hayabusa-controller
# Credentials persist in the volume at /var/lib/hayabusa-controller/bootstrap.env
#
# Or: docker compose -f docker-compose.controller.yml up -d
#
# Tailscale client is built from source with bumped golang.org/x/crypto and
# golang.org/x/image so the release CVE gate (fixable HIGH/CRITICAL) passes.

ARG TS_GO_IMAGE=golang:1.27-bookworm
ARG TS_COMMIT=e2ed432399c9b0fda7aa14e9eb27784d2d893c55
ARG TS_CRYPTO_VER=v0.57.0
ARG TS_IMAGE_VER=v0.45.0

FROM ${TS_GO_IMAGE} AS tailscale-build
ARG TS_COMMIT
ARG TS_CRYPTO_VER
ARG TS_IMAGE_VER
WORKDIR /src
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git clone --filter=blob:none https://github.com/tailscale/tailscale.git . \
 && git checkout --detach "${TS_COMMIT}" \
 && go get "golang.org/x/crypto@${TS_CRYPTO_VER}" "golang.org/x/image@${TS_IMAGE_VER}" \
 && go mod tidy \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tailscaled ./cmd/tailscaled \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tailscale ./cmd/tailscale \
 && /out/tailscale version

FROM python:3.12-slim-bookworm@sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef

LABEL org.opencontainers.image.title="Hayabusa Controller"
LABEL org.opencontainers.image.description="Site appliance: ZTP, Image Nest, SECops hand-off, Hayabusa bridge"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CONTROLLER_DATA_DIR=/var/lib/hayabusa-controller \
    CONTROLLER_LISTEN_HOST=0.0.0.0 \
    CONTROLLER_LISTEN_PORT=8790 \
    CONTROLLER_ALLOW_LAN_BIND=1 \
    CONTROLLER_DEVOPS_DEFAULTS=/opt/hayabusa-controller/devops_iac_defaults

WORKDIR /opt/hayabusa-controller

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      dnsmasq \
      iproute2 \
      iptables \
      openssh-client \
      p7zip-full \
      qemu-utils \
      rpm \
      rsync \
      squashfs-tools \
      wimtools \
      xorriso \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# Ansible / OpenTofu are NOT installed here. Hayabusa Core runs those tools after
# LAN Approve; this appliance keeps the vault + lan.relay only (openssh-client).

# BSD-3-Clause Tailscale client, rebuilt with patched Go module deps (not the
# vulnerable stock pkgs.tailscale.com binaries).
COPY --from=tailscale-build /out/tailscale /usr/bin/tailscale
COPY --from=tailscale-build /out/tailscaled /usr/sbin/tailscaled
# Prefer upstream LICENSE from the exact commit we built; fall back not needed
# because licenses/LICENSE.tailscale.txt is also copied below.
COPY --from=tailscale-build /src/LICENSE /tmp/LICENSE.tailscale.upstream
RUN chmod 755 /usr/bin/tailscale /usr/sbin/tailscaled \
 && mkdir -p /var/run/tailscale /opt/hayabusa-controller/licenses \
 && cp /tmp/LICENSE.tailscale.upstream /opt/hayabusa-controller/licenses/LICENSE.tailscale.txt \
 && rm -f /tmp/LICENSE.tailscale.upstream

COPY requirements.txt /opt/hayabusa-controller/requirements.txt
RUN pip install --no-cache-dir --upgrade 'pip>=26.2.1' 'setuptools>=83.0.0' \
 && pip install --no-cache-dir -r /opt/hayabusa-controller/requirements.txt \
 && pip install --no-cache-dir --upgrade 'msgpack>=1.2.1' \
 && pip uninstall -y pip
COPY app/              /opt/hayabusa-controller/app/
COPY scripts/          /opt/hayabusa-controller/scripts/
COPY tests/            /opt/hayabusa-controller/tests/
COPY devops_iac_defaults/ /opt/hayabusa-controller/devops_iac_defaults/
COPY docs/             /opt/hayabusa-controller/docs/
COPY licenses/         /opt/hayabusa-controller/licenses/
COPY THIRD-PARTY-NOTICES.txt /opt/hayabusa-controller/THIRD-PARTY-NOTICES.txt
COPY entrypoint.sh     /entrypoint.sh

RUN chmod +x /entrypoint.sh \
 && cp -f /opt/hayabusa-controller/THIRD-PARTY-NOTICES.txt \
      /opt/hayabusa-controller/app/static/THIRD-PARTY-NOTICES.txt \
 && cp -f /opt/hayabusa-controller/THIRD-PARTY-NOTICES.txt \
      /opt/hayabusa-controller/docs/THIRD-PARTY-NOTICES.txt \
 && find /opt/hayabusa-controller -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true

VOLUME ["/var/lib/hayabusa-controller"]
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8790/healthz', timeout=3)" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
