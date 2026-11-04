FROM golang:1.27.3-bookworm AS client-build
ARG WINDOWS_ARCH=amd64
WORKDIR /src/client
COPY client/ ./
RUN CGO_ENABLED=0 GOOS=windows GOARCH=${WINDOWS_ARCH} go build -trimpath -ldflags='-s -w' -o /out/sservcli.exe ./cmd/sservcli \
 && CGO_ENABLED=0 GOOS=windows GOARCH=${WINDOWS_ARCH} go build -trimpath -ldflags='-s -w -H=windowsgui' -o /out/sservcli-askpass.exe ./cmd/askpass

FROM ubuntu:24.04 AS server
ARG WINDOWS_ARCH=amd64
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 openssh-server passwd procps ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_*
WORKDIR /opt/sservcli
COPY sservcli/ sservcli/
COPY server/ server/
COPY tools/ tools/
COPY client/ client/
COPY examples/ examples/
COPY Build.cmd Start.cmd Stop.cmd README.md ./
COPY docker/sshd_config /etc/ssh/sshd_config
COPY --from=client-build /out/ /opt/sservcli-client/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CONFIG=/config/services.json SERVER_STATE=/state \
    SSHD_CONFIG=/etc/ssh/sshd_config SSHD_PID_FILE=/run/sservcli/sshd.pid \
    HOST_KEY_FILE=/state/ssh_host_ed25519.pub CLIENT_BINARIES=/opt/sservcli-client \
    WINDOWS_ARCH=${WINDOWS_ARCH} BUNDLE_OUTPUT=/dist/sservcli-windows-token.zip
ENTRYPOINT ["python3", "/opt/sservcli/server/container_runtime.py"]
CMD ["serve"]
