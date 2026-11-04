FROM golang:1.27.3-bookworm AS client-build
ARG WINDOWS_ARCH=amd64
ARG BUILD_CLIENT=1
WORKDIR /src/client
COPY client/ ./
RUN mkdir -p /out \
 && if [ "$BUILD_CLIENT" != "0" ]; then \
      CGO_ENABLED=0 GOOS=windows GOARCH=${WINDOWS_ARCH} go build -trimpath -ldflags='-s -w' -o /out/sservcli.exe ./cmd/sservcli \
   && CGO_ENABLED=0 GOOS=windows GOARCH=${WINDOWS_ARCH} go build -trimpath -ldflags='-s -w -H=windowsgui' -o /out/sservcli-askpass.exe ./cmd/askpass; \
    fi

FROM ubuntu:24.04 AS server
ARG WINDOWS_ARCH=amd64
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/sservcli
COPY sservcli/ sservcli/
COPY server/sservcli_server.py server/sservcli_server.py
COPY server/container_server.py server/container_server.py
COPY tools/ tools/
COPY client/ client/
COPY examples/ examples/
COPY Build.cmd Start.cmd Stop.cmd README.md ./
COPY --from=client-build /out/ /opt/sservcli-client/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CLIENT_BINARIES=/opt/sservcli-client WINDOWS_ARCH=${WINDOWS_ARCH} \
    CONFIG=/config/services.json SERVER_STATE=/state \
    SSERVCLI_BRIDGE_SOCKET=/host-ssh/bridge.sock
ENTRYPOINT ["python3", "/opt/sservcli/server/container_server.py"]
CMD ["serve"]
