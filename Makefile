# Go client; Python server provisioning and packaging. Native OpenSSH transport.
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

TUNNEL_USER ?= svc_tunnel
PUBKEY_FILE ?=
PERMIT_OPEN ?= 127.0.0.1:8080 127.0.0.1:5432 127.0.0.1:9000
SSHD_CONFIG ?= /etc/ssh/sshd_config
SSH_SERVICE ?= ssh
CONFIG ?= var/services.windows.json
PYTHON ?= python3
VENV_DIR ?= .venv
VENV_PYTHON = $(VENV_DIR)/bin/python
RUN_PYTHON = $(if $(wildcard $(VENV_PYTHON)),$(VENV_PYTHON),$(PYTHON))
SERVER_STATE ?= var/server
GO ?= go
TOKEN_FILE ?= .token
BUILD_CLIENT ?= 1
NO_RESET_TOKEN ?= 0
ifneq ($(filter NO_RESET_TOKEN,$(MAKECMDGOALS)),)
override NO_RESET_TOKEN := 1
endif
WINDOWS_ARCH ?= amd64
DOCKER ?= docker
COMPOSE = "$(RUN_PYTHON)" tools/docker_compose.py --docker "$(DOCKER)" --

export TUNNEL_USER PUBKEY_FILE PERMIT_OPEN SSHD_CONFIG SSH_SERVICE CONFIG
export HOST_KEY_FILE BUNDLE_OUTPUT DRY_RUN BUNDLE_TOKEN_FILE
export SERVER_STATE TOKEN_PORT LEGACY_SSH BUILD_CLIENT WINDOWS_ARCH NO_RESET_TOKEN

.PHONY: help setup server-setup server create delete audit render build build-windows check test integration client bundle bundle-windows client-zip
.PHONY: docker-config docker-build docker-up docker-down docker-status docker-logs docker-bundle NO_RESET_TOKEN

help:
	@printf '%s\n' \
	  'make server                         Run host token management; use the existing SSH port from var/services.windows.json' \
	  'make build                           Build the Go client for this OS' \
	  'make build-windows                   Cross-compile dist/sservcli.exe (no CGO)' \
	  'make client CONFIG=services.json     Start the Go client and localhost:8000 management page' \
	  'make bundle CONFIG=services.json     Prepare SSH account and create a minimal Windows runtime ZIP' \
	  'make bundle CONFIG=services.json BUILD_CLIENT=0  Source ZIP; build later with Build.cmd' \
	  'make bundle LEGACY_SSH=1 PUBKEY_FILE=<client.pub> CONFIG=<services.json>  Key/Agent mode' \
	  'make client-zip CONFIG=<final-profile.json>  ZIP without server/account changes' \
	  'make check test                      Validate Go/Python and run unit tests' \
	  'make integration                     Run isolated native ssh/sshd tests' \
	  'make render CONFIG=services.json     Preview restricted SSH policy'
	@printf '%s\n' \
	  'make docker-up                      Start the Docker server using the existing host SSH port' \
	  'make docker-up NO_RESET_TOKEN=1     Restart using the saved token; issue one only on first start' \
	  'make docker-bundle                  Package the running Docker server token and Windows client' \
	  'make docker-build                   Build the server image and Windows client' \
	  'make docker-logs                    Follow the Docker server log' \
	  'make docker-down                    Stop the Docker server and revoke its token; host SSH stays active' \
	  'Use DOCKER="sudo docker" when Docker requires sudo'

setup:
	$(GO) version

server-setup:
	"$(RUN_PYTHON)" -c 'import sys, shutil; assert sys.version_info >= (3, 11), "Python 3.11+ required"; assert shutil.which("ssh"), "Install OpenSSH"'

server: server-setup
	"$(RUN_PYTHON)" -m sservcli serve --config "$$CONFIG" --state-dir "$$SERVER_STATE"

create:
	@test -n "$$PUBKEY_FILE" || { echo 'Set PUBKEY_FILE to a public key file' >&2; exit 1; }
	@read -r -a permitted <<< "$$PERMIT_OPEN"; $(PYTHON) server/sservcli_server.py install --user "$$TUNNEL_USER" --public-key "$$PUBKEY_FILE" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE" --permit-open "$${permitted[@]}" --ensure-ssh

delete:
	@$(PYTHON) server/sservcli_server.py remove --user "$$TUNNEL_USER" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE"

audit:
	@read -r -a permitted <<< "$$PERMIT_OPEN"; $(PYTHON) server/sservcli_server.py audit --user "$$TUNNEL_USER" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE" --permit-open "$${permitted[@]}"

render:
	@$(PYTHON) server/sservcli_server.py render --config "$$CONFIG"

build: setup
	cd client && CGO_ENABLED=0 $(GO) build -trimpath -o sservcli ./cmd/sservcli

build-windows: setup
	mkdir -p dist
	cd client && GOOS=windows GOARCH=$(WINDOWS_ARCH) CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o ../dist/sservcli.exe ./cmd/sservcli
	cd client && GOOS=windows GOARCH=$(WINDOWS_ARCH) CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w -H=windowsgui' -o ../dist/sservcli-askpass.exe ./cmd/askpass

check: setup server-setup
	"$(RUN_PYTHON)" -m compileall -q sservcli server tools tests
	"$(RUN_PYTHON)" -c 'from sservcli.config import load_profile; load_profile("examples/services.token.json"); load_profile("examples/services.token.windows.json")'
	"$(RUN_PYTHON)" server/sservcli_server.py render --config examples/services.token.json >/dev/null
	cd client && $(GO) vet ./...

test: setup server-setup
	"$(RUN_PYTHON)" -m unittest discover -s tests -v
	cd client && $(GO) test ./...

integration: build server-setup
	SSERVCLI_SSH_TESTS=1 "$(RUN_PYTHON)" -m unittest discover -s tests -p test_ssh_integration.py -v
	SSERVCLI_SSH_TESTS=1 "$(RUN_PYTHON)" -m unittest discover -s tests -p test_token_ssh.py -v

client: build
	client/sservcli start --config "$$CONFIG" --token-file "$(TOKEN_FILE)"

bundle bundle-windows: server-setup
	"$(RUN_PYTHON)" tools/bundle_windows.py

client-zip:
	"$(RUN_PYTHON)" tools/bundle_windows.py --client-only

docker-config:
	$(COMPOSE) config --quiet

docker-build: docker-config
	$(COMPOSE) build server

docker-up: docker-build
	$(COMPOSE) stop --timeout 45 server
	"$(RUN_PYTHON)" server/ssh_bridge.py install --config "$$CONFIG" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE"
	mkdir -p dist
	@$(COMPOSE) up -d --force-recreate --wait --wait-timeout 60 server || { $(COMPOSE) logs --no-color --tail 100 server; exit 1; }

# Also accept the shorthand: make docker-up NO_RESET_TOKEN
NO_RESET_TOKEN:
	@:

docker-down:
	$(COMPOSE) down --remove-orphans

docker-status:
	$(COMPOSE) ps -a

docker-logs:
	$(COMPOSE) logs -f --tail 100 server

docker-bundle:
	$(COMPOSE) exec -T -e BUNDLE_UID="$$(id -u)" -e BUNDLE_GID="$$(id -g)" -e BUILD_CLIENT="$(BUILD_CLIENT)" -e DRY_RUN="$${DRY_RUN:-0}" server python3 /opt/sservcli/server/container_server.py bundle
