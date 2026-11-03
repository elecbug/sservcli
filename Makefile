# Python-only server provisioning, client, packaging, and checks.
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

TUNNEL_USER ?= svc_tunnel
PUBKEY_FILE ?=
PERMIT_OPEN ?= 127.0.0.1:8080 127.0.0.1:5432 127.0.0.1:9000
SSHD_CONFIG ?= /etc/ssh/sshd_config
SSH_SERVICE ?= ssh
CONFIG ?= services.json
PYTHON ?= python3
VENV_DIR ?= .venv
VENV_PYTHON = $(VENV_DIR)/bin/python
RUN_PYTHON = $(if $(wildcard $(VENV_PYTHON)),$(VENV_PYTHON),$(PYTHON))
SERVER_STATE ?= var/server
LISTEN ?= 0.0.0.0

export TUNNEL_USER PUBKEY_FILE PERMIT_OPEN SSHD_CONFIG SSH_SERVICE CONFIG
export HOST_KEY_FILE BUNDLE_OUTPUT DRY_RUN
export SERVER_STATE TOKEN_PORT LEGACY_SSH
export LISTEN

.PHONY: help setup server create delete audit render build check test integration desktop bundle bundle-windows client-zip

help:
	@printf '%s\n' \
	  'make setup                           Install Python SSH dependencies in .venv' \
	  'make server CONFIG=services.json     Run token SSH server; print a new 8-character token' \
	  'make check                           Validate Python sources and example profiles' \
	  'make test                            Run Python unit tests (no account changes)' \
	  'make integration                     Run temporary local sshd integration tests' \
	  'make desktop [CONFIG=services.json]   Run the Tkinter client' \
	  'make build                           Check sources; no compilation is needed' \
	  'make bundle CONFIG=services.json     Package Windows client with pinned server key; no token in ZIP' \
	  'make bundle LEGACY_SSH=1 PUBKEY_FILE=<client.pub> CONFIG=<services.json>  Old account/key workflow' \
	  'make client-zip CONFIG=<services.json> Package client only; preserve existing server accounts' \
	  'make render CONFIG=services.json      Preview server SSH policy' \
	  'sudo make create PUBKEY_FILE=<client.pub> [TUNNEL_USER=svc_tunnel]' \
	  'sudo make audit [TUNNEL_USER=svc_tunnel]' \
	  'sudo make delete [TUNNEL_USER=svc_tunnel]'

$(VENV_DIR)/.sservcli-ready: requirements.txt
	$(PYTHON) -m venv "$(VENV_DIR)"
	"$(VENV_PYTHON)" -m pip --disable-pip-version-check install --only-binary=:all: -r requirements.txt
	@touch "$@"

setup: $(VENV_DIR)/.sservcli-ready

server: setup
	"$(RUN_PYTHON)" -m sservcli serve --config "$$CONFIG" --state-dir "$$SERVER_STATE" --listen "$$LISTEN"

create:
	@test -n "$$PUBKEY_FILE" || { echo 'Set PUBKEY_FILE to a public key file' >&2; exit 1; }
	@read -r -a permitted <<< "$$PERMIT_OPEN"; $(PYTHON) server/sservcli_server.py install --user "$$TUNNEL_USER" --public-key "$$PUBKEY_FILE" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE" --permit-open "$${permitted[@]}" --ensure-ssh

delete:
	@$(PYTHON) server/sservcli_server.py remove --user "$$TUNNEL_USER" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE"

audit:
	@read -r -a permitted <<< "$$PERMIT_OPEN"; $(PYTHON) server/sservcli_server.py audit --user "$$TUNNEL_USER" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE" --permit-open "$${permitted[@]}"

render:
	@$(PYTHON) server/sservcli_server.py render --config "$$CONFIG"

build: check

check: setup
	"$(RUN_PYTHON)" -m compileall -q sservcli server tools tests
	"$(RUN_PYTHON)" -m sservcli check --config examples/services.token.json
	"$(RUN_PYTHON)" -m sservcli check --config examples/services.token.windows.json
	"$(RUN_PYTHON)" -m sservcli check --config examples/services.json
	"$(RUN_PYTHON)" server/sservcli_server.py render --config examples/services.json >/dev/null

test: setup
	"$(RUN_PYTHON)" -m unittest discover -s tests -v

integration: setup
	SSERVCLI_SSH_TESTS=1 "$(RUN_PYTHON)" -m unittest discover -s tests -p test_ssh_integration.py -v

desktop: setup
	"$(RUN_PYTHON)" -m sservcli desktop --config "$$CONFIG"

bundle bundle-windows: setup
	"$(RUN_PYTHON)" tools/bundle_windows.py

client-zip: setup
	"$(RUN_PYTHON)" tools/bundle_windows.py --client-only
