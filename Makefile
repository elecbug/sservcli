# SSH forwarding-only account management (Ubuntu / OpenSSH), client, and checks.
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

# Values are environment data, never interpolated into shell source.
export TUNNEL_USER PUBKEY_FILE PERMIT_OPEN SSHD_CONFIG SSH_SERVICE CONFIG
export SERVER_HOST SERVER_PORT FALLBACK_HOSTS CLIENT_IDENTITY HOST_KEY_FILE WINDOWS_ARTIFACT WINDOWS_REPO WINDOWS_REF BUNDLE_OUTPUT DRY_RUN

.PHONY: help create delete audit render build check test integration desktop bundle bundle-windows

help:
	@printf '%s\n' \
	  'make build                           Build the Rust CLI' \
	  'make check                           Validate the example and JS syntax' \
	  'make test                            Rust and server tests (no root needed)' \
	  'make integration                     Test with a temporary local sshd (no root)' \
	  'make desktop                         Run Tauri (install its prerequisites first)' \
	  'make bundle SERVER_HOST=<IP> PUBKEY_FILE=<client.pub> [WINDOWS_ARTIFACT=<zip-or-directory>] [DRY_RUN=1]' \
	  'make render CONFIG=services.json      Preview the server SSH policy' \
	  'sudo make create PUBKEY_FILE=/path/to/id_ed25519.pub [PERMIT_OPEN="127.0.0.1:8080 ..."]' \
	  'sudo make audit [PERMIT_OPEN="127.0.0.1:8080 ..."]' \
	  'sudo make delete [TUNNEL_USER=svc_tunnel]'

create:
	@test -n "$$PUBKEY_FILE" || { echo 'Set PUBKEY_FILE to a public key file' >&2; exit 1; }
	@read -r -a permitted <<< "$$PERMIT_OPEN"; $(PYTHON) server/sservcli_server.py install --user "$$TUNNEL_USER" --public-key "$$PUBKEY_FILE" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE" --permit-open "$${permitted[@]}"

delete:
	@$(PYTHON) server/sservcli_server.py remove --user "$$TUNNEL_USER" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE"

audit:
	@read -r -a permitted <<< "$$PERMIT_OPEN"; $(PYTHON) server/sservcli_server.py audit --user "$$TUNNEL_USER" --sshd-config "$$SSHD_CONFIG" --ssh-service "$$SSH_SERVICE" --permit-open "$${permitted[@]}"

render:
	@$(PYTHON) server/sservcli_server.py render --config "$$CONFIG"

build:
	cargo build --workspace --release

check:
	cargo run --quiet -- check --config client/examples/services.json
	node --check client/desktop/ui/app.js
	$(PYTHON) server/sservcli_server.py render --config client/examples/services.json >/dev/null

test:
	cargo build --workspace
	cargo test --workspace
	$(PYTHON) -m unittest discover -s tests -v

integration:
	cargo build --workspace
	SSERVCLI_SSH_TESTS=1 $(PYTHON) -m unittest discover -s tests -p test_ssh_integration.py -v

desktop:
	cd client/desktop && npm run dev

bundle bundle-windows: build
	$(PYTHON) tools/bundle_windows.py
