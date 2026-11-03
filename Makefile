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

export TUNNEL_USER PUBKEY_FILE PERMIT_OPEN SSHD_CONFIG SSH_SERVICE CONFIG
export HOST_KEY_FILE BUNDLE_OUTPUT DRY_RUN

.PHONY: help create delete audit render build check test integration desktop bundle bundle-windows client-zip

help:
	@printf '%s\n' \
	  'make check                           Validate Python sources and example profiles' \
	  'make test                            Run Python unit tests (no account changes)' \
	  'make integration                     Run temporary local sshd integration tests' \
	  'make desktop [CONFIG=services.json]   Run the Tkinter client' \
	  'make build                           Check sources; no compilation is needed' \
	  'make bundle PUBKEY_FILE=<client.pub> CONFIG=<services.json> [DRY_RUN=1]' \
	  '                                     Create/reuse account, register key, package Windows client' \
	  'make client-zip CONFIG=<services.json> Package client only; preserve existing server accounts' \
	  'make render CONFIG=services.json      Preview server SSH policy' \
	  'sudo make create PUBKEY_FILE=<client.pub> [TUNNEL_USER=svc_tunnel]' \
	  'sudo make audit [TUNNEL_USER=svc_tunnel]' \
	  'sudo make delete [TUNNEL_USER=svc_tunnel]'

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

check:
	$(PYTHON) -m compileall -q sservcli server tools tests
	$(PYTHON) -m sservcli check --config client/examples/services.json
	$(PYTHON) -m sservcli check --config client/examples/services.windows.json
	$(PYTHON) server/sservcli_server.py render --config client/examples/services.json >/dev/null

test:
	$(PYTHON) -m unittest discover -s tests -v

integration:
	SSERVCLI_SSH_TESTS=1 $(PYTHON) -m unittest discover -s tests -p test_ssh_integration.py -v

desktop:
	$(PYTHON) -m sservcli desktop --config "$$CONFIG"

bundle bundle-windows:
	$(PYTHON) tools/bundle_windows.py

client-zip:
	$(PYTHON) tools/bundle_windows.py --client-only
