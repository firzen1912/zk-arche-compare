.PHONY: build release certs setup bench plot clean-results clean-state

build:
	cargo build --bins

release:
	cargo build --release --bins

certs:
	bash scripts/gen_certs.sh

setup:
	bash benchmarks/setup.sh

bench:
	bash benchmarks/run_all.sh

plot:
	python3 -m benchmarks.plot

clean-results:
	rm -rf benchmarks/results benchmarks/graphs_tex benchmarks/plots results/security

clean-state:
	rm -rf state certs

# ============================================================
# Consolidated security test runner
# ============================================================
.PHONY: security-test security-safe security-all security-check fuzz-packet \
	security-transcript security-mutation security-invalid-curve security-session \
	security-replay security-side-channel security-fuzz \
	security-dos-zkarche security-dos-edhoc security-dos-mtls

SECURITY_RUNNER := python3 experiments/security/security_test.py

# Safe regression subset: no fuzzing and no live-server DoS traffic.
security-test security-safe:
	@for t in transcript mutation invalid-curve session replay side-channel; do \
		$(SECURITY_RUNNER) --test $$t || exit $$?; \
	done

# Runs every category in the consolidated runner, including fuzz and DoS.
# Start/prepare the appropriate server before using this target.
security-all:
	$(SECURITY_RUNNER) --test all

security-check security-side-channel:
	$(SECURITY_RUNNER) --test side-channel

security-transcript:
	$(SECURITY_RUNNER) --test transcript

security-mutation:
	$(SECURITY_RUNNER) --test mutation

security-invalid-curve:
	$(SECURITY_RUNNER) --test invalid-curve

security-session:
	$(SECURITY_RUNNER) --test session

security-replay:
	$(SECURITY_RUNNER) --test replay

security-fuzz fuzz-packet:
	$(SECURITY_RUNNER) --test fuzz --seconds 60

# Start the matching server before using DoS targets.
security-dos-zkarche:
	$(SECURITY_RUNNER) --test dos --host 127.0.0.1 --port 4000 --protocol zkarche

security-dos-edhoc:
	$(SECURITY_RUNNER) --test dos --host 127.0.0.1 --port 5688 --protocol edhoc

security-dos-mtls:
	$(SECURITY_RUNNER) --test dos --host 127.0.0.1 --port 7443 --protocol mtls

# ============================================================
# C implementation targets
# ============================================================
.PHONY: c-deps c-build c-clean c-run-server c-run-server-bench c-setup-client \
	c-run-client c-run-client-fast c-run-client-device-only c-reset-state

C_IMPL_DIR := c_implementation
C_BUILD_DIR := target/c
C_CLIENT_SRC := $(C_IMPL_DIR)/zkarche_client.c
C_SERVER_SRC := $(C_IMPL_DIR)/zkarche_server.c
C_CLIENT_BIN := $(C_BUILD_DIR)/zkarche_client_c
C_SERVER_BIN := $(C_BUILD_DIR)/zkarche_server_c
CFLAGS_C := -O2 -Wall -Wextra -std=c11
LIBS_C := -lsodium
C_BIND ?= 0.0.0.0:4000
C_SERVER ?= 127.0.0.1:4000
C_PAIRING_TOKEN ?= test

c-deps:
	sudo apt update
	sudo apt install -y build-essential libsodium-dev

c-build:
	mkdir -p $(C_BUILD_DIR)
	gcc $(CFLAGS_C) $(C_CLIENT_SRC) $(LIBS_C) -o $(C_CLIENT_BIN)
	gcc $(CFLAGS_C) $(C_SERVER_SRC) $(LIBS_C) -o $(C_SERVER_BIN)

c-clean:
	rm -rf $(C_BUILD_DIR)

c-reset-state:
	rm -rf state/client state/server

c-run-server: c-build
	$(C_SERVER_BIN) --bind $(C_BIND) --pairing --pairing-token $(C_PAIRING_TOKEN)

c-run-server-bench: c-build
	ZKARCHE_BENCH_MODE=1 ZKARCHE_ALLOW_DEVICE_ONLY=1 \
	$(C_SERVER_BIN) --bind $(C_BIND) --pairing --pairing-token $(C_PAIRING_TOKEN)

c-setup-client: c-build
	$(C_CLIENT_BIN) --server $(C_SERVER) --setup --pairing-token $(C_PAIRING_TOKEN) --allow-tofu-setup

c-run-client: c-build
	$(C_CLIENT_BIN) --server $(C_SERVER)

c-run-client-fast: c-build
	ZKARCHE_FAST_LOOKUP=1 $(C_CLIENT_BIN) --server $(C_SERVER)

c-run-client-device-only: c-build
	ZKARCHE_DEVICE_ONLY=1 ZKARCHE_BENCH_MODE=1 $(C_CLIENT_BIN) --server $(C_SERVER)
