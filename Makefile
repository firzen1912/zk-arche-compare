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
	rm -rf benchmarks/results benchmarks/graphs_tex benchmarks/plots

clean-state:
	rm -rf state certs

.PHONY: security-test security-check fuzz-packet dos-zkarche dos-edhoc dos-mtls

security-test:
	cargo test --test security_zkarche -- --nocapture

security-check:
	mkdir -p results/security
	python3 security/rng_sidechannel_check.py --project . --output results/security/rng_sidechannel_check.csv

fuzz-packet:
	cargo fuzz run packet_parsers -- -max_total_time=60

# Start the matching server before using these DoS targets.
dos-zkarche:
	mkdir -p results/security
	python3 security/dos_resilience_test.py --host 127.0.0.1 --port 4000 --protocol zkarche --output results/security/zkarche_dos.csv

dos-edhoc:
	mkdir -p results/security
	python3 security/dos_resilience_test.py --host 127.0.0.1 --port 5688 --protocol edhoc --output results/security/edhoc_dos.csv

dos-mtls:
	mkdir -p results/security
	python3 security/dos_resilience_test.py --host 127.0.0.1 --port 7443 --protocol mtls --output results/security/mtls_dos.csv

.PHONY: security-all security-transcript security-mutation security-invalid-curve security-session security-replay security-side-channel security-fuzz security-dos-zkarche security-dos-edhoc security-dos-mtls

security-all:
	bash security/run_security_tests.sh --test all

security-transcript:
	bash security/run_security_tests.sh --test transcript

security-mutation:
	bash security/run_security_tests.sh --test mutation

security-invalid-curve:
	bash security/run_security_tests.sh --test invalid-curve

security-session:
	bash security/run_security_tests.sh --test session

security-replay:
	bash security/run_security_tests.sh --test replay

security-side-channel:
	bash security/run_security_tests.sh --test side-channel

security-fuzz:
	bash security/run_security_tests.sh --test fuzz

security-dos-zkarche:
	bash security/run_security_tests.sh --test dos --protocol zkarche --port 4000

security-dos-edhoc:
	bash security/run_security_tests.sh --test dos --protocol edhoc --port 5688

security-dos-mtls:
	bash security/run_security_tests.sh --test dos --protocol mtls --port 7443

# ============================================================
# C implementation targets
# ============================================================
.PHONY: c-deps c-build c-clean c-run-server c-run-server-bench c-setup-client c-run-client c-run-client-fast c-run-client-device-only c-reset-state

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
