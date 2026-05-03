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
