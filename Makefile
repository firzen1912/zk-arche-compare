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
