all: check build test

export RUSTFLAGS=-Dwarnings

test:
	cargo test
	cargo +nightly fuzz run fuzz_roundtrip -- -runs=0

fuzz:
	cargo +nightly fuzz run fuzz_roundtrip -j 4

build:
	cargo build
	cargo build --features cli

check:
	cargo check --all-targets
	cargo check --all-targets --features cli

install:
	cargo install --path . --force --features cli

fmt:
	cargo fmt --all

clean:
	cargo clean

.PHONY: all test fuzz build check install fmt clean
