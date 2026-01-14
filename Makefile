all: check build test

export RUSTFLAGS=-Dwarnings

test:
	cargo test
	cargo test --no-default-features --features alloc
	cargo test --no-default-features
	cargo test --features serde
	cargo test --features serde-decoded
	cargo +nightly fuzz run fuzz_roundtrip                                        -- -runs=0
	cargo +nightly fuzz run fuzz_roundtrip --no-default-features --features alloc -- -runs=0
	cargo +nightly fuzz run fuzz_roundtrip --no-default-features                  -- -runs=0
	cargo +nightly fuzz run fuzz_roundtrip --features serde                       -- -runs=0
	cargo +nightly fuzz run fuzz_roundtrip --features serde-decoded               -- -runs=0

fuzz:
	cargo +nightly fuzz run fuzz_roundtrip -j 4

fuzz-nostd:
	cargo +nightly fuzz run fuzz_roundtrip -j 4 --no-default-features --features alloc

fuzz-noalloc:
	cargo +nightly fuzz run fuzz_roundtrip -j 4 --no-default-features

# Generate a lcov.info file for tools like VSCode's Coverage Gutters extension,
# and output basic coverage information on the command line.
RUST_LLVM_COV=$(shell find $(shell rustc --print sysroot) -name llvm-cov)
RUST_TARGET_TRIPLE=$(shell rustc -vV | sed -n 's|host: ||p')
fuzz-coverage:
	rustup component add --toolchain nightly llvm-tools-preview
	cargo +nightly fuzz coverage fuzz_roundtrip
	@$(RUST_LLVM_COV) export \
		-instr-profile=fuzz/coverage/fuzz_roundtrip/coverage.profdata \
		-object target/$(RUST_TARGET_TRIPLE)/coverage/$(RUST_TARGET_TRIPLE)/release/fuzz_roundtrip \
		--ignore-filename-regex "rustc" \
		-format=lcov \
		> lcov.info
	@$(RUST_LLVM_COV) report \
		-instr-profile=fuzz/coverage/fuzz_roundtrip/coverage.profdata \
		-object target/$(RUST_TARGET_TRIPLE)/coverage/$(RUST_TARGET_TRIPLE)/release/fuzz_roundtrip \
		--ignore-filename-regex ".cargo/registry"
	@echo "View the coverage in lcov.info in VSCode using the Coverage Gutters extension."

build:
	cargo build
	cargo build --no-default-features --features alloc
	cargo build --no-default-features
	cargo build --features serde
	cargo build --features serde-decoded
	cargo build --features cli

check:
	cargo check --all-targets
	cargo check --all-targets --no-default-features --features alloc
	cargo check --all-targets --no-default-features
	cargo check --all-targets --features serde
	cargo build --all-targets --features serde-decoded
	cargo check --all-targets --features cli

install:
	cargo install --path . --force --features cli

fmt:
	cargo fmt --all

clean:
	cargo clean

.PHONY: all test fuzz build check install fmt clean
