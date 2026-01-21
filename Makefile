all: check build test

export RUSTFLAGS=-Dwarnings

test:
	cargo test
	cargo test --features serde
	cargo test --features serde-decoded
	cargo +nightly fuzz run fuzz_roundtrip -- -runs=0
	cargo +nightly fuzz run fuzz_compare_v13 -- -runs=0

fuzz:
	cargo +nightly fuzz run fuzz_roundtrip -j 4

fuzz-compare-v13:
	cargo +nightly fuzz run fuzz_compare_v13 -j 4

# Generate coverage report as text summary and HTML with source highlighting.
fuzz-coverage:
	rustup component add --toolchain nightly llvm-tools-preview
	@RUST_LLVM_COV=$$(find $$(rustc +nightly --print sysroot) -name llvm-cov) && \
	RUST_TARGET_TRIPLE=$$(rustc +nightly -vV | sed -n 's|host: ||p') && \
	for TARGET in $$(cargo +nightly fuzz list); do \
		echo "=== Coverage for $$TARGET ===" && \
		cargo +nightly fuzz coverage $$TARGET && \
		$$RUST_LLVM_COV report \
			-instr-profile=fuzz/coverage/$$TARGET/coverage.profdata \
			-object target/$$RUST_TARGET_TRIPLE/coverage/$$RUST_TARGET_TRIPLE/release/$$TARGET \
			--ignore-filename-regex ".cargo/registry" && \
		$$RUST_LLVM_COV show \
			-instr-profile=fuzz/coverage/$$TARGET/coverage.profdata \
			-object target/$$RUST_TARGET_TRIPLE/coverage/$$RUST_TARGET_TRIPLE/release/$$TARGET \
			--ignore-filename-regex ".cargo/registry" \
			--format=html \
			> coverage-$$TARGET.html; \
	done

build:
	cargo build
	cargo build --features serde
	cargo build --features cli

check:
	cargo check --all-targets
	cargo check --all-targets --features serde
	cargo check --all-targets --features cli

install:
	cargo install --path . --force --features cli

fmt:
	cargo fmt --all

clean:
	cargo clean

.PHONY: all test fuzz fuzz-compare build check install fmt clean
