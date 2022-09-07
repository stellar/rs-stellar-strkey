all: check build test

export RUSTFLAGS=-Dwarnings

test:
	cargo test

build:
	cargo build

check:
	cargo check --all-targets

watch:
	cargo watch --clear --watch-when-idle --shell '$(MAKE)'

fmt:
	cargo fmt --all

clean:
	cargo clean

publish:
	cargo workspaces publish --all --force '*' --from-git --yes
