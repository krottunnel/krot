default:
    @just --list

# format all crates
fmt:
    cargo fmt --all

# lint all crates
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# run all tests
test:
    cargo test --workspace --all-features

# check without building
check:
    cargo check --workspace --all-targets

# build release binaries
build:
    cargo build --workspace --release

# full pre-commit gate
ci: fmt lint test
