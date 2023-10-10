#!/bin/bash

# Exit when any command fails
set -e

# Run build for no_std environment
printf "\n// Running build for !std environment"
printf "\n// cargo build --target x86_64-unknown-none\n\n"
cargo build --target x86_64-unknown-none

# Check formatting
printf "\n// Checking formatting"
printf "\n// cargo fmt --all -- --check\n\n"
cargo fmt --all -- --check

# Run all tests with default features (e.g. !std, prost-codec)
printf "\n// Running all tests with default features"
printf "\n// cargo test --all -- --nocapture\n\n"
cargo test --all -- --nocapture

# Run all tests with non-default features
printf "\n// Running all tests with non-default features"
printf "\n// cargo test --all --no-default-features --features std --features prost-codec -- --nocapture\n\n"
cargo test --all --no-default-features --features std --features prost-codec -- --nocapture
