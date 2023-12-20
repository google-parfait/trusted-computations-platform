#!/usr/bin/env bash

# Exit when any command fails
set -e

# Run build for no_std environment
printf "\n// Running build for !std environment"
printf "\n// cargo build --target x86_64-unknown-none\n\n"
env cargo build --target x86_64-unknown-none

# Check formatting
printf "\n// Checking formatting"
printf "\n// cargo fmt --all -- --check\n\n"
env cargo fmt --all -- --check

# Run all tests with default features (e.g. !std, prost-codec)
printf "\n// Running all tests with default features"
printf "\n// cargo test --all -- --nocapture\n\n"
env cargo test --all -- --nocapture

# Run all tests with non-default features
printf "\n// Running all tests with non-default features"
printf "\n// cargo test --all --no-default-features --features std -- --nocapture\n\n"
env cargo test --all --no-default-features --features std  -- --nocapture
