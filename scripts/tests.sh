#!/bin/bash

set -e

# Run build for no_std environment
printf "\n// Running build for !std environment\n\n"
cargo build --target x86_64-unknown-none

# Run all tests with default features (e.g. !std, prost-codec)
printf "\n// Running all tests with default features\n\n"
cargo test --all -- --nocapture

# Run all tests with non-default features
printf "\n// Running all tests with non-default features\n\n"
cargo test --all --no-default-features --features std --features prost-codec -- --nocapture
