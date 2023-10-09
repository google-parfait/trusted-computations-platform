#!/bin/bash

set -e

# Run build for no_std environment
cargo build --target x86_64-unknown-none

# Run all tests
cargo test --all
