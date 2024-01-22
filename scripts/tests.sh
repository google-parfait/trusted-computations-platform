# Copyright 2023 The Trusted Computations Platform Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
env cargo test --all -- --nocapture --color always --test-threads 1

# Run all tests with non-default features
printf "\n// Running all tests with non-default features"
printf "\n// cargo test --all --no-default-features --features std -- --nocapture\n\n"
env cargo test --all --no-default-features --features std  -- --nocapture --color always --test-threads 1
