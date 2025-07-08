# Copyright 2024 The Trusted Computations Platform Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Rust crates required by this workspace."""

load("@rules_rust//crate_universe:defs.bzl", "crate")

# Crates used by both std and no_std builds.
_COMMON_PACKAGES = {
    "aes-gcm-siv": crate.spec(
        version = "0.11.1",
    ),
    "ahash": crate.spec(
        version = "0.8.3",
        default_features = False,
    ),
    "slog": crate.spec(
        version = "2.2.0",
        default_features = False,
    ),
    "spin": crate.spec(
        version = "0.9.8",
    ),
}

# Crates used for std builds.
TCP_PACKAGES = _COMMON_PACKAGES | {
    "getset": crate.spec(
        version = "0.1.1",
    ),
    "googletest": crate.spec(
        version = "0.11.0",
    ),
    "slog-term": crate.spec(
        version = "2.9.0",
    ),
    "tonic": crate.spec(
        # Remove TLS features added by Oak to avoid depending on the ring crate,
        # which doesn't compile with our toolchain.
        features = ["gzip"],
        version = "0.12.0",
    ),
}

# Crates used for no_std builds.
TCP_NO_STD_PACKAGES = _COMMON_PACKAGES | {
    "rand": crate.spec(
        version = "0.8.5",
        default_features = False,
        features = ["alloc", "small_rng", "getrandom"],
    ),
}
