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
    "hashbrown": crate.spec(
        default_features = False,
        features = ["ahash"],
        version = "0.14.3",
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
    "mockall": crate.spec(
        version = "0.11.4",
    ),
    "slog-term": crate.spec(
        version = "2.9.0",
    ),
}

# Crates used for no_std builds.
TCP_NO_STD_PACKAGES = _COMMON_PACKAGES | {
    "base64": crate.spec(
        version = "0.22.1",
        default_features = False,
        features = ["alloc"],
    ),
    "p384": crate.spec(
        version = "0.13.0",
        default_features = False,
        features = ["ecdsa", "pem"],
    ),
    "rand": crate.spec(
        version = "0.8.5",
        default_features = False,
        features = ["alloc", "small_rng", "getrandom"],
    ),
    "rsa": crate.spec(
        version = "0.9.6",
        default_features = False,
    ),
    "serde": crate.spec(
        version = "1.0.195",
        default_features = False,
        features = ["derive"],
    ),
    "serde_json": crate.spec(
        version = "1.0.113",
        default_features = False,
        features = ["alloc"],
    ),
    "time": crate.spec(
        version = "0.3.28",
        default_features = False,
        features = ["serde", "parsing"],
    ),
    "x509-cert": crate.spec(
        version = "0.2.5",
        default_features = False,
        features = ["pem"],
    ),
}
